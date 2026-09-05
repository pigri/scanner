#!/usr/bin/env -S node --loader tsx
// ffuf: high-signal content discovery — a small curated wordlist of paths that
// almost always indicate a real exposure when they hit 200: backup files,
// dotfiles, .git/.svn/.hg, environment configs, admin panels, phpinfo dumps,
// build artefacts. Complements kiterunner's API focus (kiterunner probes API
// routes; this probes "leaked artefact" paths).
//
// Filters to live HTTP targets, runs one ffuf per host with -mc for the exact
// status set we care about, dedupes hits by 'size' to strip WAF/generic-404
// pages.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';
import { fetchCanary, probeUrl, hashBody, isNearCanary } from './lib/catchall.js';

// Curated wordlist. Kept short so per-host runtime stays under ~15s: one
// request per line, threads 20 → ~3s of network.
const CURATED_PATHS = [
  // VCS metadata
  '.git/HEAD', '.git/config', '.git/index', '.gitignore', '.gitconfig',
  '.svn/entries', '.svn/wc.db', '.hg/hgrc',
  // env / config
  '.env', '.env.local', '.env.production', '.env.development', '.env.example',
  'config.json', 'config.yml', 'config.yaml', 'config.php.bak',
  'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.swp', 'wp-config.php~',
  'app/config/parameters.yml', 'config/database.yml', 'settings.py.bak',
  // secrets / creds
  'credentials', 'credentials.json', 'secrets.json', 'private.pem',
  'server-key.pem', 'id_rsa', 'id_dsa', 'aws-credentials',
  // build / test artefacts
  'phpinfo.php', 'info.php', 'test.php', 'debug.php',
  'phpmyadmin/', 'adminer.php', 'adminer/',
  // admin panels
  'admin/', 'administrator/', 'manager/', 'wp-admin/',
  'server-status', 'server-info', 'nginx_status',
  'actuator/env', 'actuator/health', 'actuator/heapdump',
  'management/health', 'trace', 'console',
  // dotfiles / editor backups
  '.DS_Store', '.htaccess', '.htpasswd', '.bash_history', '.ssh/id_rsa',
  '.npmrc', '.dockerignore', '.editorconfig',
  // build outputs
  'composer.json', 'composer.lock', 'package.json', 'package-lock.json',
  'yarn.lock', 'Gemfile', 'Gemfile.lock', 'go.mod', 'go.sum',
  'requirements.txt', 'Dockerfile', 'docker-compose.yml',
  // backups
  'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 'database.sql',
  'dump.sql', 'site.tar.gz', 'www.zip', 'public.zip',
  // graphql / api docs
  'graphql', 'api/graphql', 'swagger.json', 'swagger-ui/', 'openapi.json',
  'api-docs', 'v1/swagger.json', 'v2/api-docs',
  // .well-known signals
  '.well-known/security.txt', '.well-known/openid-configuration',
  '.well-known/assetlinks.json', '.well-known/apple-app-site-association',
] as const;

// Path → severity mapping. Anything not classified stays medium.
function severityForPath(p: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  if (/^\.git\/|^\.svn\/|^\.hg\//.test(p)) return 'high';
  if (/^\.env(\b|\.)/.test(p) || /credentials|secrets\.json|\bid_(rsa|dsa)\b|private\.pem/.test(p)) return 'high';
  if (/wp-config\.php\.(bak|old|swp|~)|settings\.py\.bak|parameters\.yml|database\.yml/.test(p)) return 'high';
  if (/phpinfo|info\.php|debug\.php|test\.php/.test(p)) return 'medium';
  if (/phpmyadmin|adminer/.test(p)) return 'medium';
  if (/server-status|server-info|nginx_status|actuator\/(env|heapdump)|management\/|trace|console/.test(p)) return 'medium';
  if (/\.(zip|tar\.gz|sql)$/.test(p)) return 'high';
  if (/^admin\/|^administrator\/|^manager\/|^wp-admin\//.test(p)) return 'low';
  if (/graphql|swagger|openapi|api-docs/.test(p)) return 'low';
  if (/\.DS_Store|\.htaccess|\.htpasswd|\.bash_history|\.npmrc/.test(p)) return 'medium';
  if (/\.well-known\/(openid-configuration|security\.txt|assetlinks|apple-app-site-association)/.test(p)) return 'info';
  if (/composer|package|yarn|Gemfile|go\.(mod|sum)|requirements|Dockerfile|docker-compose/.test(p)) return 'low';
  return 'medium';
}

interface LiveUrl { target: string; seed: string }

function loadLive(db: Db, targets: readonly string[]): LiveUrl[] {
  if (!targets.length) return [];
  const p = targets.map(() => '?').join(',');
  const rows = db.raw.prepare(
    `SELECT DISTINCT target, url FROM http_probes
     WHERE target IN (${p}) AND (url LIKE 'http://%' OR url LIKE 'https://%')`
  ).all(...targets) as { target: string; url: string }[];
  const bySeed = new Map<string, LiveUrl>();
  for (const r of rows) {
    const existing = bySeed.get(r.target);
    if (!existing || (existing.seed.startsWith('http://') && r.url.startsWith('https://'))) {
      bySeed.set(r.target, { target: r.target, seed: r.url.replace(/\/+$/, '') });
    }
  }
  return [...bySeed.values()];
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let threads = 20;
  let timeoutSec = 8;
  let hostTimeoutSec = 60;
  let liveOnly = true;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--threads' || a === '-t') threads = parseInt(nxt(), 10);
    else if (a === '--timeout') timeoutSec = parseInt(nxt(), 10);
    else if (a === '--host-timeout') hostTimeoutSec = parseInt(nxt(), 10);
    else if (a === '--no-live-only') liveOnly = false;
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('ffuf', `
ffuf against a curated high-signal wordlist (~80 paths: .git/, .env,
wp-config backups, phpinfo, server-status, backup archives, common admin
panels). Runs one ffuf per live target, filters to status 200/301/302/401/403,
dedupes by size to strip WAF-uniform 404 responses.

Severity per path class:
  .git/.env/backups/private keys           high
  phpinfo/phpmyadmin/actuator/server-info  medium
  admin panels/graphql/build metadata      low

Wrapper flags (before '--'):
  --threads/-t <N>       ffuf worker threads per host (default: 20)
  --timeout <s>          per-request timeout (default: 8)
  --host-timeout <s>     per-host hard cap (default: 60)
  --no-live-only         include hosts httpx never saw alive`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('ffuf');
  if (!opts.sqlite) { console.error('ffuf: --sqlite is required'); process.exit(1); }

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = openDb(opts.sqlite);
  const runId = db.startRun('ffuf', { targets: targets.length, wordSize: CURATED_PATHS.length, liveOnly }, now);

  const live = liveOnly ? loadLive(db, targets) : targets.map((t) => ({ target: t, seed: `https://${t}` }));
  console.error(`ffuf live-only filter: ${targets.length} → ${live.length}`);
  if (!live.length) {
    db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
    db.close();
    return;
  }

  // Curated wordlist to a temp file — ffuf needs it on disk.
  const wl = resolveOutputPath({ ...opts, outFile: null }, runId, 'ffuf-wordlist.txt');
  writeLines(wl, [...CURATED_PATHS]);

  let findings = 0;
  let reviewFindings = 0;
  for (const { target, seed } of live) {
    // Canary: fetch an unlikely-to-exist path first. If the host is a catch-all
    // responder (Zorp/decoy/SPA-that-serves-index-html-for-everything), the
    // canary tells us exactly what "no such thing" looks like there. Any ffuf
    // hit sharing the canary's (status, near-size) is marked needs_review; the
    // body is fetched and preserved for a human to confirm.
    const canary = await fetchCanary(seed, timeoutSec);
    if (canary) {
      console.error(`  ${target}: canary ${canary.status} ${canary.size}b hash=${canary.hash.slice(0, 8)}`);
    }

    const out = resolveOutputPath({ ...opts, outFile: null }, runId, `ffuf-${target.replace(/[^a-z0-9._-]/gi, '_')}.json`);
    const args = [
      '-u', `${seed}/FUZZ`,
      '-w', `${wl}:FUZZ`,
      '-t', String(threads),
      '-timeout', String(timeoutSec),
      '-maxtime-job', String(hostTimeoutSec),
      '-mc', '200,301,302,401,403',
      '-of', 'json', '-o', out,
      '-noninteractive', '-s',
      ...passthrough,
    ];
    console.error(`ffuf ${seed}/FUZZ`);
    const r = await run('ffuf', args, { timeoutMs: (hostTimeoutSec + 15) * 1000 });
    if (r.code !== 0 && !fs.existsSync(out)) {
      console.error(`  ${target}: ffuf exited ${r.code}, no report`);
      continue;
    }
    if (!fs.existsSync(out)) continue;

    const raw = fs.readFileSync(out, 'utf8').trim();
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw) as {
        results?: Array<{ url?: string; input?: { FUZZ?: string }; status?: number; length?: number; words?: number; lines?: number }>;
      };
      const results = parsed.results ?? [];
      // Dedupe by (status, length) — WAFs / stock 4xx pages produce identical
      // sizes across many probes. Any (status, length) that repeats > 5 times
      // is a generic response, not a real hit. This is much tighter than a
      // percentage cutoff and catches nginx-stock-403 leakage where 25/80
      // paths return the same 162-byte 403 page.
      const tupleCounts = new Map<string, number>();
      for (const h of results) {
        const key = `${h.status ?? '?'}|${h.length ?? 0}`;
        tupleCounts.set(key, (tupleCounts.get(key) ?? 0) + 1);
      }
      const wafTuples = new Set(
        [...tupleCounts.entries()].filter(([, n]) => n > 5).map(([k]) => k)
      );
      const kept = results.filter((h) => !wafTuples.has(`${h.status ?? '?'}|${h.length ?? 0}`));

      // Near-size clustering: WAF dedup catches exact (status, size) matches
      // but a catch-all responder that echoes the request path into the body
      // produces sizes that vary by exactly len(path). Bucket by 50-byte
      // windows to catch those. Any cluster of >=3 or one near the canary →
      // marked needs_review, page + status preserved for the human.
      const nearBucket = (h: { status?: number; length?: number }): string =>
        `${h.status ?? '?'}|${Math.floor((h.length ?? 0) / 50)}`;
      const nearCounts = new Map<string, number>();
      for (const h of kept) nearCounts.set(nearBucket(h), (nearCounts.get(nearBucket(h)) ?? 0) + 1);

      // Cap the number of body-preserving probes per host so a heavy false
      // positive doesn't turn ffuf into a 100-request-per-target crawl.
      const MAX_BODIES_PER_HOST = 5;
      // Separate budget for sensitive-path re-fetches (.git/.svn/.env/…).
      // ffuf's initial status/size can lie (WAF UA-gating, path normalisation
      // differences), so for high-severity paths we do a real GET and only
      // downgrade or escalate based on the direct-fetch body.
      const MAX_SENSITIVE_PROBES_PER_HOST = 10;
      let bodiesFetched = 0;
      let sensitiveProbes = 0;
      let reviewFindingsThisHost = 0;

      for (const hit of kept) {
        const p = hit.input?.FUZZ ?? '';
        const nearCount = nearCounts.get(nearBucket(hit)) ?? 0;
        const matchesCanary = canary != null
          && isNearCanary(canary, { status: hit.status ?? null, size: hit.length ?? null });
        const looksFake = nearCount >= 3 || matchesCanary;

        let bodyStatus: number | undefined;
        let bodyPreview: string | undefined;
        let confirmedFake = false;
        let realLeakConfirmed = false;
        if (looksFake && bodiesFetched < MAX_BODIES_PER_HOST) {
          const targetUrl = hit.url ?? `${seed}/${p}`;
          const probe = await probeUrl(targetUrl, timeoutSec, 8192);
          bodiesFetched++;
          if (probe) {
            bodyStatus = probe.status;
            bodyPreview = probe.body.slice(0, 4096);
            if (canary && hashBody(probe.body, targetUrl) === canary.hash) confirmedFake = true;
          }
        }

        // Sensitive-path verification: for a path that would otherwise land
        // as HIGH/CRITICAL, trust a direct GET over ffuf's summary. Two
        // failure modes we're covering:
        //   1. 401/403 phantom leaks — ffuf reports "hit" but the server
        //      actively refused; body is empty or a generic error page.
        //   2. 200 SPA-fallback leaks — the site is a single-page app that
        //      returns index.html for every unknown route, so ffuf sees
        //      `200 .env (68381b)` when the body is really just the
        //      homepage. Missed by (status,size) dedup if fewer than 5
        //      probes collide at the same tuple.
        //
        // Verify by fetching the body ourselves and comparing to the canary
        // (a body hash from a known-nonexistent URL). If the sensitive-path
        // body matches the canary hash, it's the same fallback response and
        // no actual sensitive file leaked.
        const stInitial = hit.status ?? 0;
        const pathSev = severityForPath(p);
        const isSensitive = pathSev === 'high' || pathSev === 'critical';
        const wantsVerify = isSensitive && !looksFake &&
          ((stInitial === 401 || stInitial === 403) || (stInitial >= 200 && stInitial < 300));
        if (wantsVerify && sensitiveProbes < MAX_SENSITIVE_PROBES_PER_HOST) {
          const targetUrl = hit.url ?? `${seed}/${p}`;
          const probe = await probeUrl(targetUrl, timeoutSec, 8192);
          sensitiveProbes++;
          if (probe) {
            bodyStatus = probe.status;
            bodyPreview = probe.body.slice(0, 4096);
            const isCanaryBody = canary != null && hashBody(probe.body, targetUrl) === canary.hash;
            // Real leak = 2xx AND non-empty body AND body ≠ canary. Anything
            // else (still 401/403, empty body, or matches the catch-all
            // canary) is a false positive.
            if (probe.status >= 200 && probe.status < 300 && probe.size > 0 && !isCanaryBody) {
              realLeakConfirmed = true;
            }
          }
        }

        // Severity precedence:
        //   fake catch-all       → info
        //   verified real leak   → keep path's HIGH/CRITICAL (ffuf lied about 403)
        //   sensitive+access-denied unverified → low + needs_review (defensive)
        //   otherwise            → severityForPath(p) as normal
        const downgraded = wantsVerify && !realLeakConfirmed;
        let severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
        if (looksFake) severity = 'info';
        else if (downgraded) severity = 'low';
        else severity = pathSev;
        const reviewNote = confirmedFake
          ? ' — catch-all responder (body matches canary)'
          : looksFake
          ? ' — likely catch-all responder'
          : realLeakConfirmed
          ? ` — verified leak: direct GET returned ${bodyStatus} (${bodyPreview?.length ?? 0}b)`
          : downgraded
          ? (stInitial >= 200 && stInitial < 300
              ? ` — SPA / catch-all fallback (body matches canary; not a real leak)`
              : ` — ffuf saw ${stInitial}; direct GET confirmed no leak`)
          : '';
        const titlePrefix = looksFake || downgraded ? '[needs review] ' : '';

        db.insertFinding({
          tool: 'ffuf', target,
          category: `path-${hit.status ?? '?'}`,
          severity,
          title: `${titlePrefix}${hit.status ?? '?'} ${p} (${hit.length ?? 0}b${reviewNote})`,
          matched_at: hit.url ?? `${seed}/${p}`,
          meta: {
            path: p, status: hit.status, length: hit.length, words: hit.words, lines: hit.lines,
            // fields consumed by `query review`
            needs_review: looksFake || undefined,
            confirmed_fake: confirmedFake || undefined,
            near_cluster_count: looksFake ? nearCount : undefined,
            body_status: bodyStatus,
            body_preview: bodyPreview,
            canary: canary
              ? { url: canary.url, status: canary.status, size: canary.size, hash: canary.hash }
              : undefined,
          },
          needsReview: looksFake || downgraded,
        }, now, runId);
        findings++;
        if (looksFake || downgraded) { reviewFindings++; reviewFindingsThisHost++; }
      }
      console.error(
        `  ${target}: ${kept.length}/${results.length} hits kept ` +
          `(${results.length - kept.length} WAF-uniform, ${reviewFindingsThisHost} needs_review, ` +
          `${bodiesFetched} body preserved)`
      );
    } catch (e) {
      console.error(`  ${target}: parse error: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  db.finishRun(runId, { targetsCount: live.length, findingsCount: findings, at: new Date().toISOString() });
  db.close();
  console.error(
    `ffuf done: +${findings} finding(s) across ${live.length} host(s), ` +
      `${reviewFindings} flagged needs_review, run #${runId}`
  );
  console.error(`  sqlite: ${path.resolve(opts.sqlite)}`);
  console.error(`  review flagged findings with:  npm run query -- review --limit 50`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
