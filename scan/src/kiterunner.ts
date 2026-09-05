#!/usr/bin/env -S node --loader tsx
// kiterunner (kr) — Assetnote's API-route brute force. Fills a real gap in
// the pipeline: httpx probes only '/', nuclei only hits templated URLs, and
// katana only follows what's linked. kr blindly tries known-API routes.
//
// Filters to live HTTP hosts and, by default, only api-shaped hostnames
// (api.*, api-*, rest.*, graphql.*, v1.*, swagger.*). Disable with
// --all-hosts to run against every live target — much slower.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';
import { fetchCanary, probeUrl, hashBody, isNearCanary, type CanaryProbe } from './lib/catchall.js';

const API_HOST_RE = /(^|[.-])(api|rest|graphql|swagger|openapi|ords|v[0-9]+)([.-]|$)/i;

interface LiveInfo { target: string; seed: string; techJson: string | null }

// Return live HTTP targets from http_probes, preferring HTTPS seed URL per host.
function loadLive(db: Db): Map<string, LiveInfo> {
  const rows = db.raw.prepare(
    "SELECT target, url, tech_json FROM http_probes WHERE url LIKE 'http://%' OR url LIKE 'https://%'"
  ).all() as { target: string; url: string; tech_json: string | null }[];
  const bySeed = new Map<string, LiveInfo>();
  for (const r of rows) {
    const existing = bySeed.get(r.target);
    if (!existing || (existing.seed.startsWith('http://') && r.url.startsWith('https://'))) {
      bySeed.set(r.target, { target: r.target, seed: r.url, techJson: r.tech_json });
    }
  }
  return bySeed;
}

// Heuristic: is this host worth kiterunning? Cheap to be right vs. wrong.
function looksLikeApi(info: LiveInfo): boolean {
  if (API_HOST_RE.test(info.target)) return true;
  if (info.techJson) {
    // httpx often tags API frameworks in tech array — worth burning kr cycles on.
    if (/openapi|swagger|graphql|apigee|kong|ords|jhipster|fastapi|express|django rest|spring/i.test(info.techJson)) {
      return true;
    }
  }
  return false;
}

function severityForStatus(status: number): 'info' | 'low' | 'medium' | 'high' {
  if (status === 200) return 'medium';   // reachable + no auth in front
  if (status === 401 || status === 407) return 'info';   // present, auth required
  if (status === 403) return 'low';                       // present, forbidden
  if (status === 500 || status === 502) return 'low';     // present, error
  return 'info';
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);

  let wordlist = 'apiroutes-260227:5000';   // 5k routes, ~2-3 min per host on a live API
  let maxTimeoutMs = 5 * 60 * 1000;
  let apiOnly = true;                       // skip WordPress sites etc.
  let liveOnly = true;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--wordlist' || a === '-A') wordlist = nxt();
    else if (a === '--host-timeout') maxTimeoutMs = parseInt(nxt(), 10) * 1000;
    else if (a === '--all-hosts') apiOnly = false;
    else if (a === '--no-live-only') liveOnly = false;
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('kiterunner', `
kr scan against Assetnote's api-route wordlist. Emits per-hit findings —
severity mapped from response status (200 medium, 401 info, 403/5xx low).

Default profile: -A apiroutes-260227:5000 (first 5k routes), api-shaped
hosts only, --host-timeout 300s per host.

Wrapper flags (before '--'):
  --wordlist/-A <alias:N>   assetnote wordlist alias (default apiroutes-260227:5000)
  --host-timeout <sec>      per-host hard cap (default: 300)
  --all-hosts               drop the api-shaped-hostname filter (much slower)
  --no-live-only            include hosts httpx never saw alive`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('kr');
  let { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;

  // Resolve live-target seed URLs + apiOnly filter.
  let scanList: LiveInfo[];
  if (liveOnly) {
    if (!db) { console.error('--live-only requires --sqlite'); process.exit(1); }
    const live = loadLive(db);
    const before = targets.length;
    scanList = targets.map((t) => live.get(t)).filter((x): x is LiveInfo => !!x);
    console.error(`live-only filter: ${before} → ${scanList.length}`);
  } else {
    scanList = targets.map((t) => ({ target: t, seed: `https://${t}`, techJson: null }));
  }
  if (apiOnly) {
    const before = scanList.length;
    scanList = scanList.filter(looksLikeApi);
    console.error(`api-shape filter: ${before} → ${scanList.length}`);
  }
  if (!scanList.length) { console.error('no api-shaped live targets'); if (db) db.close(); process.exit(0); }

  const runId = db ? db.startRun('kiterunner', { targets: scanList.length, wordlist, apiOnly, liveOnly }, now) : null;
  const outFile = resolveOutputPath(opts, runId, 'kiterunner.jsonl');
  const wstream = fs.createWriteStream(outFile);

  let findings = 0;
  let reviewFindings = 0;
  for (const info of scanList) {
    // Canary probe first — if this host is a catch-all responder, every kr
    // hit will look like a "reachable API route" when it's actually just the
    // decoy page. Any kr result near the canary's (status, size) is marked
    // needs_review with the real page body preserved.
    const canary: CanaryProbe | null = await fetchCanary(info.seed, 8);
    if (canary) {
      console.error(`  ${info.target}: canary ${canary.status} ${canary.size}b hash=${canary.hash.slice(0, 8)}`);
    }

    console.error(`kr scan ${info.seed}`);
    const args = [
      'scan', info.seed,
      '-A', wordlist,
      '-q', '-o', 'json',
      '--fail-status-codes', '400,404,429,502,503,504,301,302',
      ...passthrough,
    ];
    const r = await run('kr', args, { timeoutMs: maxTimeoutMs });
    const MAX_BODIES_PER_HOST = 5;
    let bodiesFetched = 0;
    let reviewThisHost = 0;
    for (const line of r.stdout.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('{')) continue;
      try {
        const row = JSON.parse(t) as {
          target?: { url?: string };
          method?: string;
          path?: string;
          status_code?: number;
          length?: number;
          words?: number;
        };
        const status = row.status_code ?? 0;
        const url = (row.target?.url ?? info.seed).replace(/\/+$/, '') + (row.path ?? '');
        wstream.write(line + '\n');
        if (db && runId !== null) {
          const looksFake = canary !== null
            && isNearCanary(canary, { status, size: row.length ?? 0 });
          let bodyStatus: number | undefined;
          let bodyPreview: string | undefined;
          let confirmedFake = false;
          if (looksFake && bodiesFetched < MAX_BODIES_PER_HOST) {
            const probe = await probeUrl(url, 8, 8192);
            bodiesFetched++;
            if (probe) {
              bodyStatus = probe.status;
              bodyPreview = probe.body.slice(0, 4096);
              if (canary && hashBody(probe.body, url) === canary.hash) confirmedFake = true;
            }
          }
          const severity = looksFake ? 'info' : severityForStatus(status);
          const reviewNote = confirmedFake
            ? ' — catch-all responder (body matches canary)'
            : looksFake
            ? ' — likely catch-all responder'
            : '';
          const titlePrefix = looksFake ? '[needs review] ' : '';
          db.insertFinding({
            tool: 'kiterunner',
            target: info.target,
            category: `api-route-${status}`,
            severity,
            title: `${titlePrefix}${row.method ?? 'GET'} ${row.path ?? '?'} → ${status} (${row.length ?? 0}b${reviewNote})`,
            matched_at: url,
            meta: {
              ...row,
              needs_review: looksFake || undefined,
              confirmed_fake: confirmedFake || undefined,
              body_status: bodyStatus,
              body_preview: bodyPreview,
              canary: canary
                ? { url: canary.url, status: canary.status, size: canary.size, hash: canary.hash }
                : undefined,
            },
            needsReview: looksFake,
          }, now, runId);
          findings++;
          if (looksFake) { reviewFindings++; reviewThisHost++; }
        }
      } catch { /* ignore malformed line */ }
    }
    console.error(
      `  ${info.target}: exit ${r.code}${r.code !== 0 ? ' (may be host-timeout)' : ''}` +
        (reviewThisHost ? `, ${reviewThisHost} needs_review (${bodiesFetched} bodies preserved)` : '')
    );
  }
  await new Promise<void>((res) => wstream.end(() => res()));
  console.error(
    `kiterunner done: +${findings} route hits across ${scanList.length} host(s), ` +
      `${reviewFindings} flagged needs_review`
  );

  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: scanList.length, findingsCount: findings, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${findings} findings, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
