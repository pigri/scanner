#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';
import { fetchCanary, probeUrl, hashBody, isNearCanary, type CanaryProbe } from './lib/catchall.js';

// Nuclei templates whose semantics are "did the server return a page for this
// path?" — these fire false positives on catch-all responders that return the
// same page for every URL. Template IDs match on category prefixes and common
// "-detect"/"-detection" suffixes. TLS/headers/DNS/wappalyzer templates are
// deliberately NOT in this set — those observations are true even on decoys.
const CATCHALL_SUSPECT_TEMPLATE_RE =
  /(?:^|[\/-])(exposures|exposed-panels|backup|config-exposure|wp-config|env-file|secrets|debug-endpoint|token-exposure|dump-files)(?:[\/-]|$)|(?:-detect(?:ion)?$)/i;

// Extract the bare host from a nuclei matched-at URL so we can look up its
// canary. Falls back to the raw string when parsing fails.
function hostOf(url: string | null | undefined): string {
  if (!url) return '';
  try { return new URL(url.startsWith('http') ? url : `https://${url}`).host; }
  catch { return url.split('/')[0] ?? ''; }
}

function loadLiveHttpTargets(db: Db): Set<string> {
  const set = new Set<string>();
  // Hosts httpx got any HTTP(S) response from — the ones nuclei can actually reach.
  const rows = db.raw.prepare(
    "SELECT DISTINCT target FROM http_probes WHERE url LIKE 'http://%' OR url LIKE 'https://%'"
  ).all() as { target: string }[];
  for (const r of rows) set.add(r.target);
  // Fallback: hosts with port 80 or 443 seen open by nmap/masscan.
  const portRows = db.raw.prepare(
    'SELECT DISTINCT target FROM ports WHERE port IN (80, 443, 8080, 8443)'
  ).all() as { target: string }[];
  for (const r of portRows) set.add(r.target);
  return set;
}

// Load katana-discovered URLs for the current batch's targets. Filters out
// static assets (nothing server-side to scan there) and caps per-host to keep
// scan time bounded. Preference: same host as target, status=200, canonical
// path (query string stripped for dedup).
function loadKatanaUrls(db: Db, targets: readonly string[], perHostCap: number): string[] {
  if (!targets.length) return [];
  const staticExt = /\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|eot|mp4|mp3|webm|ogg|pdf|zip|gz|bz2|xz|7z|tar|rar)($|\?)/i;
  const placeholders = targets.map(() => '?').join(',');
  const rows = db.raw.prepare(
    `SELECT target, url, status FROM discovered_urls
     WHERE target IN (${placeholders})
       AND source = 'katana'
     ORDER BY target, url`
  ).all(...targets) as { target: string; url: string; status: number | null }[];

  const perHost = new Map<string, Set<string>>();
  for (const r of rows) {
    if (staticExt.test(r.url)) continue;
    // Skip clear 4xx/5xx; accept 200 or unknown status (naabu-like probes).
    if (r.status !== null && r.status >= 400) continue;
    let canonical: string;
    try {
      const u = new URL(r.url);
      canonical = `${u.protocol}//${u.host}${u.pathname}`;   // dedup on scheme+host+path
    } catch { continue; }
    const bucket = perHost.get(r.target) ?? new Set<string>();
    if (bucket.size >= perHostCap) continue;
    bucket.add(canonical);
    perHost.set(r.target, bucket);
  }
  const out: string[] = [];
  for (const s of perHost.values()) for (const u of s) out.push(u);
  return out;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);

  // Own-wrapper flags parsed from extraArgs (everything after `--` on cli).
  let concurrency = 50;
  let rateLimit = 150;
  let templateTimeout = 5;
  let retries = 1;
  let maxHostError = 30;   // skip a host after this many errors (was -no-mhe = never skip → hangs)
  let scanTimeoutSec = 900; // hard cap on the whole nuclei run so a batch can't hang
  let liveOnly = false;
  let severity = 'info,low,medium,high,critical';
  let fromUrls = false;         // pull katana URLs into the scan target set
  let urlsPerHost = 100;        // cap so a chatty crawl doesn't dominate the run
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '-c' || a === '--concurrency') concurrency = Math.max(1, parseInt(nxt(), 10));
    else if (a === '--rate-limit') rateLimit = parseInt(nxt(), 10);
    else if (a === '--timeout') templateTimeout = parseInt(nxt(), 10);
    else if (a === '--retries') retries = parseInt(nxt(), 10);
    else if (a === '--max-host-error') maxHostError = parseInt(nxt(), 10);
    else if (a === '--scan-timeout') scanTimeoutSec = parseInt(nxt(), 10);
    else if (a === '--live-only') liveOnly = true;
    else if (a === '--severity') severity = nxt();
    else if (a === '--from-urls') fromUrls = true;
    else if (a === '--urls-per-host') urlsPerHost = parseInt(nxt(), 10);
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('nuclei', `
Runs projectdiscovery nuclei with community templates.
Default profile: -severity info,low,medium,high,critical -c 50 -rate-limit 150
                 -timeout 5 -retries 1 -stats -mhe 30 -fhr (scan-timeout 900s)
                 (-fhr follows same-host redirects so redirect-fronted apps get scanned)

Wrapper flags (before '--'):
  --live-only          filter to hosts we've seen alive (http_probes URL OR
                       nmap port 80/443/8080/8443). Requires --sqlite.
  --from-urls          also scan the URLs katana discovered for these targets
                       (skips static-asset paths + caps per-host — see
                       --urls-per-host). Requires --sqlite. Would catch the
                       likes of /forms/frmservlet and /i/apex_version.txt
                       that root-only scans miss.
  --urls-per-host <N>  cap per-host URL sample when --from-urls is on (100)
  --severity <list>    override severity filter
  -c, --concurrency N  parallel workers (default: 50)
  --rate-limit <N>     max req/s across all workers (default: 150)
  --timeout <sec>      per-request timeout (default: 5)
  --retries <N>        per-request retries (default: 1)
  --max-host-error <N> skip a host after N errors (default: 30; prevents hangs
                       on slow/tarpitting hosts)
  --scan-timeout <sec> hard cap on the whole nuclei run (default: 900)

Everything after '--' is passed to nuclei verbatim.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('nuclei');
  let { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;

  // Live-only pre-filter — nuclei doesn't skip dead hosts on its own, they burn
  // full per-template timeouts each. Filtering upstream is the biggest speed win.
  if (liveOnly) {
    if (!db) { console.error('--live-only requires --sqlite'); process.exit(1); }
    const live = loadLiveHttpTargets(db);
    const before = targets.length;
    targets = targets.filter((t) => live.has(t.replace(/^https?:\/\//, '').split('/')[0]!));
    console.error(`--live-only filter: ${before} → ${targets.length} targets`);
    if (!targets.length) { console.error('no live http targets'); if (db) db.close(); process.exit(0); }
  }

  // --from-urls: augment the FQDN target list with katana-discovered URLs so
  // nuclei probes real endpoints, not just the site root. Filters static
  // assets + caps per host so a chatty crawl can't dominate the run.
  let urlSample: string[] = [];
  if (fromUrls) {
    if (!db) { console.error('--from-urls requires --sqlite'); process.exit(1); }
    urlSample = loadKatanaUrls(db, targets, urlsPerHost);
    console.error(`--from-urls: pulled ${urlSample.length} katana URLs across ${targets.length} target(s) (cap ${urlsPerHost}/host)`);
  }

  const runId = db ? db.startRun('nuclei', {
    targets: targets.length, urlSample: urlSample.length,
    liveOnly, severity, concurrency, rateLimit,
    timeout: templateTimeout, retries, fromUrls, urlsPerHost, extraArgs: passthrough,
  }, now) : null;

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'nuclei-targets.txt');
  writeLines(tmp, [...targets, ...urlSample]);
  const outFile = resolveOutputPath(opts, runId, 'nuclei.jsonl');
  const args = [
    '-l', tmp, '-jsonl', '-o', outFile,
    '-severity', severity,
    '-c', String(concurrency),
    '-rate-limit', String(rateLimit),
    '-timeout', String(templateTimeout),
    '-retries', String(retries),
    // -mhe (max-host-error): skip a host after N errors. The old -no-mhe made
    // nuclei grind forever on slow/tarpitting hosts, piling up connections.
    '-mhe', String(maxHostError),
    // -fhr (follow-host-redirects): scan the app a host redirects to (e.g. an
    // nginx front doing / -> /ords/ for Oracle APEX). Host-only, NOT -fr, so the
    // vuln scanner never chases an off-scope external redirect (e.g. to an SSO).
    '-fhr',
    '-stats',
    ...passthrough,
  ];
  console.error(`nuclei ${args.join(' ')} (scan-timeout ${scanTimeoutSec}s)`);
  // Hard cap the whole run so one bad batch can't block the pipeline; partial
  // JSONL written so far is still ingested.
  const r = await run('nuclei', args, { timeoutMs: scanTimeoutSec * 1000 });
  if (r.code !== 0) console.error(`nuclei exited ${r.code} (may be scan-timeout kill); output: ${outFile}`);
  else console.error(`nuclei exited ${r.code}, output: ${outFile}`);

  if (db && runId !== null && fs.existsSync(outFile)) {
    // Pre-flight: canary probe every target we're about to ingest, so we can
    // recognise catch-all responders. Cached per host and reused when scoring
    // each finding. Cheap (one HTTP fetch per host, in parallel batches).
    const canaries = new Map<string, CanaryProbe | null>();
    const bodyCache = new Map<string, { status: number; body: string } | null>();
    const canaryBatchSize = 20;
    for (let i = 0; i < targets.length; i += canaryBatchSize) {
      const chunk = targets.slice(i, i + canaryBatchSize);
      await Promise.all(chunk.map(async (t) => {
        canaries.set(t, await fetchCanary(`https://${t}`, 6));
      }));
    }
    const catchallHosts = new Set(
      [...canaries.entries()].filter(([, c]) => c && c.status === 200 && c.size > 500).map(([t]) => t)
    );
    console.error(`nuclei: canary probes flagged ${catchallHosts.size}/${targets.length} host(s) as catch-all responders`);

    let count = 0;
    let reviewCount = 0;
    for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line) as {
          'template-id'?: string; template_id?: string;
          info?: { name?: string; severity?: string; classification?: { 'cve-id'?: string[] } };
          host?: string; 'matched-at'?: string;
        };
        const tid = row['template-id'] ?? row.template_id ?? 'unknown';
        const cves = row.info?.classification?.['cve-id'];
        const targetHost = row.host ?? hostOf(row['matched-at']) ?? '';
        const bareHost = hostOf(targetHost) || targetHost;

        // needs_review path: host was flagged as catch-all AND this template's
        // category is one that fires on any-200 responder. Preserve body once
        // per (host, url) pair so a reviewer can eyeball the actual response.
        const canary = canaries.get(bareHost) ?? null;
        const isSuspect = canary != null && catchallHosts.has(bareHost)
          && CATCHALL_SUSPECT_TEMPLATE_RE.test(tid);

        let bodyStatus: number | undefined;
        let bodyPreview: string | undefined;
        let confirmedFake = false;
        if (isSuspect && row['matched-at']) {
          const cacheKey = row['matched-at'];
          let probe = bodyCache.get(cacheKey);
          if (probe === undefined) {
            probe = await probeUrl(cacheKey, 6, 8192);
            bodyCache.set(cacheKey, probe);
          }
          if (probe) {
            bodyStatus = probe.status;
            bodyPreview = probe.body.slice(0, 4096);
            if (canary && hashBody(probe.body, cacheKey) === canary.hash) confirmedFake = true;
            // Also: is the response near-canary in shape?
            if (!confirmedFake && canary && isNearCanary(canary, { status: probe.status, size: probe.body.length })) {
              // still likely fake but not byte-identical (e.g. small dynamic bit)
            }
          }
        }

        const reviewNote = confirmedFake
          ? ' — catch-all responder (body matches canary)'
          : isSuspect
          ? ' — likely catch-all responder'
          : '';
        const titlePrefix = isSuspect ? '[needs review] ' : '';
        const baseTitle = row.info?.name ?? tid;

        db.insertFinding({
          tool: 'nuclei',
          target: targetHost,
          category: tid,
          severity: isSuspect ? 'info' : (row.info?.severity ?? null),
          title: `${titlePrefix}${baseTitle}${reviewNote}`,
          cve: cves && cves.length ? cves[0]! : null,
          matched_at: row['matched-at'] ?? null,
          meta: {
            ...row,
            needs_review: isSuspect || undefined,
            confirmed_fake: confirmedFake || undefined,
            body_status: bodyStatus,
            body_preview: bodyPreview,
            canary: canary
              ? { url: canary.url, status: canary.status, size: canary.size, hash: canary.hash }
              : undefined,
          },
          needsReview: isSuspect,
        }, now, runId);
        count++;
        if (isSuspect) reviewCount++;
      } catch { /* ignore */ }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(
      `  sqlite: ${path.resolve(opts.sqlite!)} (+${count} findings, ${reviewCount} needs_review, run #${runId})`
    );
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
