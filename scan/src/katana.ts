#!/usr/bin/env -S node --loader tsx
// katana: ProjectDiscovery web crawler. Feeds the discovered_urls table so
// nuclei can rescan at the URL level (not just FQDN root). Would have caught
// the Oracle Forms /forms/frmservlet hit and the APEX /i/apex_version.txt
// disclosure automatically — httpx only probes '/'.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';

// Restrict crawl seeds to hosts we've confirmed alive via httpx. Crawling dead
// hosts wastes the per-host connect timeout, and there's usually a big list.
function loadLiveHttpTargets(db: Db): Map<string, string> {
  // target FQDN → seed URL (prefer https if present, else http).
  const rows = db.raw.prepare(
    "SELECT target, url FROM http_probes WHERE url LIKE 'http://%' OR url LIKE 'https://%'"
  ).all() as { target: string; url: string }[];
  const bySeed = new Map<string, string>();
  for (const r of rows) {
    const existing = bySeed.get(r.target);
    if (!existing || (existing.startsWith('http://') && r.url.startsWith('https://'))) {
      bySeed.set(r.target, r.url);
    }
  }
  return bySeed;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);

  let depth = 2;
  let concurrency = 20;
  let crawlTimeout = 60;    // seconds per host, hard cap on how long crawler runs
  let jsCrawl = true;
  let knownFiles = 'all';   // robots.txt + sitemap.xml + common paths
  let liveOnly = true;      // default on — dead hosts waste time
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--depth' || a === '-d') depth = parseInt(nxt(), 10);
    else if (a === '--concurrency' || a === '-c') concurrency = parseInt(nxt(), 10);
    else if (a === '--crawl-timeout' || a === '-ct') crawlTimeout = parseInt(nxt(), 10);
    else if (a === '--no-js-crawl') jsCrawl = false;
    else if (a === '--known-files' || a === '-kf') knownFiles = nxt();
    else if (a === '--no-live-only') liveOnly = false;
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('katana', `
ProjectDiscovery katana web crawler. Feeds the discovered_urls table with
every URL encountered — nuclei can then re-run against the URL set instead
of only the root FQDN.

Default profile: -d 2 -c 20 -ct 60 -jc -kf all -jsonl -silent -ob -or.

Wrapper flags (before '--'):
  --depth/-d <N>          crawl depth (default: 2)
  --concurrency/-c <N>    parallel workers (default: 20)
  --crawl-timeout/-ct <s> per-host crawl cap (default: 60)
  --no-js-crawl           disable in-JS endpoint parsing
  --known-files/-kf <s>   crawl robots/sitemap ('all', 'none', 'robotstxt')
  --no-live-only          include hosts httpx never saw alive

Everything after '--' passes to katana verbatim.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('katana');

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  let { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  // Turn each target into a seed URL. Prefer whatever httpx observed (right
  // scheme + port); fall back to https:// for hosts httpx never touched (when
  // --no-live-only is set).
  let seeds: string[];
  if (liveOnly) {
    if (!db) { console.error('--live-only default requires --sqlite; pass --no-live-only to disable'); process.exit(1); }
    const bySeed = loadLiveHttpTargets(db);
    const before = targets.length;
    targets = targets.filter((t) => bySeed.has(t));
    console.error(`live-only filter: ${before} → ${targets.length} targets`);
    if (!targets.length) { console.error('no live http targets'); if (db) db.close(); process.exit(0); }
    seeds = targets.map((t) => bySeed.get(t)!);
  } else {
    seeds = targets.map((t) => t.startsWith('http') ? t : `https://${t}`);
  }

  const runId = db ? db.startRun('katana', { targets: targets.length, depth, concurrency, crawlTimeout, jsCrawl, knownFiles }, now) : null;

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'katana-targets.txt');
  writeLines(tmp, seeds);
  const outFile = resolveOutputPath(opts, runId, 'katana.jsonl');

  const args = [
    '-list', tmp,
    '-d', String(depth),
    '-c', String(concurrency),
    '-ct', String(crawlTimeout),
    ...(jsCrawl ? ['-jc'] : []),
    ...(knownFiles && knownFiles !== 'none' ? ['-kf', knownFiles] : []),
    '-jsonl', '-o', outFile,
    '-silent',
    // Omit response body + raw request/response — we only care about URLs and
    // status codes here. Bodies balloon the JSONL by 100x for no benefit.
    '-ob', '-or',
    ...passthrough,
  ];
  console.error(`katana ${args.join(' ')}`);
  // Whole-batch cap: worst case per host = crawlTimeout, so cap at
  // targets * crawlTimeout + 60s slack.
  const hardCapMs = (targets.length * crawlTimeout + 60) * 1000;
  const r = await run('katana', args, { timeoutMs: hardCapMs });
  if (r.code !== 0) console.error(`katana exited ${r.code} (may be timeout kill); output: ${outFile}`);
  else console.error(`katana exited 0, output: ${outFile}`);

  if (db && runId !== null && fs.existsSync(outFile)) {
    // Reverse map: hostname → target FQDN we crawled from. Some URLs katana
    // discovers may be off-target (e.g., CDN); we key those to the seed FQDN
    // that led to them, using the seed's hostname as the fallback.
    const targetByHost = new Map<string, string>();
    for (let i = 0; i < targets.length; i++) {
      const host = new URL(seeds[i]!).hostname;
      targetByHost.set(host, targets[i]!);
    }

    let count = 0;
    for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        const row = JSON.parse(t) as {
          request?: { endpoint?: string; method?: string };
          response?: { status_code?: number; headers?: Record<string, string> };
        };
        const url = row.request?.endpoint;
        if (!url) continue;
        let host: string;
        try { host = new URL(url).hostname; } catch { continue; }
        const target = targetByHost.get(host) ?? host;
        db.insertDiscoveredUrl({
          target, url,
          method: row.request?.method ?? 'GET',
          source: 'katana',
          status: row.response?.status_code ?? null,
          content_type: row.response?.headers?.['Content-Type'] ?? row.response?.headers?.['content-type'] ?? null,
        }, now, runId);
        count++;
      } catch { /* ignore */ }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${count} URLs, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
