#!/usr/bin/env -S node --loader tsx
// gau (GetAllUrls): pull historical URLs from wayback / otx / urlscan /
// commoncrawl. Complements katana — katana sees what's linked today, gau sees
// what was linked historically. URL corpus for URL-level nuclei rescans.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let threads = 4;
  let providers = 'wayback,otx,urlscan';   // commoncrawl dropped by default — slow, low-yield
  let blacklist = 'png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,otf,eot,pdf,mp4,mp3,webm,zip,gz';
  let perHostCap = 5000;                    // stop after this many URLs per target
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--threads') threads = parseInt(nxt(), 10);
    else if (a === '--providers') providers = nxt();
    else if (a === '--blacklist') blacklist = nxt();
    else if (a === '--per-host-cap') perHostCap = parseInt(nxt(), 10);
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('gau', `
gau — pull historical URLs from wayback/OTX/URLScan/CommonCrawl. Persists
into discovered_urls (source='gau'). Complements katana's live crawl.

Default profile: --threads 4 --providers wayback,otx,urlscan
                 --blacklist png,jpg,gif,svg,css,woff,pdf,...

Wrapper flags (before '--'):
  --threads <N>          gau worker threads (default: 4)
  --providers <list>     wayback,otx,urlscan,commoncrawl (default omits cc — slow)
  --blacklist <ext,ext>  skip these file extensions
  --per-host-cap <N>     ceiling per target FQDN (default: 5000)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('gau');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('gau', { targets: targets.length, threads, providers, perHostCap }, now) : null;
  const outFile = resolveOutputPath(opts, runId, 'gau.txt');
  const stream = fs.createWriteStream(outFile);

  let count = 0;
  for (const target of targets) {
    const args = ['--threads', String(threads), '--providers', providers, '--blacklist', blacklist, ...passthrough];
    console.error(`gau ${target}`);
    // Feed one target at a time so we can attribute rows to that target and
    // cap per-host. gau accepts one hostname per line on stdin.
    const r = await run('gau', args, { timeoutMs: 3 * 60 * 1000, stdin: target + '\n' });
    let perTarget = 0;
    for (const line of r.stdout.split('\n')) {
      const url = line.trim();
      if (!url || !url.startsWith('http')) continue;
      if (perTarget >= perHostCap) break;
      stream.write(url + '\n');
      if (db && runId !== null) {
        db.insertDiscoveredUrl({ target, url, method: 'GET', source: 'gau' }, now, runId);
      }
      perTarget++;
      count++;
    }
    console.error(`  gau ${target}: +${perTarget}`);
  }
  await new Promise<void>((res) => stream.end(() => res()));
  console.error(`gau done: +${count} URLs total → ${outFile}`);

  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${count} URLs, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
