#!/usr/bin/env -S node --loader tsx
// waybackurls (tomnomnom): pull URLs from web.archive.org's CDX index for
// each target. Overlaps with gau's wayback provider but uses a different
// path through the CDX API — running both catches URLs one alone misses
// (e.g., when the CDX query hits a rate-limit or pagination edge). Rows
// dedupe automatically via discovered_urls UNIQUE(target, url).
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let noSubs = true;                        // scan per-target so subdomain expansion happens upstream
  let perHostCap = 5000;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--include-subs') noSubs = false;
    else if (a === '--per-host-cap') perHostCap = parseInt(nxt(), 10);
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('waybackurls', `
waybackurls — pull URLs from the Wayback Machine CDX index per target.
Persists into discovered_urls (source='waybackurls'). Overlaps with gau's
wayback provider — running both catches CDX-pagination edge cases.

Wrapper flags (before '--'):
  --include-subs         allow subdomains (default: -no-subs, exact host only)
  --per-host-cap <N>     ceiling per target FQDN (default: 5000)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('waybackurls');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('waybackurls', { targets: targets.length, noSubs, perHostCap }, now) : null;
  const outFile = resolveOutputPath(opts, runId, 'waybackurls.txt');
  const stream = fs.createWriteStream(outFile);

  let count = 0;
  for (const target of targets) {
    const args = [...(noSubs ? ['-no-subs'] : []), ...passthrough];
    console.error(`waybackurls ${target}`);
    const r = await run('waybackurls', args, { timeoutMs: 3 * 60 * 1000, stdin: target + '\n' });
    let perTarget = 0;
    for (const line of r.stdout.split('\n')) {
      const url = line.trim();
      if (!url || !url.startsWith('http')) continue;
      if (perTarget >= perHostCap) break;
      stream.write(url + '\n');
      if (db && runId !== null) {
        db.insertDiscoveredUrl({ target, url, method: 'GET', source: 'waybackurls' }, now, runId);
      }
      perTarget++;
      count++;
    }
    console.error(`  waybackurls ${target}: +${perTarget}`);
  }
  await new Promise<void>((res) => stream.end(() => res()));
  console.error(`waybackurls done: +${count} URLs total → ${outFile}`);

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
