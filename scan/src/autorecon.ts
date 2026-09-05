#!/usr/bin/env -S node --loader tsx
// AutoRecon: heavy orchestrator that runs nmap + service-specific enum tools
// per target. We wrap it as a "black box" — spawn it once with output dir,
// index the result files. Doesn't parse into findings (output tree is
// tool-specific text/xml/html); use for one-off deep dives, not bulk work.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('autorecon', `
Runs autorecon (Tib3rius) per target in a scoped output directory. Doesn't
parse findings into the DB — this is intentional; the output tree is large
and per-service, and we already run the tool categories it wraps.

Recommended usage: cherry-pick one high-value target at a time.

Everything after '--' is passed to autorecon verbatim.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('autorecon');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('autorecon', { targets: targets.length, extraArgs: opts.extraArgs }, now) : null;

  const outDir = resolveOutputPath({ ...opts, outFile: null }, runId, 'autorecon-out');
  fs.mkdirSync(outDir, { recursive: true });

  const args = ['-o', outDir, ...opts.extraArgs, ...targets];
  console.error(`autorecon ${args.join(' ')}`);
  const r = await run('autorecon', args, { timeoutMs: 4 * 60 * 60 * 1000 });
  console.error(`autorecon exit ${r.code}, output tree: ${outDir}`);

  if (db && runId !== null) {
    // Count top-level artifact files as a rough "findings" number.
    let count = 0;
    const walk = (dir: string): void => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else count++;
      }
    };
    if (fs.existsSync(outDir)) walk(outDir);
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, notes: `output tree at ${outDir}`, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (${count} output files, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
