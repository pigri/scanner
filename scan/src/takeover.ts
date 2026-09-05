#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('takeover', `
Runs nuclei with just the subdomain-takeover templates. Fast, cheap, high-signal.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('nuclei');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('takeover', { targets: targets.length }, now) : null;

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'takeover-targets.txt');
  writeLines(tmp, targets);
  const outFile = resolveOutputPath(opts, runId, 'takeover.jsonl');
  const args = [
    '-l', tmp, '-jsonl', '-o', outFile,
    '-tags', 'takeover',
    '-rate-limit', '100',
    ...opts.extraArgs,
  ];
  console.error(`nuclei ${args.join(' ')}`);
  const r = await run('nuclei', args);
  console.error(`takeover exited ${r.code}, output: ${outFile}`);

  if (db && runId !== null && fs.existsSync(outFile)) {
    let count = 0;
    for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line) as {
          'template-id'?: string; info?: { name?: string; severity?: string };
          host?: string; 'matched-at'?: string;
        };
        db.insertFinding({
          tool: 'takeover',
          target: row.host ?? row['matched-at'] ?? '',
          category: row['template-id'] ?? 'takeover',
          severity: row.info?.severity ?? 'high',
          title: row.info?.name ?? row['template-id'] ?? 'subdomain takeover',
          cve: null,
          matched_at: row['matched-at'] ?? null,
          meta: row,
        }, now, runId);
        count++;
      } catch { /* ignore */ }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${count} findings, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
