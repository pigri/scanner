#!/usr/bin/env -S node --loader tsx
// enum4linux (classic Perl). Text output; we persist per-host and index
// the raw file in the run dir. --live-only skips hosts with no :445/:139.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';
import { smbLiveTargets } from './lib/smb-live.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let liveOnly = false;
  const passthrough: string[] = [];
  for (const a of opts.extraArgs) {
    if (a === '--live-only') liveOnly = true;
    else passthrough.push(a);
  }
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('enum4linux', `
Runs enum4linux -a per in-scope host, one at a time. Requires port 445 open.

Wrapper flags (before '--'):
  --live-only     filter targets to those with 445/139 in the ports table.
                  Requires --sqlite.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('enum4linux');
  let { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;

  if (liveOnly) {
    if (!db) { console.error('--live-only requires --sqlite'); process.exit(1); }
    const live = smbLiveTargets(db);
    const before = targets.length;
    targets = targets.filter((t) => live.has(t));
    console.error(`--live-only: ${before} → ${targets.length} targets`);
    if (!targets.length) { console.error('no live SMB targets'); db.close(); process.exit(0); }
  }

  const runId = db ? db.startRun('enum4linux', { targets: targets.length, extraArgs: passthrough }, now) : null;
  const outFile = resolveOutputPath(opts, runId, 'enum4linux.log');
  const stream = fs.createWriteStream(outFile);
  let findings = 0;
  for (const host of targets) {
    const args = ['-a', ...passthrough, host];
    console.error(`enum4linux ${host}`);
    const r = await run('enum4linux', args, { timeoutMs: 5 * 60 * 1000 });
    stream.write(`\n=== ${host} ===\n${r.stdout}\n`);
    if (db && runId !== null) {
      db.insertFinding({
        tool: 'enum4linux', target: host, category: 'smb-enum',
        severity: r.code === 0 ? 'info' : 'low',
        title: `enum4linux ${r.code === 0 ? 'ok' : `exit ${r.code}`}`,
        cve: null, matched_at: host,
        meta: { stdout_head: r.stdout.slice(0, 2000), code: r.code },
      }, now, runId);
      findings++;
    }
  }
  await new Promise<void>((r) => stream.end(() => r()));
  console.error(`done: ${targets.length} hosts. Output: ${outFile}`);
  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: findings, at: new Date().toISOString() });
    db.close();
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
