#!/usr/bin/env -S node --loader tsx
// SMBMap: null-session share enumeration, JSON output.
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
    console.error(commonUsage('smbmap', `
Runs smbmap -H <host> per in-scope host, null session by default.

Wrapper flags (before '--'):
  --live-only     filter to hosts with 445/139 in the ports table.

Common passthrough:
  -- -u <user> -p <pass>     credentialed enum
  -- --admin                 test admin access
  -- --shares                enum shares only`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('smbmap');
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

  const runId = db ? db.startRun('smbmap', { targets: targets.length }, now) : null;
  const outFile = resolveOutputPath(opts, runId, 'smbmap.log');
  const stream = fs.createWriteStream(outFile);
  let findings = 0;
  for (const host of targets) {
    const args = ['-H', host, ...passthrough];
    console.error(`smbmap -H ${host}`);
    const r = await run('smbmap', args, { timeoutMs: 3 * 60 * 1000 });
    stream.write(`\n=== ${host} ===\n${r.stdout}\n`);
    if (db && runId !== null) {
      db.insertFinding({
        tool: 'smbmap', target: host, category: 'smb-shares',
        severity: /READ, WRITE|WRITE ONLY|Anonymous logon/i.test(r.stdout) ? 'high' : 'info',
        title: `smbmap ${host}`,
        cve: null, matched_at: host,
        meta: { stdout: r.stdout.slice(0, 4000), code: r.code },
      }, now, runId);
      findings++;
    }
  }
  await new Promise<void>((r) => stream.end(() => r()));
  console.error(`done. Output: ${outFile}`);
  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: findings, at: new Date().toISOString() });
    db.close();
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
