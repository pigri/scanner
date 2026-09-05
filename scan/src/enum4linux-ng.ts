#!/usr/bin/env -S node --loader tsx
// enum4linux-ng: Python rewrite of enum4linux with -oJ JSON output.
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
    console.error(commonUsage('enum4linux-ng', `
Runs enum4linux-ng -A -oJ per in-scope host with JSON output. Requires 445 open.

Wrapper flags (before '--'):
  --live-only     filter to hosts with 445/139 in the ports table.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  const bin = await requireTool('enum4linux-ng');
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

  const runId = db ? db.startRun('enum4linux-ng', { targets: targets.length }, now) : null;
  let findings = 0;
  for (const host of targets) {
    const perHost = resolveOutputPath(
      { ...opts, outFile: null },
      runId,
      `enum4linux-ng-${host.replace(/[^a-z0-9._-]+/gi, '_')}.json`
    );
    const args = ['-A', '-oJ', perHost.replace(/\.json$/, ''), ...passthrough, host];
    console.error(`enum4linux-ng ${host}`);
    const r = await run(bin, args, { timeoutMs: 5 * 60 * 1000 });
    if (db && runId !== null) {
      let parsed: unknown = null;
      if (fs.existsSync(perHost)) {
        try { parsed = JSON.parse(fs.readFileSync(perHost, 'utf8')); } catch { /* leave null */ }
      }
      db.insertFinding({
        tool: 'enum4linux-ng', target: host, category: 'smb-enum',
        severity: 'info',
        title: `enum4linux-ng ${r.code === 0 ? 'ok' : `exit ${r.code}`}`,
        cve: null, matched_at: host,
        meta: parsed ?? { stdout_head: r.stdout.slice(0, 2000), code: r.code },
      }, now, runId);
      findings++;
    }
  }
  console.error(`done: ${targets.length} hosts.`);
  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: findings, at: new Date().toISOString() });
    db.close();
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
