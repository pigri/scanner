#!/usr/bin/env -S node --loader tsx
// rpcclient (samba-common-bin): null-session RPC enum. Runs a canned batch
// of commands per host: enumdomusers, enumdomgroups, querydominfo, srvinfo.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';
import { smbLiveTargets } from './lib/smb-live.js';

const DEFAULT_COMMANDS = ['srvinfo', 'querydominfo', 'enumdomusers', 'enumdomgroups', 'enumalsgroups builtin', 'enumshareall'];

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let liveOnly = false;
  let commands = DEFAULT_COMMANDS;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--live-only') liveOnly = true;
    else if (a === '--commands') commands = nxt().split(';').map((s) => s.trim()).filter(Boolean);
    else passthrough.push(a);
  }
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('rpcclient', `
Runs 'rpcclient -U "" -N -c "<cmd>;<cmd>;..." <host>' per host.

Wrapper flags (before '--'):
  --live-only          filter to hosts with 445/139 in the ports table.
  --commands "<a;b;c>" override the command batch (default: srvinfo;
                       querydominfo; enumdomusers; enumdomgroups;
                       enumalsgroups builtin; enumshareall)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('rpcclient');
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

  const runId = db ? db.startRun('rpcclient', { targets: targets.length, commands }, now) : null;
  const outFile = resolveOutputPath(opts, runId, 'rpcclient.log');
  const stream = fs.createWriteStream(outFile);
  const cmdString = commands.join(';');
  let findings = 0;
  for (const host of targets) {
    const args = ['-U', '', '-N', '-c', cmdString, ...passthrough, host];
    console.error(`rpcclient ${host}`);
    const r = await run('rpcclient', args, { timeoutMs: 3 * 60 * 1000 });
    stream.write(`\n=== ${host} ===\n${r.stdout}\n`);
    if (db && runId !== null) {
      db.insertFinding({
        tool: 'rpcclient', target: host, category: 'null-session',
        severity: r.stdout.includes('user:') || r.stdout.includes('Domain:') ? 'medium' : 'info',
        title: `rpcclient null-session ${r.code === 0 ? 'ok' : `exit ${r.code}`}`,
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
