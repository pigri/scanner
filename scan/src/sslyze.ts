#!/usr/bin/env -S node --loader tsx
// sslyze — modern TLS audit. Complements testssl: catches ROBOT/CCS/Heartbleed
// as typed findings, verifies certificate chain-order and SCT count, flags
// SSLv3/TLS 1.0/1.1 protocol support, and audits session-renegotiation +
// TLS-extended-master-secret which testssl only partially covers.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';
import { ingestAndFinishRun } from './lib/sslyze-ingest.js';

// Live-HTTPS targets from either http_probes (https://) or a 443/tcp port.
function loadHttpsTargets(db: Db, targets: readonly string[]): string[] {
  if (!targets.length) return [];
  const p = targets.map(() => '?').join(',');
  const httpsRows = db.raw.prepare(
    `SELECT DISTINCT target FROM http_probes
     WHERE target IN (${p}) AND url LIKE 'https://%'`
  ).all(...targets) as { target: string }[];
  const portRows = db.raw.prepare(
    `SELECT DISTINCT target FROM ports WHERE target IN (${p}) AND port = 443`
  ).all(...targets) as { target: string }[];
  const set = new Set<string>();
  for (const r of httpsRows) set.add(r.target);
  for (const r of portRows) set.add(r.target);
  return [...set];
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let liveOnly = true;
  let slow = false;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    if (a === '--no-live-only') liveOnly = false;
    else if (a === '--slow') slow = true;
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('sslyze', `
sslyze — modern TLS audit per HTTPS target. Emits findings for known-vuln
positives (Heartbleed / ROBOT / CCS / CRIME), deprecated-protocol support
(SSLv2/3, TLS 1.0/1.1), and certificate-chain quality (SHA-1, Symantec
anchor, SCT count, chain order, OCSP must-staple).

Defaults: --certinfo --heartbleed --openssl_ccs --robot --fallback
          --compression --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 --sslv3
          --reneg --resum --ems. Runs one process across all targets in
          parallel via --targets_in.

Wrapper flags (before '--'):
  --slow                 pass --slow_connection (fewer parallel conns)
  --no-live-only         include hosts httpx never saw alive (or with 443 open)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('sslyze');
  if (!opts.sqlite) { console.error('sslyze: --sqlite is required'); process.exit(1); }

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = openDb(opts.sqlite);
  const runId = db.startRun('sslyze', { targets: targets.length, liveOnly, slow }, now);

  let scanTargets: string[];
  if (liveOnly) {
    scanTargets = loadHttpsTargets(db, targets);
    console.error(`live-only filter: ${targets.length} → ${scanTargets.length}`);
  } else {
    scanTargets = [...targets];
  }
  if (!scanTargets.length) {
    console.error('no HTTPS targets to scan');
    db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
    db.close();
    return;
  }

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'sslyze-targets.txt');
  fs.writeFileSync(tmp, scanTargets.join('\n') + '\n');
  const outFile = resolveOutputPath(opts, runId, 'sslyze.json');

  const args = [
    '--targets_in', tmp,
    '--json_out', outFile,
    '--quiet',
    '--certinfo', '--heartbleed', '--openssl_ccs', '--robot', '--fallback',
    '--compression', '--reneg', '--resum', '--ems',
    '--sslv3', '--tlsv1', '--tlsv1_1', '--tlsv1_2', '--tlsv1_3',
    ...(slow ? ['--slow_connection'] : []),
    ...passthrough,
  ];
  console.error(`sslyze ${args.slice(0, 6).join(' ')} ... (${scanTargets.length} target(s))`);
  const r = await run('sslyze', args, { timeoutMs: Math.max(60 * scanTargets.length, 600) * 1000 });
  console.error(`sslyze exited ${r.code}`);
  if (r.code !== 0 && r.stderr) console.error(r.stderr.slice(0, 500));

  if (!fs.existsSync(outFile)) {
    db.finishRun(runId, { targetsCount: scanTargets.length, findingsCount: 0, at: new Date().toISOString() });
    db.close();
    return;
  }

  const ingested = ingestAndFinishRun(db, fs.readFileSync(outFile, 'utf8'), now, runId, scanTargets.length);
  if (!ingested) return;
  const { rows, findings, certs } = ingested;
  console.error(`sslyze done: +${findings} finding(s), +${certs} cert(s) across ${rows} scanned host(s), run #${runId}`);
  console.error(`  sqlite: ${path.resolve(opts.sqlite)}`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
