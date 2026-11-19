#!/usr/bin/env -S node --loader tsx
// checkdmarc: batch DNS-level email-security audit (SPF, DMARC, MTA-STS,
// DNSSEC, BIMI, SMTP-TLS-Reporting). Emits findings for missing / weak /
// invalid records — direct phishing-enablement signal for the estate.
//
// Slow-ish: MX SMTP probes tack ~7-8s per domain. Runs with --skip-tls
// by default because we've got other tools (testssl) for TLS auditing and
// the timeouts pile up per batch.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';
import { ingestCheckdmarcRows, type CheckdmarcResult } from './lib/checkdmarc-ingest.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let skipTls = true;             // TLS probes to MX add ~8s per host; testssl covers TLS separately
  let timeout = 5;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--tls') skipTls = false;
    else if (a === '--timeout') timeout = parseInt(nxt(), 10);
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('checkdmarc', `
checkdmarc — validate SPF / DMARC / MTA-STS / DNSSEC / BIMI /
SMTP-TLS-Reporting per FQDN. Findings emitted per weak/missing record.

Default profile: --skip-tls --timeout 5. Runs all targets in one invocation
(checkdmarc parallelizes internally). --skip-tls kills the ~8s/host MX SMTP
TLS probe — testssl already audits TLS separately.

Wrapper flags (before '--'):
  --tls              re-enable MX SMTP TLS probe (slow; default is --skip-tls)
  --timeout <sec>    per-DNS-query timeout (default: 5)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('checkdmarc');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('checkdmarc', { targets: targets.length, skipTls }, now) : null;

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'checkdmarc-targets.txt');
  fs.writeFileSync(tmp, targets.join('\n') + '\n');
  const outFile = resolveOutputPath(opts, runId, 'checkdmarc.json');

  const args = [
    tmp,                    // domain positional (accepts file path)
    '-f', 'json',
    '-o', outFile,
    '-t', String(timeout),
    ...(skipTls ? ['--skip-tls'] : []),
    ...passthrough,
  ];
  console.error(`checkdmarc ${args.join(' ')}`);
  const r = await run('checkdmarc', args, { timeoutMs: Math.max(30 * targets.length, 300) * 1000 });
  console.error(`checkdmarc exited ${r.code}, output: ${outFile}`);
  if (r.code !== 0 && r.stderr) console.error(r.stderr.slice(0, 500));

  if (!db || runId === null || !fs.existsSync(outFile)) return;

  const parsed = JSON.parse(fs.readFileSync(outFile, 'utf8')) as CheckdmarcResult | CheckdmarcResult[];
  const rows: CheckdmarcResult[] = Array.isArray(parsed) ? parsed : [parsed];
  const { findings } = await ingestCheckdmarcRows(db, rows, now, runId, undefined, r.code);
  db.close();
  console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${findings} findings across ${rows.length} domains, run #${runId})`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
