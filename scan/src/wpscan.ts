#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';
import { parseWpscanStdout, wpscanRows, type WpscanParsed } from './lib/wpscan-parse.js';
import { finishWithWhy, partialReasons, rowsAtRisk, wpscanFailed } from './lib/run-partial.js';
import { wpscanEnv } from './lib/wpscan-env.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('wpscan', `
Runs wpscan --url <target> for each in-scope host, one at a time.
Adds --format json --random-user-agent --disable-tls-checks by default.
Reads WPSCAN_API_TOKEN env var for CVE lookups (optional). Unset or empty
means no vuln API: wpscan still enumerates, without vulnerability data.
Pass --enumerate flags after '--'. Output: JSONL to --out (default: wpscan.jsonl).`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('wpscan');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }
  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('wpscan', { targets: targets.length, extraArgs: opts.extraArgs }, now) : null;
  const outFile = resolveOutputPath(opts, runId, 'wpscan.jsonl');
  const env = wpscanEnv(process.env);
  const token = env['WPSCAN_API_TOKEN'];
  const wstream = fs.createWriteStream(outFile);
  let ok = 0, aborted = 0, fail = 0, findings = 0, incomplete = 0;
  for (const target of targets) {
    const url = target.startsWith('http') ? target : `https://${target}`;
    const args = ['--url', url, '--format', 'json', '--random-user-agent', '--disable-tls-checks', ...opts.extraArgs];
    if (token) args.push('--api-token', token);
    console.error(`wpscan ${url}`);
    const r = await run('wpscan', args, { timeoutMs: 300_000, env });
    const rowsBefore = findings;
    if (r.stdout.trim()) {
      try {
        const parsed = parseWpscanStdout(r.stdout) as WpscanParsed;
        wstream.write(JSON.stringify({ target: url, wpscan: parsed }) + '\n');
        const abort = (parsed as { scan_aborted?: unknown }).scan_aborted;
        if (abort !== undefined && !/not seem to be running WordPress/i.test(String(abort))) aborted++; else ok++;
        if (db) {
          for (const row of wpscanRows(parsed)) {
            db.insertFinding({ tool: 'wpscan', target: url, ...row, matched_at: row.matched_at ?? url }, now, runId);
            findings++;
          }
        }
        if (rowsAtRisk(findings - rowsBefore, wpscanFailed(r.code, parsed))) incomplete++;
      } catch {
        if (rowsAtRisk(findings - rowsBefore, true)) incomplete++;
        wstream.write(JSON.stringify({ target: url, error: 'non-json output', raw: r.stdout.slice(0, 500) }) + '\n');
        fail++;
      }
    } else {
      wstream.write(JSON.stringify({ target: url, error: r.stderr.slice(0, 300) || 'no output', code: r.code }) + '\n');
      fail++;
    }
  }
  await new Promise<void>((r) => wstream.end(() => r()));
  console.error(`wpscan done: ${ok} ok, ${aborted} aborted, ${fail} failed. Output: ${outFile}`);
  if (db && runId !== null) {
    finishWithWhy(db, runId, { targetsCount: targets.length, findingsCount: findings, at: new Date().toISOString() }, partialReasons([[incomplete, 'target(s) incomplete']]));
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${findings} findings, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
