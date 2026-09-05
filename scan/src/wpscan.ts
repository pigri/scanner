#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('wpscan', `
Runs wpscan --url <target> for each in-scope host, one at a time.
Adds --format json --random-user-agent --disable-tls-checks by default.
Reads WPSCAN_API_TOKEN env var for CVE lookups (optional but recommended).
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
  const token = process.env['WPSCAN_API_TOKEN'];
  const wstream = fs.createWriteStream(outFile);
  let ok = 0, fail = 0, findings = 0;
  for (const target of targets) {
    const url = target.startsWith('http') ? target : `https://${target}`;
    const args = ['--url', url, '--format', 'json', '--random-user-agent', '--disable-tls-checks', ...opts.extraArgs];
    if (token) args.push('--api-token', token);
    console.error(`wpscan ${url}`);
    const r = await run('wpscan', args, { timeoutMs: 300_000 });
    if (r.stdout.trim()) {
      const line = r.stdout.trim().split('\n').filter(Boolean).slice(-1)[0] ?? '';
      try {
        const parsed = JSON.parse(line) as {
          interesting_findings?: { to_s?: string; type?: string; url?: string; references?: unknown }[];
          version?: { number?: string; vulnerabilities?: { title?: string; references?: { cve?: string[] } }[] };
          plugins?: Record<string, { version?: { number?: string }; vulnerabilities?: { title?: string; references?: { cve?: string[] } }[] }>;
        };
        wstream.write(JSON.stringify({ target: url, wpscan: parsed }) + '\n');
        ok++;
        if (db) {
          const emit = (title: string, severity: string | null, category: string, cve: string | null, meta: unknown) => {
            db.insertFinding({ tool: 'wpscan', target: url, category, severity, title, cve, matched_at: url, meta }, now, runId);
            findings++;
          };
          for (const f of parsed.interesting_findings ?? []) emit(f.to_s ?? 'interesting finding', 'info', f.type ?? 'interesting', null, f);
          for (const v of parsed.version?.vulnerabilities ?? []) emit(v.title ?? 'core vuln', 'high', 'core-vulnerability', v.references?.cve?.[0] ?? null, v);
          for (const [name, p] of Object.entries(parsed.plugins ?? {})) {
            for (const v of p.vulnerabilities ?? []) emit(`${name}: ${v.title ?? 'plugin vuln'}`, 'high', 'plugin-vulnerability', v.references?.cve?.[0] ?? null, v);
          }
        }
      } catch {
        wstream.write(JSON.stringify({ target: url, error: 'non-json output', raw: r.stdout.slice(0, 500) }) + '\n');
        fail++;
      }
    } else {
      wstream.write(JSON.stringify({ target: url, error: r.stderr.slice(0, 300) || 'no output', code: r.code }) + '\n');
      fail++;
    }
  }
  await new Promise<void>((r) => wstream.end(() => r()));
  console.error(`wpscan done: ${ok} ok, ${fail} failed. Output: ${outFile}`);
  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: findings, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${findings} findings, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
