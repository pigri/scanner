#!/usr/bin/env -S node --loader tsx
// Fierce: DNS reconnaissance / zone-transfer probe. Text output — we grep
// hostnames from it.
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { openDb } from './lib/db.js';

interface Opts { domains: string[]; suffix: string | null; sqlite: string | null; out: string; merge: string | null; extraArgs: string[]; help?: boolean }

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { domains: [], suffix: null, sqlite: null, out: 'fierce.log', merge: null, extraArgs: [] };
  let passthrough = false;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (passthrough) { opts.extraArgs.push(a); continue; }
    const next = () => argv[++i]!;
    if (a === '--') passthrough = true;
    else if (a === '--suffix') opts.suffix = next().toLowerCase().replace(/^\./, '');
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '-o' || a === '--out') opts.out = next();
    else if (a === '--merge') opts.merge = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else opts.domains.push(a);
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: fierce <domain>... [options]

Runs 'fierce --domain <d>' per input. Logs raw output; extracts host entries.

Options:
  --suffix <s>     only keep hosts under this suffix
  --sqlite <path>  recon.db (source='fierce')
  --merge <path>   merge into existing hostname file
  -o <path>        raw fierce log output
`);
}

function runFierce(domain: string, extra: string[]): Promise<string> {
  return new Promise((resolve) => {
    execFile('fierce', ['--domain', domain, ...extra], { maxBuffer: 100 * 1024 * 1024, timeout: 20 * 60 * 1000 }, (_err, stdout, stderr) => {
      resolve((stdout || '') + (stderr || ''));
    });
  });
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.domains.length) { usage(); process.exit(opts.domains.length ? 0 : 1); }
  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('fierce', { domains: opts.domains }, now) : null;

  const all = new Set<string>();
  const log = fs.createWriteStream(path.resolve(opts.out));
  for (const d of opts.domains) {
    console.error(`fierce ${d}`);
    const out = await runFierce(d, opts.extraArgs);
    log.write(`\n=== ${d} ===\n${out}\n`);
    for (const m of out.matchAll(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi)) {
      const host = m[1]!.toLowerCase();
      if (opts.suffix && !host.endsWith(opts.suffix)) continue;
      all.add(host);
    }
    console.error(`  → ${all.size} unique so far`);
  }
  await new Promise<void>((r) => log.end(() => r()));

  if (db && runId !== null) {
    for (const h of all) db.upsertHost(h, 'fierce', now);
    db.finishRun(runId, { addedHosts: all.size, at: new Date().toISOString() });
    db.close();
  }
  if (opts.merge) {
    const existing = fs.existsSync(opts.merge)
      ? new Set(fs.readFileSync(opts.merge, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean))
      : new Set<string>();
    for (const h of all) existing.add(h);
    fs.writeFileSync(opts.merge, [...existing].sort().join('\n') + '\n');
  }
}

main().catch((err: unknown) => { console.error('FATAL:', err instanceof Error ? err.message : String(err)); process.exit(1); });
