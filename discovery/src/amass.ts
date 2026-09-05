#!/usr/bin/env -S node --loader tsx
// OWASP Amass: passive+active subdomain enum. -passive is default here; add
// -- -active -brute for the full-fat version.
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { openDb } from './lib/db.js';

interface Opts {
  domains: string[];
  suffix: string | null;
  sqlite: string | null;
  out: string;
  merge: string | null;
  timeoutMin: number;
  help?: boolean;
  extraArgs: string[];
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { domains: [], suffix: null, sqlite: null, out: 'amass.txt', merge: null, timeoutMin: 15, extraArgs: [] };
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
    else if (a === '--timeout-min') opts.timeoutMin = parseInt(next(), 10);
    else if (a === '-h' || a === '--help') opts.help = true;
    else opts.domains.push(a);
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: amass <domain>... [options]

Runs 'amass enum -passive -d <domain>' per input.

Options:
  --suffix <s>         only keep hosts under this suffix
  --sqlite <path>      recon.db
  --merge <path>       also merge into this hostname file
  --timeout-min <N>    kill amass after N minutes (default: 15)
  -o, --out <path>     raw hostname list output
  --                   passed to amass (e.g. '-- -active -brute -min-for-recursive 2')
`);
}

function runAmass(domain: string, extra: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    const args = ['enum', '-passive', '-d', domain, '-silent', ...extra];
    execFile('amass', args, { maxBuffer: 100 * 1024 * 1024, timeout: timeoutMs }, (_err, stdout) => {
      resolve(stdout || '');
    });
  });
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.domains.length) { usage(); process.exit(opts.domains.length ? 0 : 1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('amass', { domains: opts.domains, extraArgs: opts.extraArgs }, now) : null;

  const all = new Set<string>();
  for (const d of opts.domains) {
    console.error(`amass ${d} (timeout ${opts.timeoutMin}m)`);
    const out = await runAmass(d, opts.extraArgs, opts.timeoutMin * 60 * 1000);
    for (const line of out.split('\n')) {
      const host = line.trim().toLowerCase();
      if (!host) continue;
      if (opts.suffix && !host.endsWith(opts.suffix)) continue;
      all.add(host);
    }
    console.error(`  → ${all.size} unique so far`);
  }

  fs.writeFileSync(path.resolve(opts.out), [...all].sort().join('\n') + '\n');
  console.error(`wrote ${all.size} hosts to ${path.resolve(opts.out)}`);

  if (db && runId !== null) {
    for (const h of all) db.upsertHost(h, 'amass', now);
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

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
