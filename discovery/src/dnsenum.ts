#!/usr/bin/env -S node --loader tsx
// dnsenum: zone transfer + bruteforce + reverse. XML output via -o.
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { openDb } from './lib/db.js';

interface Opts { domains: string[]; suffix: string | null; sqlite: string | null; out: string; merge: string | null; extraArgs: string[]; help?: boolean }

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { domains: [], suffix: null, sqlite: null, out: 'dnsenum.xml', merge: null, extraArgs: [] };
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
  console.error(`Usage: dnsenum <domain>... [options]

Runs 'dnsenum --enum -o out.xml <domain>' per input. Zone transfer + brute.

Options:
  --suffix <s>     only keep hosts under this suffix
  --sqlite <path>  recon.db (source='dnsenum')
  --merge <path>   merge into hostname file
  -o <path>        XML output (default: dnsenum.xml)
`);
}

function runDnsenum(domain: string, xmlOut: string, extra: string[]): Promise<string> {
  return new Promise((resolve) => {
    execFile('dnsenum', ['--enum', '-o', xmlOut, ...extra, domain], { maxBuffer: 200 * 1024 * 1024, timeout: 30 * 60 * 1000 }, (_err, stdout, stderr) => {
      resolve((stdout || '') + (stderr || ''));
    });
  });
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.domains.length) { usage(); process.exit(opts.domains.length ? 0 : 1); }
  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('dnsenum', { domains: opts.domains }, now) : null;

  const all = new Set<string>();
  for (const d of opts.domains) {
    const perOut = path.resolve(opts.out.replace(/(\.[^.]+)?$/, `-${d.replace(/[^a-z0-9._-]+/gi, '_')}$1`));
    console.error(`dnsenum ${d} → ${perOut}`);
    const stdout = await runDnsenum(d, perOut, opts.extraArgs);
    // Extract A records from stdout — dnsenum prints "hostname     IN      A       ip"
    for (const m of stdout.matchAll(/([a-z0-9._-]+)\s+\d+\s+IN\s+A\s+[\d.]+/gi)) {
      const host = m[1]!.toLowerCase().replace(/\.$/, '');
      if (opts.suffix && !host.endsWith(opts.suffix)) continue;
      all.add(host);
    }
    console.error(`  → ${all.size} unique so far`);
  }

  if (db && runId !== null) {
    for (const h of all) db.upsertHost(h, 'dnsenum', now);
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
