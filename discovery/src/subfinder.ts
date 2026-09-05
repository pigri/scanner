#!/usr/bin/env -S node --loader tsx
// projectdiscovery/subfinder: fast passive subdomain enum.
// Usage: subfinder <domain> [<domain>...] --sqlite recon.db
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
  help?: boolean;
  extraArgs: string[];
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { domains: [], suffix: null, sqlite: null, out: 'subfinder.txt', merge: null, extraArgs: [] };
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
  console.error(`Usage: subfinder <domain>... [--sqlite recon.db] [options]

Passive subdomain enum via projectdiscovery/subfinder. Writes hosts (source
'subfinder') into recon.db if --sqlite is set.

Options:
  --suffix <s>        only keep hosts under this suffix
  --sqlite <path>     recon.db
  --merge <path>      also merge into this hostname file
  -o, --out <path>    raw hostname list output (default: subfinder.txt)
  --                  everything after passed to subfinder
`);
}

function runSubfinder(domain: string, extra: string[]): Promise<string> {
  return new Promise((resolve) => {
    execFile('subfinder', ['-d', domain, '-silent', ...extra], { maxBuffer: 100 * 1024 * 1024 }, (_err, stdout) => {
      resolve(stdout || '');
    });
  });
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.domains.length) { usage(); process.exit(opts.domains.length ? 0 : 1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('subfinder', { domains: opts.domains, extraArgs: opts.extraArgs }, now) : null;

  const all = new Set<string>();
  for (const d of opts.domains) {
    console.error(`subfinder ${d}`);
    const out = await runSubfinder(d, opts.extraArgs);
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
    for (const h of all) db.upsertHost(h, 'subfinder', now);
    db.finishRun(runId, { addedHosts: all.size, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: +${all.size} hosts, run #${runId}`);
  }

  if (opts.merge) {
    const existing = fs.existsSync(opts.merge)
      ? new Set(fs.readFileSync(opts.merge, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean))
      : new Set<string>();
    const before = existing.size;
    for (const h of all) existing.add(h);
    fs.writeFileSync(opts.merge, [...existing].sort().join('\n') + '\n');
    console.error(`merged into ${opts.merge}: was ${before}, now ${existing.size}`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
