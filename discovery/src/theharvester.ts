#!/usr/bin/env -S node --loader tsx
// theHarvester: emails + subdomains from ~50 OSINT sources.
// We save the JSON output and pull hosts + emails from it.
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { openDb } from './lib/db.js';

interface Opts { domains: string[]; suffix: string | null; sqlite: string | null; out: string; merge: string | null; sources: string; extraArgs: string[]; help?: boolean }

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { domains: [], suffix: null, sqlite: null, out: 'theharvester.json', merge: null, sources: 'all', extraArgs: [] };
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
    else if (a === '--sources') opts.sources = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else opts.domains.push(a);
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: theharvester <domain>... [options]

Runs theHarvester per domain. Extracts hosts (source='theharvester') into DB.

Options:
  --sources <list>    engines (default: all). e.g. 'crtsh,duckduckgo,hackertarget'
  --suffix <s>        only keep hosts under this suffix
  --sqlite <path>     recon.db
  --merge <path>      merge into hostname file
  -o <path>           JSON output base name (default: theharvester.json)
`);
}

function runHarvest(domain: string, base: string, sources: string, extra: string[]): Promise<void> {
  return new Promise((resolve) => {
    execFile('theHarvester', ['-d', domain, '-b', sources, '-f', base, ...extra], { maxBuffer: 200 * 1024 * 1024, timeout: 30 * 60 * 1000 }, () => resolve());
  });
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.domains.length) { usage(); process.exit(opts.domains.length ? 0 : 1); }
  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('theharvester', { domains: opts.domains, sources: opts.sources }, now) : null;

  const allHosts = new Set<string>();
  for (const d of opts.domains) {
    const perOut = path.resolve(opts.out.replace(/(\.[^.]+)?$/, `-${d.replace(/[^a-z0-9._-]+/gi, '_')}$1`));
    console.error(`theHarvester ${d} → ${perOut}`);
    await runHarvest(d, perOut.replace(/\.json$/, ''), opts.sources, opts.extraArgs);
    const jsonFile = perOut.endsWith('.json') ? perOut : `${perOut}.json`;
    if (fs.existsSync(jsonFile)) {
      try {
        const j = JSON.parse(fs.readFileSync(jsonFile, 'utf8')) as { hosts?: string[]; emails?: string[] };
        for (const h of j.hosts ?? []) {
          const host = h.split(':')[0]!.toLowerCase();
          if (opts.suffix && !host.endsWith(opts.suffix)) continue;
          allHosts.add(host);
        }
        console.error(`  ${(j.hosts ?? []).length} hosts + ${(j.emails ?? []).length} emails from JSON`);
      } catch (e: unknown) { console.error(`  parse error: ${e instanceof Error ? e.message : e}`); }
    }
  }

  if (db && runId !== null) {
    for (const h of allHosts) db.upsertHost(h, 'theharvester', now);
    db.finishRun(runId, { addedHosts: allHosts.size, at: new Date().toISOString() });
    db.close();
  }
  if (opts.merge) {
    const existing = fs.existsSync(opts.merge)
      ? new Set(fs.readFileSync(opts.merge, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean))
      : new Set<string>();
    for (const h of allHosts) existing.add(h);
    fs.writeFileSync(opts.merge, [...existing].sort().join('\n') + '\n');
  }
}

main().catch((err: unknown) => { console.error('FATAL:', err instanceof Error ? err.message : String(err)); process.exit(1); });
