#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import { expandCidr, cidrSize, extractHostsFromResults, type PtrResult } from './lib/ptr.js';
import { openDb } from './lib/db.js';

interface Opts {
  prefixesFile: string;
  out: string;
  merge: string | null;
  suffix: string | null;
  concurrency: number;
  timeoutMs: number;
  resolvers: string[] | null;
  progressEvery: number;
  sqlite: string | null;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    prefixesFile: '',
    out: 'ptr-hosts.txt',
    merge: null,
    suffix: null,
    concurrency: 100,
    timeoutMs: 4000,
    resolvers: null,
    progressEvery: 5000,
    sqlite: null,
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '-o' || a === '--out') opts.out = next();
    else if (a === '--merge') opts.merge = next();
    else if (a === '--suffix') opts.suffix = next().toLowerCase().replace(/^\./, '');
    else if (a === '--concurrency') opts.concurrency = parseInt(next(), 10);
    else if (a === '--timeout-ms') opts.timeoutMs = parseInt(next(), 10);
    else if (a === '--resolvers') opts.resolvers = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--progress-every') opts.progressEvery = parseInt(next(), 10);
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  opts.prefixesFile = rest[0] ?? '';
  return opts;
}

function usage(): void {
  console.error(`Usage: ptr-sweep <prefixes.txt> [options]

Reverse-DNS every IPv4 in the given CIDR list, filter by suffix,
emit unique hostnames. Discovers deeply nested subdomains that no
search engine or CT log surfaces.

Options:
  -o, --out <path>       Output file (default: ptr-hosts.txt)
  --merge <path>         Also merge into this existing hostname file
  --suffix <domain>      Only keep hosts under this suffix (e.g. gov.hu)
  --concurrency <N>      Parallel lookups (default: 100)
  --timeout-ms <N>       Per-lookup timeout (default: 4000)
  --resolvers <a,b,c>    Override system resolvers
  --progress-every <N>   Log progress every N lookups (default: 5000)
`);
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([p, new Promise<null>((res) => setTimeout(() => res(null), ms))]);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.prefixesFile) {
    usage();
    process.exit(opts.prefixesFile ? 0 : 1);
  }

  const resolver = new dns.Resolver();
  if (opts.resolvers && opts.resolvers.length) resolver.setServers(opts.resolvers);

  const cidrs = fs
    .readFileSync(opts.prefixesFile, 'utf8')
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith('#') && !s.includes(':'));

  const total = cidrs.reduce((a, c) => a + cidrSize(c), 0);
  console.error(`sweeping ${cidrs.length} CIDR(s) = ${total} IPs (concurrency ${opts.concurrency})`);

  const results: PtrResult[] = [];
  let done = 0;
  let hits = 0;
  const start = Date.now();
  const outFile = path.resolve(opts.out);

  const workers = new Array(opts.concurrency).fill(0);
  const iterator = (function* () {
    for (const c of cidrs) yield* expandCidr(c);
  })();

  async function worker(): Promise<void> {
    while (true) {
      const next = iterator.next();
      if (next.done) return;
      const ip = next.value;
      const rev = await withTimeout(resolver.reverse(ip), opts.timeoutMs).catch(() => null);
      if (rev && rev.length) {
        for (const name of rev) results.push({ ip, ptr: name });
        hits++;
      }
      done++;
      if (done % opts.progressEvery === 0) {
        const rate = (done / ((Date.now() - start) / 1000)).toFixed(0);
        process.stderr.write(`\r${done}/${total} · ${hits} hits · ${rate} IPs/s`);
      }
    }
  }

  await Promise.all(workers.map(() => worker()));
  process.stderr.write('\n');

  const hosts = extractHostsFromResults(results, opts.suffix);
  fs.writeFileSync(outFile, hosts.sort().join('\n') + '\n');

  if (opts.sqlite && (hosts.length || results.length)) {
    const db = openDb(opts.sqlite);
    const now = new Date().toISOString();
    const runId = db.startRun('ptr-sweep', { prefixesFile: opts.prefixesFile, suffix: opts.suffix }, now);
    for (const r of results) if (r.ptr) db.addPtr(r.ip, r.ptr, now);
    for (const h of hosts) db.upsertHost(h, 'ptr', now);
    db.finishRun(runId, { addedHosts: hosts.length, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite)} (+${hosts.length} hosts, ${results.length} PTR records)`);
  }
  const elapsed = ((Date.now() - start) / 1000).toFixed(0);
  console.error(`\ndone in ${elapsed}s`);
  console.error(`  ${done} IPs · ${hits} with PTRs · ${hosts.length} unique hostnames matching suffix`);
  console.error(`  hosts: ${outFile}`);

  if (opts.merge) {
    const mergePath = path.resolve(opts.merge);
    const existing = new Set(
      fs.existsSync(mergePath)
        ? fs.readFileSync(mergePath, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
        : []
    );
    const before = existing.size;
    for (const h of hosts) existing.add(h);
    fs.writeFileSync(mergePath, [...existing].sort().join('\n') + '\n');
    console.error(`  merged into ${mergePath}: was ${before}, now ${existing.size} (+${existing.size - before})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
