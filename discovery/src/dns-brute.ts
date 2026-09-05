#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { openDb } from './lib/db.js';
import { digShort } from './lib/dns.js';
import { wildcardProbeHosts, classifyWildcard } from './lib/wildcard.js';

const SECLISTS = {
  'top-5000': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
  'top-20000': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt',
  'top-110000': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt',
  'bitquark-100k': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt',
};

interface Opts {
  parentsFile: string;
  wordlist: string;
  seclist: keyof typeof SECLISTS | null;
  out: string;
  merge: string | null;
  resolver: string;
  concurrency: number;
  timeoutMs: number;
  detectWildcard: boolean;
  progressEvery: number;
  sqlite: string | null;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    parentsFile: '',
    wordlist: '',
    seclist: null,
    out: 'brute-hosts.txt',
    merge: null,
    resolver: '1.1.1.1',
    concurrency: 100,
    timeoutMs: 3000,
    detectWildcard: true,
    progressEvery: 5000,
    sqlite: null,
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--parents') opts.parentsFile = next();
    else if (a === '--wordlist') opts.wordlist = next();
    else if (a === '--seclist') opts.seclist = next() as keyof typeof SECLISTS;
    else if (a === '-o' || a === '--out') opts.out = next();
    else if (a === '--merge') opts.merge = next();
    else if (a === '--resolver') opts.resolver = next();
    else if (a === '--concurrency') opts.concurrency = parseInt(next(), 10);
    else if (a === '--timeout-ms') opts.timeoutMs = parseInt(next(), 10);
    else if (a === '--no-wildcard') opts.detectWildcard = false;
    else if (a === '--progress-every') opts.progressEvery = parseInt(next(), 10);
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: dns-brute --parents <file> --wordlist <file> [options]

For each parent P and word W, query 'W.P' via dig @<resolver> and keep hits.
Detects wildcards (with --no-wildcard to skip) and records the wildcard IP so
matches against it are excluded.

Options:
  --parents <file>     Parent domains, one per line
  --wordlist <file>    Local word list path
  --seclist <name>     Auto-fetch SecLists wordlist by name; caches to ./wordlists/
                       Options: top-5000, top-20000, top-110000, bitquark-100k
  --resolver <ip>      DNS resolver (default: 1.1.1.1)
  --concurrency <N>    Parallel dig processes (default: 100)
  --timeout-ms <N>     Per-query timeout (default: 3000)
  --no-wildcard        Skip wildcard detection
  --progress-every <N> Log every N queries (default: 5000)
  -o, --out <path>     Output file (default: brute-hosts.txt)
  --merge <path>       Also merge into this existing hostname file
`);
}

async function ensureSeclist(name: keyof typeof SECLISTS): Promise<string> {
  const url = SECLISTS[name];
  const dir = path.resolve('wordlists');
  const file = path.join(dir, `${name}.txt`);
  if (fs.existsSync(file) && fs.statSync(file).size > 0) return file;
  fs.mkdirSync(dir, { recursive: true });
  console.error(`fetching SecLists ${name} from ${url}...`);
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok || !res.body) throw new Error(`seclist download failed: ${res.status}`);
  await pipeline(Readable.fromWeb(res.body as any), fs.createWriteStream(file));
  const stat = fs.statSync(file);
  console.error(`saved ${file} (${stat.size} bytes)`);
  return file;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.parentsFile || (!opts.wordlist && !opts.seclist)) {
    usage();
    process.exit(opts.parentsFile && (opts.wordlist || opts.seclist) ? 0 : 1);
  }
  if (opts.seclist && !opts.wordlist) {
    opts.wordlist = await ensureSeclist(opts.seclist);
  }
  const parents = fs
    .readFileSync(opts.parentsFile, 'utf8')
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith('#'));
  const words = fs
    .readFileSync(opts.wordlist, 'utf8')
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith('#'));

  console.error(`${parents.length} parents · ${words.length} words = ${parents.length * words.length} queries`);
  console.error(`resolver ${opts.resolver}, concurrency ${opts.concurrency}`);

  const wildcards = new Map<string, Set<string>>();
  if (opts.detectWildcard) {
    console.error('detecting wildcards...');
    for (const p of parents) {
      const answers = await Promise.all(
        wildcardProbeHosts(p).map((h) => digShort(h, opts.resolver, 3))
      );
      const v = classifyWildcard(p, answers);
      if (v.wildcard) {
        wildcards.set(p, new Set(v.ips));
        console.error(`  WILDCARD ${p} -> ${v.ips.join(', ')}`);
      }
    }
  }

  const candidates: string[] = [];
  for (const p of parents) {
    for (const w of words) candidates.push(`${w}.${p}`);
  }

  const outFile = path.resolve(opts.out);
  const hits = new Set<string>();
  let done = 0;
  const start = Date.now();
  const timeoutSec = Math.max(1, Math.round(opts.timeoutMs / 1000));

  const iterator = candidates[Symbol.iterator]();
  async function worker(): Promise<void> {
    while (true) {
      const next = iterator.next();
      if (next.done) return;
      const host = next.value;
      const parent = parents.find((p) => host.endsWith(`.${p}`)) ?? '';
      const wildcardIps = wildcards.get(parent);
      const answer = await digShort(host, opts.resolver, timeoutSec);
      if (answer.length) {
        const ips = answer.filter((s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s));
        const differs = ips.some((ip) => !wildcardIps || !wildcardIps.has(ip));
        if (differs && ips.length) hits.add(host);
      }
      done++;
      if (done % opts.progressEvery === 0) {
        const rate = (done / ((Date.now() - start) / 1000)).toFixed(0);
        process.stderr.write(`\r${done}/${candidates.length} · ${hits.size} hits · ${rate} q/s`);
      }
    }
  }
  await Promise.all(Array.from({ length: opts.concurrency }, () => worker()));
  process.stderr.write('\n');

  const sorted = [...hits].sort();
  fs.writeFileSync(outFile, sorted.join('\n') + '\n');
  const elapsed = ((Date.now() - start) / 1000).toFixed(0);
  console.error(`\ndone in ${elapsed}s`);
  console.error(`  ${done} queries · ${hits.size} unique hits`);
  console.error(`  hosts: ${outFile}`);

  if (opts.sqlite && sorted.length) {
    const db = openDb(opts.sqlite);
    const now = new Date().toISOString();
    const runId = db.startRun('dns-brute', { seclist: opts.seclist, wordlist: opts.wordlist, resolver: opts.resolver }, now);
    for (const h of sorted) db.upsertHost(h, 'brute', now);
    db.finishRun(runId, { addedHosts: sorted.length, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite)} (+${sorted.length} hosts)`);
  }

  if (opts.merge) {
    const mergePath = path.resolve(opts.merge);
    const existing = new Set(
      fs.existsSync(mergePath)
        ? fs.readFileSync(mergePath, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
        : []
    );
    const before = existing.size;
    for (const h of sorted) existing.add(h);
    fs.writeFileSync(mergePath, [...existing].sort().join('\n') + '\n');
    console.error(`  merged into ${mergePath}: was ${before}, now ${existing.size} (+${existing.size - before})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
