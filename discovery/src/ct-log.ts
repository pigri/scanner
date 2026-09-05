#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { extractCtHosts, extractCertspotterHosts } from './lib/ct.js';
import { makeDomainFilter } from './lib/ddg.js';
import { openDb } from './lib/db.js';

type Source = 'crtsh' | 'certspotter' | 'both';

interface Opts {
  patterns: string[];
  out: string;
  suffix: string | null;
  exclude: string[];
  merge: string | null;
  timeoutMs: number;
  source: Source;
  sqlite: string | null;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    patterns: [],
    out: 'ct-hosts.txt',
    suffix: null,
    exclude: [],
    merge: null,
    timeoutMs: 60000,
    source: 'both',
    sqlite: null,
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '-o' || a === '--out') opts.out = next();
    else if (a === '--suffix') opts.suffix = next().toLowerCase().replace(/^\./, '');
    else if (a === '--exclude') opts.exclude = next().split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    else if (a === '--merge') opts.merge = next();
    else if (a === '--timeout-ms') opts.timeoutMs = parseInt(next(), 10);
    else if (a === '--source') opts.source = next() as Source;
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  opts.patterns = rest;
  return opts;
}

function usage(): void {
  console.error(`Usage: ct-log <pattern...> [options]

Query crt.sh certificate transparency logs for one or more domain patterns
and emit a deduplicated hostname list. Use '%' as a wildcard in patterns
(SQL LIKE style), e.g. '%.dtr.gov.hu' or '%.gov.hu'.

Options:
  -o, --out <path>       Output file, one host per line (default: ct-hosts.txt)
  --suffix <domain>      Only keep hosts ending in this suffix (e.g. gov.hu)
  --exclude <a,b,c>      Skip these apex domains + their subdomains
  --merge <path>         Merge into this existing hostname file (dedupe union)
  --timeout-ms <N>       Per-request timeout (default: 60000; crt.sh can be slow)
  --source <src>         crtsh | certspotter | both (default: both — union)
  --sqlite <path>        Also write hosts + source tags to this SQLite DB

Examples:
  ct-log '%.dtr.gov.hu' -o dtr-hosts.txt
  ct-log '%.gov.hu' --exclude nki.gov.hu,nbsz.gov.hu --merge domains.txt
`);
}

async function queryCrtSh(pattern: string, timeoutMs: number): Promise<string[]> {
  const url = `https://crt.sh/?q=${encodeURIComponent(pattern)}&output=json`;
  const res = await fetch(url, {
    headers: { 'User-Agent': 'discovery/ct-log', Accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`crt.sh returned HTTP ${res.status}`);
  const text = await res.text();
  if (!text.trim()) return [];
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`crt.sh returned non-JSON (${text.length}b, likely HTML error page)`);
  }
  return extractCtHosts(json);
}

function patternToDomain(pattern: string): string {
  // '%.dtr.gov.hu' or '*.dtr.gov.hu' -> 'dtr.gov.hu'
  return pattern.replace(/^[%*]\./, '').replace(/^%/, '').trim();
}

async function queryCertspotter(pattern: string, timeoutMs: number): Promise<string[]> {
  const domain = patternToDomain(pattern);
  const url =
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
    `&include_subdomains=true&expand=dns_names`;
  const res = await fetch(url, {
    headers: { 'User-Agent': 'discovery/ct-log', Accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`certspotter returned HTTP ${res.status}`);
  const json = await res.json();
  return extractCertspotterHosts(json);
}

// TEMPORARY: crt.sh has been returning 502 Bad Gateway globally since
// 2026-08-26 (their public sqlite backend is overloaded). Silently skip it
// so 'both'/'crtsh' runs don't waste time waiting on failures. Delete this
// block and the `CRTSH_DISABLED` gate to re-enable when they recover.
const CRTSH_DISABLED = true;

async function queryAll(pattern: string, source: Source, timeoutMs: number, log: (s: string) => void): Promise<string[]> {
  const all = new Set<string>();
  const attempt = async (name: string, fn: () => Promise<string[]>) => {
    try {
      const hosts = await fn();
      log(`    ${name}: ${hosts.length} hosts`);
      for (const h of hosts) all.add(h);
    } catch (e: unknown) {
      log(`    ${name}: ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  if (source === 'crtsh' || source === 'both') {
    if (CRTSH_DISABLED) {
      log('    crt.sh: SKIPPED (temporarily disabled — 502s global since 2026-08-26)');
    } else {
      await attempt('crt.sh', () => queryCrtSh(pattern, timeoutMs));
    }
  }
  if (source === 'certspotter' || source === 'both') {
    await attempt('certspotter', () => queryCertspotter(pattern, timeoutMs));
  }
  return [...all];
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.patterns.length) {
    usage();
    process.exit(opts.patterns.length ? 0 : 1);
  }
  const keep = makeDomainFilter(opts.suffix, opts.exclude);
  const existing = opts.merge
    ? new Set(
        fs.readFileSync(opts.merge, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
      )
    : new Set<string>();
  const seed = new Set(existing);
  const found = new Set<string>();

  const log = (s: string) => console.error(s);
  for (const pattern of opts.patterns) {
    console.error(`querying ${opts.source}: ${pattern}`);
    const hosts = await queryAll(pattern, opts.source, opts.timeoutMs, log);
    let kept = 0, newHosts = 0;
    for (const raw of hosts) {
      const filtered = keep(raw);
      if (!filtered) continue;
      kept++;
      if (!existing.has(filtered) && !found.has(filtered)) {
        found.add(filtered);
        newHosts++;
      }
    }
    console.error(`  ${hosts.length} raw union · ${kept} kept · ${newHosts} new`);
  }

  const merged = new Set([...seed, ...found]);
  const outPath = path.resolve(opts.out);
  fs.writeFileSync(outPath, [...merged].sort().join('\n') + '\n');

  if (opts.sqlite && found.size) {
    const db = openDb(opts.sqlite);
    const now = new Date().toISOString();
    const source = opts.source === 'both' ? 'ct-both' : `ct-${opts.source}`;
    const runId = db.startRun('ct-log', { patterns: opts.patterns, source: opts.source }, now);
    for (const h of found) db.upsertHost(h, source, now);
    db.finishRun(runId, { addedHosts: found.size, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite)} (+${found.size} hosts)`);
  }
  console.error(`wrote ${merged.size} hosts (${found.size} new) to ${outPath}`);

  if (opts.merge) {
    fs.writeFileSync(path.resolve(opts.merge), [...merged].sort().join('\n') + '\n');
    console.error(`merged back into ${opts.merge} (was ${seed.size}, now ${merged.size})`);
  }
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error('FATAL:', msg);
  process.exit(1);
});
