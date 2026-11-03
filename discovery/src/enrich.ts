#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import maxmind from 'maxmind';
import type { EnrichedAddress, EnrichedRow } from './lib/graph.js';
import { fetchCert, certCsvFields } from './lib/cert.js';
import { openDb, type Db } from './lib/db.js';
import { ResolverPool, resolveHost, reverseIp, DEFAULT_RESOLVERS } from './lib/resolve.js';

const MMDB_URL =
  'https://github.com/gen0sec/geoip-databases/releases/latest/download/ipinfo_lite.mmdb';

interface Opts {
  input: string;
  mmdb: string;
  outJsonl: string | null;
  outCsv: string | null;
  concurrency: number;
  timeoutMs: number;
  maxTries: number;
  resolvers: string[] | null;
  ipv6: boolean;
  ptr: boolean;
  refresh: boolean;
  sqlite: string | null;
  source: string;
  tlsCert: boolean;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    input: '',
    mmdb: 'ipinfo_lite.mmdb',
    outJsonl: 'enriched.jsonl',
    outCsv: 'enriched.csv',
    concurrency: 20,
    timeoutMs: 5000,
    maxTries: 3,
    resolvers: DEFAULT_RESOLVERS,
    ipv6: true,
    ptr: true,
    refresh: false,
    sqlite: null,
    source: 'enrich',
    tlsCert: true,
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--mmdb') opts.mmdb = next();
    else if (a === '--out-jsonl') opts.outJsonl = next();
    else if (a === '--out-csv') opts.outCsv = next();
    else if (a === '--no-csv') opts.outCsv = null;
    else if (a === '--no-jsonl') opts.outJsonl = null;
    else if (a === '--concurrency') opts.concurrency = parseInt(next(), 10);
    else if (a === '--timeout-ms') opts.timeoutMs = parseInt(next(), 10);
    else if (a === '--resolvers') {
      const v = next();
      opts.resolvers = v === 'system' ? null : v.split(',').map((s) => s.trim()).filter(Boolean);
    }
    else if (a === '--max-tries') opts.maxTries = Math.max(1, parseInt(next(), 10) || 1);
    else if (a === '--no-ipv6') opts.ipv6 = false;
    else if (a === '--no-ptr') opts.ptr = false;
    else if (a === '--refresh-mmdb') opts.refresh = true;
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '--source') opts.source = next();
    else if (a === '--no-tls-cert') opts.tlsCert = false;
    else if (a === '--help' || a === '-h') opts.help = true;
    else rest.push(a);
  }
  opts.input = rest[0] ?? '';
  return opts;
}

function usage(): void {
  console.error(`Usage: enrich <domains.txt> [options]

For each domain, resolve A/AAAA -> PTR -> ipinfo MMDB (ASN, country, ...).
Writes JSONL (one row per domain) and/or CSV (one row per (domain, ip) pair).

Options:
  --mmdb <path>          MMDB file (default: ipinfo_lite.mmdb; auto-downloaded if missing)
  --refresh-mmdb         Force re-download of the MMDB
  --out-jsonl <path>     JSONL output (default: enriched.jsonl; --no-jsonl to disable)
  --out-csv <path>       CSV output (default: enriched.csv; --no-csv to disable)
  --concurrency <N>      Parallel resolves (default: 20)
  --timeout-ms <N>       DNS timeout per query (default: 5000)
  --resolvers <a,b,c>    Resolvers to use (default: 1.1.1.1,8.8.8.8,9.9.9.9;
                         pass 'system' to use the OS-configured resolvers)
  --max-tries <N>        Retries per record on transient failures (default: 3)
  --no-ipv6              Skip AAAA lookups
  --no-ptr               Skip reverse DNS
  --sqlite <path>        Also write hosts/ips/resolutions/ptr history to this SQLite DB
  --source <name>        Source tag for provenance (default: enrich)
  --no-tls-cert          Skip the TLS certificate fetch (org/CN/issuer per host)
`);
}

async function ensureMmdb(file: string, force: boolean): Promise<void> {
  if (!force && fs.existsSync(file)) return;
  console.error(`downloading ${MMDB_URL}...`);
  const res = await fetch(MMDB_URL, { redirect: 'follow' });
  if (!res.ok || !res.body) throw new Error(`mmdb download failed: ${res.status}`);
  await pipeline(Readable.fromWeb(res.body as any), fs.createWriteStream(file));
  const stat = fs.statSync(file);
  console.error(`saved ${file} (${(stat.size / 1024 / 1024).toFixed(1)} MiB)`);
}

async function pool<T, R>(items: readonly T[], size: number, worker: (item: T, idx: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let i = 0;
  async function run(): Promise<void> {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      results[idx] = await worker(items[idx]!, idx);
    }
  }
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, run));
  return results;
}

function csvEscape(v: unknown): string {
  if (v == null) return '';
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

interface GeoRow {
  asn?: string; as_name?: string; as_domain?: string;
  country?: string; country_code?: string;
  continent?: string; continent_code?: string;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.input) {
    usage();
    process.exit(opts.input ? 0 : 1);
  }

  await ensureMmdb(opts.mmdb, opts.refresh);
  const geo = (await maxmind.open(opts.mmdb)) as { get(ip: string): GeoRow | null };

  const resolverPool = new ResolverPool(opts.resolvers);

  const domains = fs
    .readFileSync(opts.input, 'utf8')
    .split('\n')
    .map((s) => s.trim().replace(/^www\./, '').toLowerCase())
    .filter(Boolean);
  const unique = [...new Set(domains)];
  console.error(`enriching ${unique.length} domains (concurrency ${opts.concurrency})...`);
  console.error(`  resolvers: ${opts.resolvers ? opts.resolvers.join(',') : 'system'} · max-tries ${opts.maxTries}`);

  const jsonlStream = opts.outJsonl ? fs.createWriteStream(opts.outJsonl) : null;
  const csvStream = opts.outCsv ? fs.createWriteStream(opts.outCsv) : null;
  if (csvStream) {
    csvStream.write(
      'domain,ip,ip_version,ptr,asn,as_name,as_domain,country_code,country,continent_code,cert_org,cert_cn,cert_issuer_org\n'
    );
  }

  let db: Db | null = null;
  let runId: number | null = null;
  const now = new Date().toISOString();
  if (opts.sqlite) {
    db = openDb(opts.sqlite);
    runId = db.startRun('enrich', { input: opts.input, concurrency: opts.concurrency, source: opts.source }, now);
  }

  let done = 0, resolved = 0, ipCount = 0;
  const start = Date.now();
  await pool(unique, opts.concurrency, async (domain) => {
    const dns4and6 = await resolveHost(domain, resolverPool, {
      ipv6: opts.ipv6,
      maxTries: opts.maxTries,
      timeoutMs: opts.timeoutMs,
    });
    const ips = [
      ...dns4and6.a.map((ip) => ({ ip, version: 4 as const })),
      ...dns4and6.aaaa.map((ip) => ({ ip, version: 6 as const })),
    ];
    const addresses: EnrichedAddress[] = await Promise.all(
      ips.map(async ({ ip, version }) => {
        const [ptr, geoRow] = await Promise.all([
          opts.ptr ? reverseIp(ip, resolverPool, opts.timeoutMs) : Promise.resolve([]),
          Promise.resolve(geo.get(ip) || {}),
        ]);
        return {
          ip, version, ptr,
          asn: geoRow.asn ?? null,
          as_name: geoRow.as_name ?? null,
          as_domain: geoRow.as_domain ?? null,
          country_code: geoRow.country_code ?? null,
          country: geoRow.country ?? null,
          continent_code: geoRow.continent_code ?? null,
        };
      })
    );

    // One cert per hostname (keyed by SNI), fetched against the first
    // resolved IP (prefer v4). fetchCert never throws, so the worker never
    // rejects and enrich still reaches a clean exit 0 (the enrich-exit invariant).
    const cert =
      opts.tlsCert && addresses.length
        ? await fetchCert(domain, {
            ip: (addresses.find((a) => a.version === 4) ?? addresses[0]!).ip,
            timeoutMs: opts.timeoutMs,
          })
        : null;

    const row: EnrichedRow = { domain, addresses, errors: dns4and6.errors, cert };
    if (jsonlStream) jsonlStream.write(JSON.stringify(row) + '\n');

    if (db && addresses.length) {
      const hostId = db.upsertHost(domain, opts.source, now);
      for (const a of addresses) {
        db.upsertIp(a.ip, {
          family: a.version,
          asn: a.asn, as_name: a.as_name, as_domain: a.as_domain,
          country_code: a.country_code, country: a.country, continent_code: a.continent_code,
        }, now);
        db.addResolution(hostId, a.ip, a.version, now);
        for (const p of a.ptr) db.addPtr(a.ip, p, now);
      }
    }
    if (csvStream) {
      if (!addresses.length) {
        csvStream.write([csvEscape(domain), '', '', '', '', '', '', '', '', '', ...certCsvFields(cert).map(csvEscape)].join(',') + '\n');
      } else {
        for (const a of addresses) {
          csvStream.write(
            [
              csvEscape(domain),
              csvEscape(a.ip),
              csvEscape(a.version),
              csvEscape(a.ptr.join('|')),
              csvEscape(a.asn),
              csvEscape(a.as_name),
              csvEscape(a.as_domain),
              csvEscape(a.country_code),
              csvEscape(a.country),
              csvEscape(a.continent_code),
              ...certCsvFields(cert).map(csvEscape),
            ].join(',') + '\n'
          );
        }
      }
    }

    done++;
    if (addresses.length) { resolved++; ipCount += addresses.length; }
    if (done % 25 === 0 || done === unique.length) {
      const rate = (done / ((Date.now() - start) / 1000)).toFixed(1);
      process.stderr.write(`\r${done}/${unique.length} · resolved ${resolved} · ${ipCount} IPs · ${rate} d/s`);
    }
  });
  process.stderr.write('\n');

  if (jsonlStream) await new Promise<void>((r) => jsonlStream.end(() => r()));
  if (csvStream) await new Promise<void>((r) => csvStream.end(() => r()));

  if (db && runId !== null) {
    db.finishRun(runId, { addedHosts: resolved, addedIps: ipCount, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)}`);
  }

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.error(`\ndone in ${elapsed}s`);
  console.error(`  ${unique.length} domains -> ${resolved} resolved, ${unique.length - resolved} failed`);
  console.error(`  ${ipCount} total IPs`);
  if (opts.outJsonl) console.error(`  jsonl: ${path.resolve(opts.outJsonl)}`);
  if (opts.outCsv) console.error(`  csv:   ${path.resolve(opts.outCsv)}`);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error('FATAL:', msg);
  process.exit(1);
});
