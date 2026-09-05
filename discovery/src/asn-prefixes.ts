#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import {
  normalizeAsn,
  extractPrefixes,
  dedupePrefixes,
  familyOf,
} from './lib/asn.js';

interface Opts {
  asns: string[];
  out: string | null;
  outJson: string | null;
  ipv4Only: boolean;
  ipv6Only: boolean;
  source: 'ripe' | 'bgpview';
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    asns: [],
    out: null,
    outJson: null,
    ipv4Only: false,
    ipv6Only: false,
    source: 'ripe',
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '-o' || a === '--out') opts.out = next();
    else if (a === '--out-json') opts.outJson = next();
    else if (a === '--ipv4') opts.ipv4Only = true;
    else if (a === '--ipv6') opts.ipv6Only = true;
    else if (a === '--source') opts.source = next() as 'ripe' | 'bgpview';
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  opts.asns = rest;
  return opts;
}

function usage(): void {
  console.error(`Usage: asn-prefixes <ASN...> [options]

Fetch announced CIDR prefixes for one or more ASNs and print (or write)
a de-duplicated CIDR list. Ranges are sorted numerically within family.

Options:
  -o, --out <path>       Write CIDRs to this file (default: stdout)
  --out-json <path>      Also write per-ASN metadata as JSON
  --ipv4                 Only IPv4 prefixes
  --ipv6                 Only IPv6 prefixes
  --source <ripe|bgpview>   Data source (default: ripe)

Example:
  asn-prefixes 1955 31581 -o prefixes.txt --out-json prefixes.json
`);
}

async function fetchRipe(asn: string): Promise<string[]> {
  const url = `https://stat.ripe.net/data/announced-prefixes/data.json?resource=${encodeURIComponent(asn)}`;
  const res = await fetch(url, { headers: { 'User-Agent': 'discovery/asn-prefixes' }, signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`${asn} RIPE fetch: HTTP ${res.status}`);
  const json = await res.json();
  return extractPrefixes(json);
}

async function fetchBgpview(asn: string): Promise<string[]> {
  const num = asn.replace(/^AS/, '');
  const url = `https://api.bgpview.io/asn/${num}/prefixes`;
  const res = await fetch(url, { headers: { 'User-Agent': 'discovery/asn-prefixes' }, signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`${asn} bgpview fetch: HTTP ${res.status}`);
  const json: unknown = await res.json();
  const data = (json as { data?: { ipv4_prefixes?: { prefix: string }[]; ipv6_prefixes?: { prefix: string }[] } }).data ?? {};
  return [
    ...(data.ipv4_prefixes ?? []).map((p) => p.prefix),
    ...(data.ipv6_prefixes ?? []).map((p) => p.prefix),
  ];
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.asns.length) {
    usage();
    process.exit(opts.asns.length ? 0 : 1);
  }
  if (opts.ipv4Only && opts.ipv6Only) {
    console.error('--ipv4 and --ipv6 are mutually exclusive');
    process.exit(1);
  }

  const asns = opts.asns.map(normalizeAsn);
  const perAsn: Record<string, string[]> = {};
  const all: string[] = [];

  const fetcher = opts.source === 'bgpview' ? fetchBgpview : fetchRipe;

  for (const asn of asns) {
    console.error(`fetching ${asn} from ${opts.source}...`);
    let prefixes: string[] = [];
    try {
      prefixes = await fetcher(asn);
    } catch (e: unknown) {
      console.error(`  error: ${e instanceof Error ? e.message : String(e)}`);
      continue;
    }
    if (opts.ipv4Only) prefixes = prefixes.filter((p) => familyOf(p) === 4);
    if (opts.ipv6Only) prefixes = prefixes.filter((p) => familyOf(p) === 6);
    perAsn[asn] = prefixes;
    all.push(...prefixes);
    console.error(`  ${asn}: ${prefixes.length} prefixes`);
  }

  const merged = dedupePrefixes(all, { sort: true });

  if (opts.out) {
    fs.writeFileSync(opts.out, merged.join('\n') + '\n');
    console.error(`wrote ${merged.length} prefixes to ${path.resolve(opts.out)}`);
  } else {
    process.stdout.write(merged.join('\n') + '\n');
  }

  if (opts.outJson) {
    const meta = {
      asns,
      source: opts.source,
      fetched_at: new Date().toISOString(),
      per_asn: Object.fromEntries(
        Object.entries(perAsn).map(([a, p]) => [a, { count: p.length, prefixes: dedupePrefixes(p, { sort: true }) }])
      ),
      merged_count: merged.length,
    };
    fs.writeFileSync(opts.outJson, JSON.stringify(meta, null, 2));
    console.error(`wrote metadata to ${path.resolve(opts.outJson)}`);
  }
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error('FATAL:', msg);
  process.exit(1);
});
