#!/usr/bin/env -S node --loader tsx
// ripe-search: query the RIPE database by free-text (name / descr / netname /
// org-name) and emit the matching CIDRs, ASNs, and organisation handles.
// Companion to asn-prefixes.ts (ASN → CIDR); this one is the reverse:
// search-term → orgs/ASNs → CIDRs, so you can seed an in-scope prefix list
// from an organisation or ministry name rather than a known ASN.
//
// Uses the fulltextsearch endpoint under apps.db.ripe.net. Terms are OR-ed
// and quoted when they contain whitespace; type-filter restricts to the
// object kinds that carry routable data (inetnum, inet6num, aut-num,
// organisation by default). Results are filtered by --country (default: HU)
// after fetch — the RIPE query language doesn't reliably narrow country on
// the server side across all object types.
import fs from 'node:fs';
import path from 'node:path';
import {
  parseSearchResponse,
  buildSearchUrl,
  extractCidrs,
  extractAsn,
  extractOrg,
  hasCountry,
  type RipeObject,
} from './lib/ripe-search.js';
import { dedupePrefixes } from './lib/asn.js';

interface Opts {
  terms: string[];
  types: string[];
  country: string | null;   // null = don't filter
  rows: number;
  out: string | null;       // CIDR list file
  outAsns: string | null;   // ASN list file
  outOrgs: string | null;   // org handles file
  outJson: string | null;   // full metadata
  timeoutMs: number;
  help?: boolean;
}

const DEFAULT_TYPES = ['inetnum', 'inet6num', 'aut-num', 'organisation'];

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    terms: [], types: DEFAULT_TYPES, country: 'HU', rows: 500,
    out: null, outAsns: null, outOrgs: null, outJson: null,
    timeoutMs: 30000,
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = (): string => argv[++i]!;
    if (a === '--country') opts.country = next() || null;
    else if (a === '--no-country') opts.country = null;
    else if (a === '--types') opts.types = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--rows') opts.rows = parseInt(next(), 10);
    else if (a === '-o' || a === '--out') opts.out = next();
    else if (a === '--out-asns') opts.outAsns = next();
    else if (a === '--out-orgs') opts.outOrgs = next();
    else if (a === '--out-json') opts.outJson = next();
    else if (a === '--timeout') opts.timeoutMs = parseInt(next(), 10) * 1000;
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  opts.terms = rest;
  return opts;
}

function usage(): void {
  console.error(`Usage: ripe-search <term>... [options]

Search the RIPE database (fulltextsearch API) by name / descr / netname /
org-name and emit matching CIDRs, ASNs, and org handles. Terms are OR-ed;
quote multi-word terms (e.g. "Ministry of Interior") on the shell.

Options:
  --country <cc>       Filter to this country code (default: HU). --no-country
                       to disable. inetnum/inet6num carry the country attr;
                       aut-num typically doesn't, so ASNs are kept regardless.
  --types <t,t,..>     RIPE object types to include (default:
                       inetnum,inet6num,aut-num,organisation)
  --rows N             Max results from the API (default: 500)
  -o, --out <path>     Write CIDR list to path (one per line, deduped + sorted)
  --out-asns <path>    Write ASN list to path
  --out-orgs <path>    Write org handle list to path
  --out-json <path>    Write full per-object metadata as JSON
  --timeout <sec>      HTTP timeout (default: 30)

Examples:
  # HU government netblocks — feeds ptr-sweep / masscan targets:
  ripe-search kormany "gov.hu" NISZ "Nemzeti Infokommunikáció" \\
    -o hu-gov-prefixes.txt --out-asns hu-gov-asns.txt --out-json hu-gov.json

  # Follow up on ASNs with the full BGP-announced expansion:
  npm run asn-prefixes -- $(cat hu-gov-asns.txt) -o hu-gov-bgp-prefixes.txt

  # Ministry-name search without country filter (some orgs registered abroad):
  ripe-search "Ministry of Interior" "Miniszterelnökség" --no-country
`);
}

async function fetchSearch(url: string, timeoutMs: number): Promise<unknown> {
  const res = await fetch(url, {
    headers: { Accept: 'application/json', 'User-Agent': 'discovery/ripe-search' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`RIPE fulltextsearch: HTTP ${res.status}`);
  return res.json();
}

function summarize(obj: RipeObject): string {
  const netname = obj.attrs['netname']?.[0];
  const orgName = obj.attrs['org-name']?.[0];
  const asName = obj.attrs['as-name']?.[0];
  const descr = obj.attrs['descr']?.[0];
  const country = obj.attrs['country']?.[0] ?? '?';
  // For aut-num, the actual AS number lives in the aut-num attribute — the
  // primaryKey is RIPE's numeric object ID, which looks confusingly like an
  // ASN (e.g. primaryKey=2054 for AS3219).
  const idField = obj.type === 'aut-num'
    ? (obj.attrs['aut-num']?.[0] ?? obj.primaryKey)
    : obj.primaryKey;
  const label = netname ?? asName ?? orgName ?? descr ?? idField;
  return `[${obj.type.padEnd(12)}] ${country.padEnd(3)} ${idField.padEnd(24)} ${label}`;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.terms.length) { usage(); process.exit(opts.help ? 0 : 1); }

  const url = buildSearchUrl(opts.terms, opts.types, opts.rows);
  console.error(`fetching: ${url}`);
  const json = await fetchSearch(url, opts.timeoutMs);
  const parsed = parseSearchResponse(json);
  console.error(`numFound: ${parsed.numFound} (returning up to ${opts.rows})`);
  console.error(`  raw docs: ${parsed.docs.length}`);

  // Country filter: applied only to inetnum/inet6num/organisation which
  // carry a country attribute. aut-num rows are kept regardless — an HU-run
  // ASN may announce prefixes that RIPE geolocates elsewhere.
  const kept = parsed.docs.filter((d) => {
    if (opts.country == null) return true;
    if (d.type === 'aut-num') return true;
    return hasCountry(d, opts.country);
  });
  console.error(`  kept after country filter (${opts.country ?? 'off'}): ${kept.length}`);

  const cidrs: string[] = [];
  const asns = new Set<string>();
  const orgs = new Set<string>();
  const bySection: Record<string, RipeObject[]> = {
    inetnum: [], inet6num: [], 'aut-num': [], organisation: [], other: [],
  };
  for (const obj of kept) {
    cidrs.push(...extractCidrs(obj));
    const a = extractAsn(obj); if (a) asns.add(a);
    const o = extractOrg(obj); if (o) orgs.add(o);
    (bySection[obj.type] ?? bySection.other!).push(obj);
  }
  const mergedCidrs = dedupePrefixes(cidrs, { sort: true });
  const asnList = [...asns].sort();
  const orgList = [...orgs].sort();

  // Human-readable preview to stderr; machine outputs go to the files/stdout.
  for (const section of ['organisation', 'aut-num', 'inetnum', 'inet6num']) {
    const rows = bySection[section]!;
    if (!rows.length) continue;
    console.error(`\n── ${section} (${rows.length}) ──`);
    for (const r of rows.slice(0, 20)) console.error(`  ${summarize(r)}`);
    if (rows.length > 20) console.error(`  … +${rows.length - 20} more`);
  }
  console.error(`\nsummary: ${mergedCidrs.length} CIDR(s), ${asnList.length} ASN(s), ${orgList.length} org(s)`);

  if (opts.out) {
    fs.writeFileSync(opts.out, mergedCidrs.join('\n') + '\n');
    console.error(`wrote ${mergedCidrs.length} CIDRs → ${path.resolve(opts.out)}`);
  } else if (!opts.outAsns && !opts.outOrgs && !opts.outJson) {
    process.stdout.write(mergedCidrs.join('\n') + '\n');
  }
  if (opts.outAsns) {
    fs.writeFileSync(opts.outAsns, asnList.join('\n') + '\n');
    console.error(`wrote ${asnList.length} ASNs → ${path.resolve(opts.outAsns)}`);
  }
  if (opts.outOrgs) {
    fs.writeFileSync(opts.outOrgs, orgList.join('\n') + '\n');
    console.error(`wrote ${orgList.length} orgs → ${path.resolve(opts.outOrgs)}`);
  }
  if (opts.outJson) {
    const meta = {
      query: { terms: opts.terms, types: opts.types, country: opts.country, rows: opts.rows },
      fetched_at: new Date().toISOString(),
      num_found: parsed.numFound,
      kept: kept.length,
      cidrs: mergedCidrs,
      asns: asnList,
      orgs: orgList,
      objects: kept.map((o) => ({
        type: o.type,
        primary_key: o.primaryKey,
        attrs: o.attrs,
        cidrs: extractCidrs(o),
      })),
    };
    fs.writeFileSync(opts.outJson, JSON.stringify(meta, null, 2));
    console.error(`wrote metadata → ${path.resolve(opts.outJson)}`);
  }
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error('FATAL:', msg);
  process.exit(1);
});
