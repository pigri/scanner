import type { Db } from './db.js';
import type { GeoLookup, GeoRow } from './geoip.js';
import { classifyIp, normalizeIp, type IpClass } from './ip.js';
import { lookupPtrs, type LookupPtrsOpts } from './ptr.js';

export const WRITE_CHUNK = 500;

export interface NetinfoOpts {
  db: Db;
  /** Target names, or 'all' for every scan_queue target. */
  targets: readonly string[] | 'all';
  /** null when no MMDB is available: stored geo is left alone. */
  geo: GeoLookup | null;
  now?: Date;
  chunkSize?: number;
}

export interface NetinfoResult {
  targets: number;
  rowsWritten: number;
  skippedInvalid: number;
  geoHits: number;
  geoMisses: number;
  ptr: PtrCounts;
}

export interface PtrCounts {
  looked_up: number;
  found: number;
  empty: number;
  failed: number;
  skipped_budget: number;
}

export interface PtrOpts {
  budgetMs: number;
  /** Injectable for tests; defaults to the c-ares lookup in ./ptr.ts. */
  lookup?: (ips: readonly string[], opts: LookupPtrsOpts) => Promise<Map<string, string[] | null>>;
}

interface NetRow {
  target: string;
  ip: string;
  ip_version: 4 | 6;
  ip_class: IpClass;
  asn: string | null;
  as_name: string | null;
  as_domain: string | null;
  country_code: string | null;
  country: string | null;
  geo_checked_at: string | null;
  ptr_json: string | null;
  from_ports: number;
  from_dns: number;
  first_seen: string;
  last_seen: string;
}

interface Evidence { ports: boolean; dns: boolean; first: string; last: string }

const UPSERT = `
INSERT INTO target_network
  (target, ip, ip_version, ip_class, asn, as_name, as_domain, country_code, country,
   geo_checked_at, ptr_json, from_ports, from_dns, first_seen, last_seen)
VALUES
  (@target, @ip, @ip_version, @ip_class, @asn, @as_name, @as_domain, @country_code, @country,
   @geo_checked_at, @ptr_json, @from_ports, @from_dns, @first_seen, @last_seen)
ON CONFLICT(target, ip) DO UPDATE SET
  ip_version     = excluded.ip_version,
  ip_class       = excluded.ip_class,
  asn            = CASE WHEN excluded.geo_checked_at IS NOT NULL THEN excluded.asn ELSE asn END,
  as_name        = CASE WHEN excluded.geo_checked_at IS NOT NULL THEN excluded.as_name ELSE as_name END,
  as_domain      = CASE WHEN excluded.geo_checked_at IS NOT NULL THEN excluded.as_domain ELSE as_domain END,
  country_code   = CASE WHEN excluded.geo_checked_at IS NOT NULL THEN excluded.country_code ELSE country_code END,
  country        = CASE WHEN excluded.geo_checked_at IS NOT NULL THEN excluded.country ELSE country END,
  geo_checked_at = COALESCE(excluded.geo_checked_at, geo_checked_at),
  ptr_json       = COALESCE(excluded.ptr_json, ptr_json),
  from_ports     = MAX(from_ports, excluded.from_ports),
  from_dns       = MAX(from_dns, excluded.from_dns),
  first_seen     = MIN(first_seen, excluded.first_seen),
  last_seen      = MAX(last_seen, excluded.last_seen)`;

const PORTS_SQL = `SELECT ip, MIN(seen_at) f, MAX(seen_at) l FROM ports
  WHERE target = ? AND ip IS NOT NULL AND ip != '' GROUP BY ip`;
const DNS_SQL = `SELECT value ip, MIN(seen_at) f, MAX(COALESCE(last_seen, seen_at)) l FROM dns_records
  WHERE target = ? AND type IN ('A','AAAA') GROUP BY value`;

type EvidenceRow = { ip: string; f: string; l: string };

const noPtr = (): PtrCounts => ({ looked_up: 0, found: 0, empty: 0, failed: 0, skipped_budget: 0 });

/** Derives and writes rows without any network I/O. */
export function runNetinfo(opts: NetinfoOpts): NetinfoResult {
  const { out, result } = derive(opts);
  write(opts, out, result);
  return result;
}

/** As runNetinfo, but resolves PTR names for the distinct public IPs first. All lookups end before the first write. */
export async function runNetinfoPtr(opts: NetinfoOpts & { ptr: PtrOpts }): Promise<NetinfoResult> {
  const { out, result } = derive(opts);
  const publicIps = [...new Set(out.filter((r) => r.ip_class === 'public').map((r) => r.ip))];
  const stats = { skippedByBudget: 0 };
  let found = new Map<string, string[] | null>();
  try {
    found = await (opts.ptr.lookup ?? lookupPtrs)(publicIps, { budgetMs: opts.ptr.budgetMs, stats });
  } catch (e) {
    console.error(`netinfo: ptr lookup failed, writing rows without names: ${e instanceof Error ? e.message : String(e)}`);
    stats.skippedByBudget = 0;
  }
  result.ptr.looked_up = publicIps.length;
  result.ptr.skipped_budget = stats.skippedByBudget;
  for (const ip of publicIps) {
    const names = found.get(ip) ?? null;
    if (names === null) continue;
    if (names.length > 0) result.ptr.found++; else result.ptr.empty++;
  }
  result.ptr.failed = publicIps.length - result.ptr.found - result.ptr.empty - result.ptr.skipped_budget;
  for (const r of out) {
    const names = r.ip_class === 'public' ? found.get(r.ip) ?? null : null;
    r.ptr_json = names === null ? null : JSON.stringify(names);
  }
  write(opts, out, result);
  return result;
}

function derive(opts: NetinfoOpts): { out: NetRow[]; result: NetinfoResult } {
  const { db, geo } = opts;
  const nowIso = (opts.now ?? new Date()).toISOString();
  // Scan workers hold write locks for whole batches (same reasoning as risk.ts).
  db.raw.pragma('busy_timeout = 60000');

  // Time an IP-literal target is stamped with when no evidence carries one.
  const targets = new Map<string, string>();
  if (opts.targets === 'all') {
    const q = db.raw.prepare('SELECT target, COALESCE(finished_at, started_at, queued_at) t FROM scan_queue').all() as { target: string; t: string }[];
    for (const r of q) targets.set(r.target, r.t);
  } else {
    for (const t of opts.targets) targets.set(t, nowIso);
  }

  const portsStmt = db.raw.prepare(PORTS_SQL);
  const dnsStmt = db.raw.prepare(DNS_SQL);
  const result: NetinfoResult = { targets: targets.size, rowsWritten: 0, skippedInvalid: 0, geoHits: 0, geoMisses: 0, ptr: noPtr() };
  const out: NetRow[] = [];

  for (const [target, identityAt] of targets) {
    const ev = new Map<string, { version: 4 | 6; e: Evidence }>();
    const add = (raw: string, f: string, l: string, source: 'ports' | 'dns'): void => {
      const n = normalizeIp(raw);
      if (!n) { result.skippedInvalid++; return; }
      const cur = ev.get(n.ip);
      if (!cur) {
        ev.set(n.ip, { version: n.version, e: { ports: source === 'ports', dns: source === 'dns', first: f, last: l } });
        return;
      }
      if (source === 'ports') cur.e.ports = true; else cur.e.dns = true;
      if (f < cur.e.first) cur.e.first = f;
      if (l > cur.e.last) cur.e.last = l;
    };
    for (const r of portsStmt.all(target) as EvidenceRow[]) add(r.ip, r.f, r.l, 'ports');
    for (const r of dnsStmt.all(target) as EvidenceRow[]) add(r.ip, r.f, r.l, 'dns');

    const self = normalizeIp(target);
    if (self && !ev.has(self.ip)) ev.set(self.ip, { version: self.version, e: { ports: false, dns: false, first: identityAt, last: identityAt } });
    else if (self) {
      const e = ev.get(self.ip)!.e;
      if (identityAt < e.first) e.first = identityAt;
      if (identityAt > e.last) e.last = identityAt;
    }

    for (const [ip, { version, e }] of ev) {
      const ipClass = classifyIp(ip);
      let g: GeoRow | null = null;
      let checked: string | null = null;
      if (geo && ipClass === 'public') {
        g = geo.get(ip);
        checked = nowIso;
        if (g) result.geoHits++; else result.geoMisses++;
      }
      out.push({
        target, ip, ip_version: version, ip_class: ipClass,
        asn: g?.asn ?? null, as_name: g?.as_name ?? null, as_domain: g?.as_domain ?? null,
        country_code: g?.country_code ?? null, country: g?.country ?? null,
        geo_checked_at: checked, ptr_json: null,
        from_ports: e.ports ? 1 : 0, from_dns: e.dns ? 1 : 0,
        first_seen: e.first, last_seen: e.last,
      });
    }
  }

  return { out, result };
}

function write(opts: NetinfoOpts, out: NetRow[], result: NetinfoResult): void {
  const { db } = opts;
  const chunk = Math.max(1, opts.chunkSize ?? WRITE_CHUNK);
  const upsert = db.raw.prepare(UPSERT);
  for (let i = 0; i < out.length; i += chunk) {
    const slice = out.slice(i, i + chunk);
    db.raw.transaction(() => { for (const r of slice) upsert.run(r); }).immediate();
    result.rowsWritten += slice.length;
  }
}
