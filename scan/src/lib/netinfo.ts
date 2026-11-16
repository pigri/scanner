import type Database from 'better-sqlite3';
import type { Db } from './db.js';
import type { GeoLookup, GeoRow } from './geoip.js';
import { classifyIp, normalizeIp, type IpClass } from './ip.js';
import { lookupPtrs, type LookupPtrsOpts } from './ptr.js';
import { scanStatus } from './target-network.js';

export const WRITE_CHUNK = 500;

export interface NetinfoOpts {
  db: Db;
  /** Target names, or 'all' for every scan_queue target. */
  targets: readonly string[] | 'all';
  /** null when no MMDB is available: stored geo is left alone. */
  geo: GeoLookup | null;
  now?: Date;
  chunkSize?: number;
  /** The netinfo run row, stored on the events this run writes. */
  runId?: number | null;
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
  from_http: number;
  first_seen: string;
  last_seen: string;
}

interface Evidence { ports: boolean; dns: boolean; http: boolean; first: string; last: string }

const UPSERT = `
INSERT INTO target_network
  (target, ip, ip_version, ip_class, asn, as_name, as_domain, country_code, country,
   geo_checked_at, ptr_json, from_ports, from_dns, from_http, first_seen, last_seen)
VALUES
  (@target, @ip, @ip_version, @ip_class, @asn, @as_name, @as_domain, @country_code, @country,
   @geo_checked_at, @ptr_json, @from_ports, @from_dns, @from_http, @first_seen, @last_seen)
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
  from_http      = MAX(from_http, excluded.from_http),
  first_seen     = MIN(first_seen, excluded.first_seen),
  last_seen      = MAX(last_seen, excluded.last_seen)`;

const PORTS_SQL = `SELECT ip, MIN(seen_at) f, MAX(seen_at) l FROM ports
  WHERE target = ? AND ip IS NOT NULL AND ip != '' GROUP BY ip`;
const DNS_SQL = `SELECT value ip, MIN(seen_at) f, MAX(COALESCE(last_seen, seen_at)) l FROM dns_records
  WHERE target = ? AND type IN ('A','AAAA') GROUP BY value`;

const HTTP_SQL = `SELECT ip, MIN(seen_at) f, MAX(seen_at) l FROM http_probes
  WHERE target = ? AND ip IS NOT NULL AND ip != '' GROUP BY ip`;

const STORED_SQL = 'SELECT asn, country_code, first_seen, last_seen FROM target_network WHERE target = ? AND ip = ?';
const LAST_PRESENCE_SQL = `SELECT kind FROM target_network_events
  WHERE target = ? AND ip = ? AND kind IN ('ip_added', 'ip_gone', 'ip_back') ORDER BY at DESC, id DESC LIMIT 1`;
const BATCH_START_SQL = "SELECT started_at FROM scan_queue WHERE target = ? AND status = 'in_progress'";
const DNS_UNTRACKED_SQL = 'SELECT EXISTS(SELECT 1 FROM dns_records WHERE target = ? AND last_seen IS NULL) AS n';
const TRACKING_START_SQL = 'SELECT MIN(last_seen) AS t FROM dns_records';
const INSERT_EVENT = `INSERT OR IGNORE INTO target_network_events
  (target, ip, kind, at, old_country_code, new_country_code, old_asn, new_asn, run_id, source)
  VALUES (@target, @ip, @kind, @at, @old_country_code, @new_country_code, @old_asn, @new_asn, @run_id, 'scan')`;

interface StoredRow { asn: string | null; country_code: string | null; first_seen: string; last_seen: string }

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
  const httpStmt = db.raw.prepare(HTTP_SQL);
  const result: NetinfoResult = { targets: targets.size, rowsWritten: 0, skippedInvalid: 0, geoHits: 0, geoMisses: 0, ptr: noPtr() };
  const out: NetRow[] = [];

  for (const [target, identityAt] of targets) {
    const ev = new Map<string, { version: 4 | 6; e: Evidence }>();
    const add = (raw: string, f: string, l: string, source: 'ports' | 'dns' | 'http'): void => {
      const n = normalizeIp(raw);
      if (!n) { result.skippedInvalid++; return; }
      const cur = ev.get(n.ip);
      if (!cur) {
        ev.set(n.ip, { version: n.version, e: { ports: source === 'ports', dns: source === 'dns', http: source === 'http', first: f, last: l } });
        return;
      }
      if (source === 'ports') cur.e.ports = true; else if (source === 'dns') cur.e.dns = true; else cur.e.http = true;
      if (f < cur.e.first) cur.e.first = f;
      if (l > cur.e.last) cur.e.last = l;
    };
    for (const r of portsStmt.all(target) as EvidenceRow[]) add(r.ip, r.f, r.l, 'ports');
    for (const r of dnsStmt.all(target) as EvidenceRow[]) add(r.ip, r.f, r.l, 'dns');
    for (const r of httpStmt.all(target) as EvidenceRow[]) add(r.ip, r.f, r.l, 'http');

    const self = normalizeIp(target);
    if (self && !ev.has(self.ip)) ev.set(self.ip, { version: self.version, e: { ports: false, dns: false, http: false, first: identityAt, last: identityAt } });
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
        from_ports: e.ports ? 1 : 0, from_dns: e.dns ? 1 : 0, from_http: e.http ? 1 : 0,
        first_seen: e.first, last_seen: e.last,
      });
    }
  }

  return { out, result };
}

function write(opts: NetinfoOpts, out: NetRow[], result: NetinfoResult): void {
  const { db } = opts;
  const chunk = Math.max(1, opts.chunkSize ?? WRITE_CHUNK);
  const nowIso = (opts.now ?? new Date()).toISOString();
  const runId = opts.runId ?? null;
  // ip_gone / ip_back only make sense for a worker batch: --all rewrites rows outside any scan.
  const batchMode = opts.targets !== 'all';
  const upsert = db.raw.prepare(UPSERT);
  const getStored = db.raw.prepare(STORED_SQL);
  const lastPresence = db.raw.prepare(LAST_PRESENCE_SQL);
  const batchStart = db.raw.prepare(BATCH_START_SQL);
  const dnsUntracked = db.raw.prepare(DNS_UNTRACKED_SQL);
  const insertEvent = db.raw.prepare(INSERT_EVENT);
  let trackingStart: string | null | undefined;

  for (let i = 0; i < out.length; i += chunk) {
    const slice = out.slice(i, i + chunk);
    db.raw.transaction(() => {
      const scanCtx = new Map<string, { s: string; untracked: boolean } | null>();
      const ctxOf = (target: string): { s: string; untracked: boolean } | null => {
        if (scanCtx.has(target)) return scanCtx.get(target)!;
        const row = batchStart.get(target) as { started_at: string | null } | undefined;
        const c = row?.started_at ? { s: row.started_at, untracked: (dnsUntracked.get(target) as { n: number }).n === 1 } : null;
        scanCtx.set(target, c);
        return c;
      };
      for (const r of slice) {
        const before = getStored.get(r.target, r.ip) as StoredRow | undefined;
        upsert.run(r);
        const after = getStored.get(r.target, r.ip) as StoredRow;
        const ev = (kind: string, at: string, oldCc: string | null, newCc: string | null, oldAsn: string | null, newAsn: string | null): void => {
          insertEvent.run({ target: r.target, ip: r.ip, kind, at, old_country_code: oldCc, new_country_code: newCc, old_asn: oldAsn, new_asn: newAsn, run_id: runId });
        };
        const last = (lastPresence.get(r.target, r.ip) as { kind: string } | undefined)?.kind;
        // An earlier rebuild may already have recorded this ip: never add a second ip_added.
        if (!before) {
          if (last === undefined) ev('ip_added', after.first_seen, null, after.country_code, null, after.asn);
        } else if (
          (before.country_code !== null && after.country_code !== before.country_code) ||
          (before.asn !== null && after.asn !== before.asn)
        ) {
          ev('geo_changed', nowIso, before.country_code, after.country_code, before.asn, after.asn);
        }
        if (!batchMode) continue;
        const c = ctxOf(r.target);
        if (!c) continue;
        if (trackingStart === undefined) trackingStart = (db.raw.prepare(TRACKING_START_SQL).get() as { t: string | null }).t;
        const status = scanStatus(after.last_seen, c.s, c.untracked, trackingStart);
        const present = last !== 'ip_gone';
        if (status === 'no' && present) ev('ip_gone', c.s, null, null, null, null);
        else if (status === 'yes' && !present) ev('ip_back', c.s, null, null, null, null);
      }
    }).immediate();
    result.rowsWritten += slice.length;
  }
}

/**
 * Queue hook: the history events a batch wrote at its start are void once the batch
 * is released, failed or reaped, because only done scans count.
 */
export function retractBatchEvents(raw: Database.Database): (rows: readonly { target: string; started_at: string }[]) => void {
  const del = raw.prepare(
    "DELETE FROM target_network_events WHERE target = ? AND at = ? AND source = 'scan' AND kind IN ('ip_gone', 'ip_back')",
  );
  return (rows) => { for (const r of rows) del.run(r.target, r.started_at); };
}
