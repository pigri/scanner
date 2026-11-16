/** The UI never migrates: pass hasFromHttp=false for a DB whose target_network predates from_http. */
export const targetNetworkSql = (hasFromHttp: boolean): string => `SELECT ip, ip_version, ip_class, asn, as_name, as_domain, country_code, country,
  geo_checked_at, ptr_json, from_ports, from_dns, ${hasFromHttp ? 'from_http' : '0 AS from_http'}, first_seen, last_seen
  FROM target_network WHERE target = ? ORDER BY ip LIMIT 500`;

export const TARGET_NETWORK_SQL = targetNetworkSql(true);

/** `started_at` is the target's latest done scan, NULL when it has none. */
export const TARGET_NETWORK_LIST_SQL = `SELECT tn.target, tn.ip, tn.asn, tn.country_code, tn.country,
  tn.last_seen, tn.ip_class, q.started_at
  FROM target_network tn
  LEFT JOIN scan_queue q ON q.target = tn.target AND q.status = 'done'
  ORDER BY tn.target, tn.ip`;

/** The target's queue row (target is UNIQUE there). Only a `done` row is a latest scan. */
export const TARGET_SCAN_SQL = `SELECT status, started_at, finished_at FROM scan_queue WHERE target = ?`;

/** Newest evidence time and the count seen at or after @s, for ports and HTTP probes. Bind @t and @s. */
export const TARGET_ANSWERED_SQL = `SELECT 'port' AS source, MAX(seen_at) AS at,
    COUNT(DISTINCT CASE WHEN seen_at >= @s THEN port || '/' || protocol END) AS n
  FROM ports WHERE target = @t
  UNION ALL
  SELECT 'http', MAX(seen_at), COUNT(DISTINCT CASE WHEN seen_at >= @s THEN url END)
  FROM http_probes WHERE target = @t`;

/** Same for DNS records, which carry last_seen only since it was added. Bind @t and @s. */
export const TARGET_ANSWERED_DNS_SQL = `SELECT 'dns' AS source, MAX(COALESCE(last_seen, seen_at)) AS at,
    COUNT(CASE WHEN COALESCE(last_seen, seen_at) >= @s THEN 1 END) AS n
  FROM dns_records WHERE target = @t`;

/** For a DB whose dns_records predates last_seen: seen_at is the only time. Bind @t and @s. */
export const TARGET_ANSWERED_DNS_NO_LAST_SEEN_SQL = `SELECT 'dns' AS source, MAX(seen_at) AS at,
    COUNT(CASE WHEN seen_at >= @s THEN 1 END) AS n
  FROM dns_records WHERE target = @t`;

/** When DNS per-scan tracking began, and whether @t has rows from before it. Bind @t. */
export const DNS_TRACKING_SQL = `SELECT MIN(last_seen) AS tracking_start,
    EXISTS(SELECT 1 FROM dns_records WHERE target = @t AND last_seen IS NULL) AS untracked
  FROM dns_records`;

/** The list without the scan join, for a database that has no scan_queue. */
export const TARGET_NETWORK_LIST_NO_QUEUE_SQL = `SELECT target, ip, asn, country_code, country,
  last_seen, ip_class FROM target_network ORDER BY target, ip`;

/** Targets that have a dns_records row written before last_seen existed. One read per list build. */
export const DNS_UNTRACKED_TARGETS_SQL = `SELECT DISTINCT target FROM dns_records WHERE last_seen IS NULL`;

/** When DNS per-scan tracking began. NULL when nothing is tracked yet. */
export const DNS_TRACKING_START_SQL = `SELECT MIN(last_seen) AS tracking_start FROM dns_records`;

export type ScanStatus = 'yes' | 'no' | 'unknown' | 'none';

export interface ScanContext {
  /** `started_at` of the target's latest done scan; null when it has none. */
  startedAt: string | null;
  /** The target has dns_records rows with NULL last_seen. */
  dnsUntracked: boolean;
  /** MIN(dns_records.last_seen); null when nothing is tracked yet. */
  trackingStart: string | null;
}

export interface NetworkDbRow {
  ip: string;
  ip_version: number;
  ip_class: string;
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

export interface NetworkRow {
  ip: string;
  ipVersion: number;
  ipClass: string;
  asn: string | null;
  as_name: string | null;
  as_domain: string | null;
  country_code: string | null;
  country: string | null;
  /** none = not looked up, miss = looked up with no data, hit = data found. */
  geo: 'hit' | 'miss' | 'none';
  /** null = not looked up; [] = looked up, no PTR. */
  ptr: string[] | null;
  seenVia: ('ports' | 'dns' | 'http')[];
  first_seen: string;
  last_seen: string;
  scanStatus: ScanStatus;
  current: boolean;
}

const CURRENT_WINDOW_MS = 24 * 3600_000;

/** A row is current when its last_seen is within 24 h of the newest one. */
export function markCurrent(rows: readonly Pick<NetworkDbRow, 'last_seen'>[]): boolean[] {
  const times = rows.map((r) => Date.parse(r.last_seen));
  const valid = times.filter((t) => Number.isFinite(t));
  if (valid.length === 0) return rows.map(() => true);
  const newest = Math.max(...valid);
  return times.map((t) => !Number.isFinite(t) || newest - t <= CURRENT_WINDOW_MS);
}

/**
 * Whether an IP was seen in the target's latest done scan. `scanStart` is null
 * when there is none ('none': the caller applies the 24 h rule). An unparsable
 * IP or scan time counts as current ('yes'); an unparsable tracking start counts
 * as no tracking at all, so every scan predates it.
 */
export function scanStatus(
  ipLastSeen: string,
  scanStart: string | null,
  dnsUntracked: boolean,
  trackingStart: string | null,
): ScanStatus {
  if (scanStart === null) return 'none';
  const seen = Date.parse(ipLastSeen);
  const s = Date.parse(scanStart);
  if (!Number.isFinite(seen) || !Number.isFinite(s)) return 'yes';
  if (seen >= s) return 'yes';
  if (!dnsUntracked) return 'no';
  const track = trackingStart === null ? NaN : Date.parse(trackingStart);
  return !Number.isFinite(track) || s < track ? 'unknown' : 'no';
}

/**
 * `scanStart` when the target has a done scan and none of its IPs was 'yes' or
 * 'unknown' in it. A target with no IPs has nothing to compare, so it counts
 * only when `answered` is false: no port or HTTP row came from that scan.
 * An undefined `answered` means unknown, which does not flag.
 */
export function unreachableSince(
  statuses: readonly ScanStatus[],
  scanStart: string | null,
  answered?: boolean,
): string | null {
  if (scanStart === null) return null;
  if (statuses.length === 0) return answered === false ? scanStart : null;
  return statuses.every((st) => st === 'no') ? scanStart : null;
}

/**
 * Done scans of targets that have no target_network row, with whether a port or
 * HTTP row was seen at or after the scan start. Pass false for a table the DB
 * lacks. With byTarget, bind one target; else it lists every such target.
 */
export function noIpScanSql(hasPorts: boolean, hasHttp: boolean, byTarget: boolean): string {
  const ex = (table: string, idx: string): string =>
    `EXISTS(SELECT 1 FROM ${table} x INDEXED BY ${idx} WHERE x.target = q.target AND x.seen_at >= q.started_at)`;
  const answered = [hasPorts ? ex('ports', 'idx_ports_target') : '', hasHttp ? ex('http_probes', 'idx_http_target') : '']
    .filter(Boolean)
    .join(' OR ');
  return `SELECT q.target, q.started_at, ${answered ? `(${answered})` : '0'} AS answered
  FROM scan_queue q
  WHERE q.status = 'done' AND q.started_at IS NOT NULL
    AND NOT EXISTS(SELECT 1 FROM target_network tn WHERE tn.target = q.target)${byTarget ? ' AND q.target = ?' : ''}`;
}

function parsePtr(json: string | null): string[] | null {
  if (json === null) return null;
  try {
    const v: unknown = JSON.parse(json);
    if (!Array.isArray(v)) return null;
    return v.filter((x): x is string => typeof x === 'string');
  } catch {
    return null;
  }
}

export function shapeNetworkRows(rows: readonly NetworkDbRow[], scanCtx?: ScanContext): NetworkRow[] {
  const status = rows.map((r) =>
    scanCtx ? scanStatus(r.last_seen, scanCtx.startedAt, scanCtx.dnsUntracked, scanCtx.trackingStart) : 'none',
  );
  const old = markCurrent(rows);
  const current = rows.map((_, i) => (status[i] === 'none' ? old[i]! : status[i] !== 'no'));
  return rows.map((r, i) => ({
    ip: r.ip,
    ipVersion: r.ip_version,
    ipClass: r.ip_class,
    asn: r.asn,
    as_name: r.as_name,
    as_domain: r.as_domain,
    country_code: r.country_code,
    country: r.country,
    geo: r.geo_checked_at === null ? 'none' : r.asn !== null || r.country_code !== null ? 'hit' : 'miss',
    ptr: parsePtr(r.ptr_json),
    seenVia: [...(r.from_ports ? ['ports' as const] : []), ...(r.from_dns ? ['dns' as const] : []), ...(r.from_http ? ['http' as const] : [])],
    first_seen: r.first_seen,
    last_seen: r.last_seen,
    scanStatus: status[i]!,
    current: current[i]!,
  }));
}

export interface ListNetworkRow {
  target: string;
  ip: string;
  asn: string | null;
  country_code: string | null;
  country: string | null;
  last_seen: string;
  ip_class: string;
  /** `started_at` of the target's latest done scan; null or absent when it has none. */
  started_at?: string | null;
}

/** What the list needs to decide scan status for every target at once. */
export interface ListScanContext {
  /** Targets with dns_records rows that have NULL last_seen. */
  untracked: ReadonlySet<string>;
  /** MIN(dns_records.last_seen); null when nothing is tracked yet. */
  trackingStart: string | null;
}

export interface NetworkSummary {
  countries: string[];
  asns: string[];
  /** Start of the latest done scan when it reached none of the target's IPs, else null. */
  unreachableSince: string | null;
}

/**
 * Distinct countries and ASNs of each target's current public IPs. Rows must be
 * grouped by target. With a context, currency follows the latest scan (see
 * scanStatus); without one, the 24 h rule.
 */
export function summarizeNetworks(
  rows: readonly ListNetworkRow[],
  ctx?: ListScanContext,
): Map<string, NetworkSummary> {
  const out = new Map<string, NetworkSummary>();
  const flush = (target: string, group: ListNetworkRow[]): void => {
    const old = markCurrent(group);
    const untracked = ctx?.untracked.has(target) ?? false;
    const statuses = group.map((r) =>
      ctx ? scanStatus(r.last_seen, r.started_at ?? null, untracked, ctx.trackingStart) : ('none' as const),
    );
    const current = group.map((_, i) => (statuses[i] === 'none' ? old[i]! : statuses[i] !== 'no'));
    const countries = new Set<string>();
    const asns = new Set<string>();
    group.forEach((r, i) => {
      if (!current[i] || r.ip_class !== 'public') return;
      const c = r.country_code;
      if (c) countries.add(c);
      if (r.asn) asns.add(r.asn);
    });
    out.set(target, {
      countries: [...countries].sort(),
      asns: [...asns].sort(),
      unreachableSince: unreachableSince(statuses, group[0]!.started_at ?? null),
    });
  };
  let group: ListNetworkRow[] = [];
  for (const r of rows) {
    if (group.length && group[0]!.target !== r.target) {
      flush(group[0]!.target, group);
      group = [];
    }
    group.push(r);
  }
  if (group.length) flush(group[0]!.target, group);
  return out;
}

/** Newest first, capped. The UI never writes: this is the only read of target_network_events. Bind a target. */
export const TARGET_HISTORY_LIMIT = 200;
export const TARGET_HISTORY_SQL = `SELECT id, ip, kind, at, old_country_code, new_country_code, old_asn, new_asn, source
  FROM target_network_events WHERE target = ? ORDER BY at DESC, id DESC LIMIT ${TARGET_HISTORY_LIMIT}`;

export interface HistoryDbRow {
  kind: string;
  source: string;
  old_country_code: string | null;
  new_country_code: string | null;
  old_asn: string | null;
  new_asn: string | null;
}

/** One line for the panel. Reconstructed events are inferred from older evidence, so they say so. */
export function historyText(e: HistoryDbRow): string {
  const inferred = e.source === 'reconstructed' ? ' (inferred)' : '';
  if (e.kind === 'geo_changed') {
    const parts: string[] = [];
    if (e.old_country_code !== e.new_country_code) parts.push(`country ${e.old_country_code ?? 'none'} → ${e.new_country_code ?? 'none'}`);
    if (e.old_asn !== e.new_asn) parts.push(`ASN ${e.old_asn ?? 'none'} → ${e.new_asn ?? 'none'}`);
    return `geo changed: ${parts.join(', ')}${inferred}`;
  }
  const label = e.kind === 'ip_added' ? 'added' : e.kind === 'ip_gone' ? 'gone' : e.kind === 'ip_back' ? 'back' : e.kind;
  return `${label}${inferred}`;
}
