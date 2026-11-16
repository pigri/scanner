export const TARGET_NETWORK_SQL = `SELECT ip, ip_version, ip_class, asn, as_name, as_domain, country_code, country,
  geo_checked_at, ptr_json, from_ports, from_dns, first_seen, last_seen
  FROM target_network WHERE target = ? ORDER BY ip LIMIT 500`;

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
  seenVia: ('ports' | 'dns')[];
  first_seen: string;
  last_seen: string;
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

export function shapeNetworkRows(rows: readonly NetworkDbRow[]): NetworkRow[] {
  const current = markCurrent(rows);
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
    seenVia: [...(r.from_ports ? ['ports' as const] : []), ...(r.from_dns ? ['dns' as const] : [])],
    first_seen: r.first_seen,
    last_seen: r.last_seen,
    current: current[i]!,
  }));
}
