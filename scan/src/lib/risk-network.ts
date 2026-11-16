import type Database from 'better-sqlite3';
import type { HostCountryDetail } from './risk.js';
import {
  DNS_TRACKING_START_SQL, DNS_UNTRACKED_TARGETS_SQL, TARGET_NETWORK_LIST_NO_QUEUE_SQL, TARGET_NETWORK_LIST_SQL,
  listCurrent, type ListNetworkRow, type ListScanContext,
} from './target-network.js';

export const NETWORK_CHANGE_DAYS = 30;
const WINDOW_MS = NETWORK_CHANGE_DAYS * 86_400_000;

export interface NetworkEvent {
  target: string;
  ip: string;
  kind: string;
  at: string;
  old_country_code: string | null;
  new_country_code: string | null;
  old_asn: string | null;
  new_asn: string | null;
  source: string;
}

/**
 * Most frequent country among `codes` (one entry per current public IP). A tie
 * goes to the lowest code, so the choice never depends on row order.
 */
export function pickCountry(codes: readonly string[]): { code: string; counts: Record<string, number>; tie: boolean } | null {
  if (codes.length === 0) return null;
  const n = new Map<string, number>();
  for (const c of codes) n.set(c, (n.get(c) ?? 0) + 1);
  const sorted = [...n.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  const top = sorted[0]!;
  return {
    code: top[0],
    counts: Object.fromEntries([...n.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))),
    tie: sorted.length > 1 && sorted[1]![1] === top[1],
  };
}

/**
 * Events in the last 30 days (inclusive) that count as a network change:
 * - a geo_changed with a new country or ASN;
 * - an ip_added whose ASN is not among the ASNs of the target's strictly earlier
 *   events. With no earlier IP, or only IPs without an ASN, it never counts, so
 *   the first IPs of a new target are not a change.
 * Scan and reconstructed events follow the same window.
 */
export function recentNetworkChange(events: readonly NetworkEvent[], now: string): { count: number } {
  const t = Date.parse(now);
  const timed = events
    .map((e) => ({ e, at: Date.parse(e.at) }))
    .filter((x) => Number.isFinite(x.at));
  let count = 0;
  for (const { e, at } of timed) {
    if (!Number.isFinite(t) || at < t - WINDOW_MS) continue;
    if (e.kind === 'geo_changed') {
      if ((e.new_country_code !== null && e.new_country_code !== e.old_country_code) ||
          (e.new_asn !== null && e.new_asn !== e.old_asn)) count++;
    } else if (e.kind === 'ip_added' && e.new_asn !== null) {
      const earlier = new Set<string>();
      for (const o of timed) {
        if (o.at >= at) continue;
        if (o.e.new_asn) earlier.add(o.e.new_asn);
        if (o.e.old_asn) earlier.add(o.e.old_asn);
      }
      if (earlier.size > 0 && !earlier.has(e.new_asn)) count++;
    }
  }
  return { count };
}

export interface NetworkSignal {
  country: HostCountryDetail | null;
  networkChange: { count: number };
}

const hasTable = (raw: Database.Database, name: string): boolean =>
  raw.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) !== undefined;

function listContext(raw: Database.Database): ListScanContext {
  if (!hasTable(raw, 'dns_records')) return { untracked: new Set(), trackingStart: null };
  const hasLastSeen = (raw.prepare('PRAGMA table_info(dns_records)').all() as { name: string }[]).some((c) => c.name === 'last_seen');
  if (!hasLastSeen) {
    const all = raw.prepare('SELECT DISTINCT target FROM dns_records').all() as { target: string }[];
    return { untracked: new Set(all.map((r) => r.target)), trackingStart: null };
  }
  const untracked = new Set((raw.prepare(DNS_UNTRACKED_TARGETS_SQL).all() as { target: string }[]).map((r) => r.target));
  const t = raw.prepare(DNS_TRACKING_START_SQL).get() as { tracking_start: string | null };
  return { untracked, trackingStart: t.tracking_start };
}

/**
 * Per target: the country of its current public IPs and its recent network
 * changes. Current follows the list's rule (latest done scan, else 24 h).
 * `fold` maps a raw target onto the key the scorer uses. Read-only; tolerates
 * a database without the tables.
 */
export function loadNetworkSignals(
  raw: Database.Database,
  now: string,
  fold: (target: string) => string = (t) => t,
): Map<string, NetworkSignal> {
  const codes = new Map<string, string[]>();
  const events = new Map<string, NetworkEvent[]>();
  if (hasTable(raw, 'target_network')) {
    const queue = hasTable(raw, 'scan_queue');
    const rows = raw.prepare(queue ? TARGET_NETWORK_LIST_SQL : TARGET_NETWORK_LIST_NO_QUEUE_SQL).all() as ListNetworkRow[];
    const ctx = queue ? listContext(raw) : undefined;
    const groups = new Map<string, ListNetworkRow[]>();
    for (const r of rows) {
      const g = groups.get(r.target);
      if (g) g.push(r); else groups.set(r.target, [r]);
    }
    for (const [target, group] of groups) {
      const { current } = listCurrent(target, group, ctx);
      const key = fold(target);
      group.forEach((r, i) => {
        if (!current[i] || r.ip_class !== 'public' || !r.country_code) return;
        const l = codes.get(key);
        if (l) l.push(r.country_code); else codes.set(key, [r.country_code]);
      });
    }
  }
  if (hasTable(raw, 'target_network_events')) {
    const rows = raw.prepare(`SELECT target, ip, kind, at, old_country_code, new_country_code, old_asn, new_asn, source
      FROM target_network_events WHERE kind IN ('ip_added', 'geo_changed')`).all() as NetworkEvent[];
    for (const e of rows) {
      const key = fold(e.target);
      const l = events.get(key);
      if (l) l.push(e); else events.set(key, [e]);
    }
  }
  const out = new Map<string, NetworkSignal>();
  for (const key of new Set([...codes.keys(), ...events.keys()])) {
    const pick = pickCountry(codes.get(key) ?? []);
    out.set(key, {
      country: pick ? { code: pick.code, source: 'network', counts: pick.counts, tie: pick.tie } : null,
      networkChange: recentNetworkChange(events.get(key) ?? [], now),
    });
  }
  return out;
}
