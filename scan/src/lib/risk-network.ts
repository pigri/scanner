import type Database from 'better-sqlite3';
import type { HostCountryDetail } from './risk.js';
import { WINDOW_GAP_MS } from './netinfo-rebuild.js';
import {
  TARGET_NETWORK_LIST_NO_QUEUE_SQL, TARGET_NETWORK_LIST_SQL, listCurrent, loadListScanContext, type ListNetworkRow,
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
  run_id?: number | string | null;
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
 * Events in the last 30 days (inclusive, none after `now`) that count as a
 * network change:
 * - a geo_changed with a new country or ASN;
 * - an ip_added whose ASN is not among the ASNs of the target's strictly earlier
 *   events.
 * The target's first batch of ip_added events never counts (a geo_changed always
 * implies an earlier state, so it is not part of the exemption): every event within WINDOW_GAP_MS of its
 * earliest event, or sharing that event's non-null run_id. Its ASNs seed the
 * known set, so the first IPs of a new target are not a change.
 */
export function recentNetworkChange(events: readonly NetworkEvent[], now: string): { count: number } {
  const t = Date.parse(now);
  if (!Number.isFinite(t)) return { count: 0 };
  const timed = events
    .map((e) => ({ e, at: Date.parse(e.at) }))
    .filter((x) => Number.isFinite(x.at));
  if (timed.length === 0) return { count: 0 };
  const first = timed.reduce((m, x) => (x.at < m.at ? x : m));
  const firstRun = first.e.run_id ?? null;
  const inFirst = (x: { e: NetworkEvent; at: number }): boolean =>
    x.at - first.at <= WINDOW_GAP_MS || (firstRun !== null && x.e.run_id === firstRun);
  let count = 0;
  for (const x of timed) {
    const { e, at } = x;
    if (at < t - WINDOW_MS || at > t) continue;
    if (e.kind === 'geo_changed') {
      if ((e.new_country_code !== null && e.new_country_code !== e.old_country_code) ||
          (e.new_asn !== null && e.new_asn !== e.old_asn)) count++;
    } else if (e.kind === 'ip_added' && e.new_asn !== null && !inFirst(x)) {
      const earlier = new Set<string>();
      for (const o of timed) {
        if (!inFirst(o) && o.at >= at) continue;
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
    const ctx = queue ? loadListScanContext(raw) : undefined;
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
    const rows = raw.prepare(`SELECT target, ip, kind, at, old_country_code, new_country_code, old_asn, new_asn, run_id, source
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
