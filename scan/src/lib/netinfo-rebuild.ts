import type { Db } from './db.js';
import { normalizeIp } from './ip.js';
import { scanStatus } from './target-network.js';
import { WRITE_CHUNK } from './netinfo.js';

/** Runs that started within this long of each other, one after another, form one scan window. */
export const WINDOW_GAP_MS = 3 * 3600_000;

export interface PseudoRun { at: string; runId: number | null }
export interface ScanWindow {
  start: string;
  /** Last run start plus the gap, inclusive: the next window starts after it. */
  end: string;
  runIds: Set<number>;
}

/** Chains runs whose starts are at most WINDOW_GAP_MS apart. Unparsable times are dropped. */
export function clusterWindows(runs: readonly PseudoRun[]): ScanWindow[] {
  const sorted = runs
    .map((r) => ({ ...r, ms: Date.parse(r.at) }))
    .filter((r) => Number.isFinite(r.ms))
    .sort((a, b) => a.ms - b.ms);
  const out: ScanWindow[] = [];
  let lastMs = 0;
  for (const r of sorted) {
    const cur = out[out.length - 1];
    if (cur && r.ms - lastMs <= WINDOW_GAP_MS) {
      if (r.runId !== null) cur.runIds.add(r.runId);
      cur.end = new Date(r.ms + WINDOW_GAP_MS).toISOString();
    } else {
      out.push({ start: r.at, end: new Date(r.ms + WINDOW_GAP_MS).toISOString(), runIds: new Set(r.runId === null ? [] : [r.runId]) });
    }
    lastMs = r.ms;
  }
  return out;
}

export interface RebuildOpts {
  db: Db;
  /** Target names, or 'all' for every scan_queue target. */
  targets: readonly string[] | 'all';
  now?: Date;
  chunkSize?: number;
  runId?: number | null;
}

export interface RebuildResult {
  targets: number;
  windows: number;
  /** Events derived from the evidence. */
  proposed: number;
  /** Events that were new; the rest already existed. */
  inserted: number;
}

interface Proposed {
  target: string;
  ip: string;
  kind: 'ip_added' | 'ip_gone' | 'ip_back';
  at: string;
  new_country_code: string | null;
  new_asn: string | null;
}

const RUNS_SQL = `SELECT id, started_at FROM runs WHERE id IN (
  SELECT run_id FROM findings WHERE target = @t
  UNION SELECT run_id FROM ports WHERE target = @t
  UNION SELECT run_id FROM http_probes WHERE target = @t
  UNION SELECT run_id FROM dns_records WHERE target = @t)`;
const PORT_IPS_SQL = `SELECT DISTINCT ip, run_id FROM ports WHERE target = ? AND ip IS NOT NULL AND ip != '' AND run_id IS NOT NULL`;
const HTTP_IPS_SQL = `SELECT DISTINCT ip, run_id FROM http_probes WHERE target = ? AND ip IS NOT NULL AND ip != '' AND run_id IS NOT NULL`;
const DNS_IPS_SQL = `SELECT value ip, seen_at f, COALESCE(last_seen, seen_at) l FROM dns_records WHERE target = ? AND type IN ('A','AAAA')`;
const QUEUE_SQL = `SELECT started_at FROM scan_queue WHERE target = ? AND status = 'done' AND started_at IS NOT NULL`;
const UNTRACKED_SQL = 'SELECT EXISTS(SELECT 1 FROM dns_records WHERE target = ? AND last_seen IS NULL) AS n';
const GEO_SQL = 'SELECT ip, asn, country_code FROM target_network WHERE target = ?';
const SCAN_FIRST_SQL = `SELECT ip, MIN(at) AS at FROM target_network_events
  WHERE target = ? AND source = 'scan' AND kind IN ('ip_added', 'ip_gone', 'ip_back') GROUP BY ip`;
const INSERT_SQL = `INSERT OR IGNORE INTO target_network_events
  (target, ip, kind, at, old_country_code, new_country_code, old_asn, new_asn, run_id, source)
  VALUES (@target, @ip, @kind, @at, NULL, @new_country_code, NULL, @new_asn, @run_id, 'reconstructed')`;

// A time before any window: scanStatus then answers 'no' or 'unknown', never 'yes'.
const NEVER = '1970-01-01T00:00:00.000Z';

/**
 * Adds source='reconstructed' events from the stored evidence (see the plan, "Rebuild").
 * Only the events table is written, in .immediate() chunks; a re-run adds nothing, and
 * scan events are neither changed nor repeated.
 */
export function rebuildHistory(opts: RebuildOpts): RebuildResult {
  const { db } = opts;
  const chunk = Math.max(1, opts.chunkSize ?? WRITE_CHUNK);
  const runId = opts.runId ?? null;
  db.raw.pragma('busy_timeout = 60000');

  let names: string[];
  if (opts.targets === 'all') names = (db.raw.prepare('SELECT target FROM scan_queue').all() as { target: string }[]).map((r) => r.target);
  else names = [...new Set(opts.targets)];

  const runsStmt = db.raw.prepare(RUNS_SQL);
  const portStmt = db.raw.prepare(PORT_IPS_SQL);
  const httpStmt = db.raw.prepare(HTTP_IPS_SQL);
  const dnsStmt = db.raw.prepare(DNS_IPS_SQL);
  const queueStmt = db.raw.prepare(QUEUE_SQL);
  const untrackedStmt = db.raw.prepare(UNTRACKED_SQL);
  const geoStmt = db.raw.prepare(GEO_SQL);
  const scanFirst = db.raw.prepare(SCAN_FIRST_SQL);
  const insert = db.raw.prepare(INSERT_SQL);
  const trackingStart = (db.raw.prepare('SELECT MIN(last_seen) AS t FROM dns_records').get() as { t: string | null }).t;

  const result: RebuildResult = { targets: names.length, windows: 0, proposed: 0, inserted: 0 };
  let pending: Proposed[] = [];

  const flush = (): void => {
    if (pending.length === 0) return;
    const batch = pending;
    pending = [];
    db.raw.transaction(() => {
      const firstScan = new Map<string, Map<string, number>>();
      for (const e of batch) {
        let m = firstScan.get(e.target);
        if (!m) {
          m = new Map((scanFirst.all(e.target) as { ip: string; at: string }[]).map((r) => [r.ip, Date.parse(r.at)]));
          firstScan.set(e.target, m);
        }
        const cut = m.get(e.ip);
        if (cut !== undefined && Date.parse(e.at) >= cut) continue;
        result.inserted += insert.run({ ...e, run_id: runId }).changes;
      }
    }).immediate();
  };

  for (const target of names) {
    const runs: PseudoRun[] = (runsStmt.all({ t: target }) as { id: number; started_at: string }[]).map((r) => ({ at: r.started_at, runId: r.id }));
    for (const q of queueStmt.all(target) as { started_at: string }[]) runs.push({ at: q.started_at, runId: null });
    const windows = clusterWindows(runs);
    result.windows += windows.length;
    if (windows.length === 0) continue;

    // Per IP: the windows (by index) that saw it.
    const seen = new Map<string, Set<number>>();
    const mark = (raw: string, w: number): void => {
      const n = normalizeIp(raw);
      if (!n) return;
      let s = seen.get(n.ip);
      if (!s) seen.set(n.ip, (s = new Set()));
      s.add(w);
    };
    const byRun = new Map<number, number>();
    windows.forEach((w, i) => { for (const id of w.runIds) byRun.set(id, i); });
    for (const r of [...(portStmt.all(target) as { ip: string; run_id: number }[]), ...(httpStmt.all(target) as { ip: string; run_id: number }[])]) {
      const w = byRun.get(r.run_id);
      if (w !== undefined) mark(r.ip, w);
    }
    const bounds = windows.map((w) => [Date.parse(w.start), Date.parse(w.end)] as const);
    for (const r of dnsStmt.all(target) as { ip: string; f: string; l: string }[]) {
      for (const t of [Date.parse(r.f), Date.parse(r.l)]) {
        if (!Number.isFinite(t)) continue;
        const w = bounds.findIndex(([a, b]) => t >= a && t <= b);
        if (w >= 0) mark(r.ip, w);
      }
    }
    // An IP-literal target is its own evidence in every window.
    const self = normalizeIp(target);
    if (self) for (let i = 0; i < windows.length; i++) mark(self.ip, i);

    const untracked = (untrackedStmt.get(target) as { n: number }).n === 1;
    const geo = new Map((geoStmt.all(target) as { ip: string; asn: string | null; country_code: string | null }[]).map((g) => [g.ip, g]));

    for (const [ip, wins] of seen) {
      let state: 'never' | 'present' | 'gone' = 'never';
      for (let i = 0; i < windows.length; i++) {
        const at = windows[i]!.start;
        const push = (kind: Proposed['kind']): void => {
          const g = kind === 'ip_added' ? geo.get(ip) : undefined;
          pending.push({ target, ip, kind, at, new_country_code: g?.country_code ?? null, new_asn: g?.asn ?? null });
          result.proposed++;
        };
        if (wins.has(i)) {
          if (state === 'never') push('ip_added');
          else if (state === 'gone') push('ip_back');
          state = 'present';
        } else if (state === 'present' && scanStatus(NEVER, at, untracked, trackingStart) === 'no') {
          push('ip_gone');
          state = 'gone';
        }
      }
    }
    if (pending.length >= chunk) flush();
  }
  flush();
  return result;
}
