import Database from 'better-sqlite3';
import { STICKY_TOOLS, tableExists } from './current-findings.js';

export interface FrozenPair {
  target: string;
  tool: string;
  /** Finding rows of the pair held current (seen_at >= w). */
  rows: number;
  newest: string;
  /** Oldest stamp of the pair that carries a marker. */
  oldestMarker: string;
  /** The pair's rule-3 watermark is '' (every stamp is marked). */
  allMarked: boolean;
}

export interface ToolSummary {
  tool: string;
  pairs: number;
  allMarked: number;
  rows: number;
  oldestMarker: string | null;
  oldestMarkerAgeDays: number | null;
}

export interface FrozenReport {
  tools: ToolSummary[];
  top: FrozenPair[];
}

/** The report never writes: open the DB read-only and require it to exist. */
export function openReadOnly(path: string): Database.Database {
  return new Database(path, { readonly: true, fileMustExist: true });
}

const STICKY = STICKY_TOOLS.map((t) => `'${t}'`).join(',');

/**
 * Raw pairs with no tool_coverage row whose newest stamp carries a marker.
 * Candidates come from the marker stamps (idx_findings_seen, then the tool
 * filter), then every lookup is bounded to one pair (idx_findings_logical on
 * target, tool) or one partial_stamps primary key.
 */
export function frozenPairsSql(coverage: boolean): string {
  const noCoverage = coverage
    ? 'AND NOT EXISTS (SELECT 1 FROM tool_coverage c WHERE c.target = f.target AND c.tool = f.tool)'
    : '';
  const marked = (alias: string) =>
    `EXISTS (SELECT 1 FROM partial_stamps p WHERE p.tool = ${alias}.tool AND p.seen_at = ${alias}.seen_at)`;
  return `
WITH cand AS (
  SELECT DISTINCT f.target, f.tool
  FROM (SELECT DISTINCT tool, seen_at FROM partial_stamps) m
  CROSS JOIN findings f INDEXED BY idx_findings_seen ON f.seen_at = m.seen_at AND f.tool = m.tool
  WHERE f.tool NOT IN (${STICKY}) ${noCoverage}
), nw AS (
  SELECT c.target, c.tool,
         (SELECT MAX(f.seen_at) FROM findings f WHERE f.target = c.target AND f.tool = c.tool) newest
  FROM cand c
), fw AS (
  SELECT target, tool, newest,
         COALESCE((SELECT MAX(f.seen_at) FROM findings f WHERE f.target = nw.target AND f.tool = nw.tool
                   AND NOT ${marked('f')}), '') w
  FROM nw WHERE EXISTS (SELECT 1 FROM partial_stamps p WHERE p.tool = nw.tool AND p.seen_at = nw.newest)
), fz AS (
  SELECT target, tool, newest, w,
         (SELECT MIN(f.seen_at) FROM findings f WHERE f.target = fw.target AND f.tool = fw.tool
          AND f.seen_at > fw.w AND ${marked('f')}) oldest_marker
  FROM fw
)
SELECT target, tool, newest, w, oldest_marker,
       (SELECT COUNT(*) FROM findings f WHERE f.target = fz.target AND f.tool = fz.tool AND f.seen_at >= fz.w) rows
FROM fz`;
}

export function frozenReport(db: Database.Database, top: number, now: Date = new Date()): FrozenReport {
  if (!tableExists(db, 'partial_stamps')) return { tools: [], top: [] };
  const rows = db.prepare(frozenPairsSql(tableExists(db, 'tool_coverage'))).all() as {
    target: string; tool: string; newest: string; w: string; oldest_marker: string; rows: number;
  }[];
  const pairs: FrozenPair[] = rows.map((r) => ({
    target: r.target, tool: r.tool, rows: r.rows, newest: r.newest,
    oldestMarker: r.oldest_marker, allMarked: r.w === '',
  }));
  const by = new Map<string, ToolSummary>();
  for (const p of pairs) {
    const s = by.get(p.tool) ?? { tool: p.tool, pairs: 0, allMarked: 0, rows: 0, oldestMarker: null, oldestMarkerAgeDays: null };
    s.pairs++;
    if (p.allMarked) s.allMarked++;
    s.rows += p.rows;
    if (s.oldestMarker === null || p.oldestMarker < s.oldestMarker) s.oldestMarker = p.oldestMarker;
    by.set(p.tool, s);
  }
  const tools = [...by.values()].sort((a, b) => a.tool.localeCompare(b.tool));
  for (const s of tools) {
    const t = Date.parse(s.oldestMarker!);
    s.oldestMarkerAgeDays = Number.isNaN(t) ? null : Math.max(0, Math.floor((now.getTime() - t) / 86_400_000));
  }
  const biggest = [...pairs]
    .sort((a, b) => b.rows - a.rows || a.target.localeCompare(b.target) || a.tool.localeCompare(b.tool))
    .slice(0, Math.max(0, top));
  return { tools, top: biggest };
}

export function formatText(r: FrozenReport): string {
  if (r.tools.length === 0) return 'frozen pairs: none\n';
  const lines = ['tool\tpairs\tall-marked\trows\toldest-marker\tage-days'];
  for (const t of r.tools) {
    lines.push([t.tool, t.pairs, t.allMarked, t.rows, t.oldestMarker, t.oldestMarkerAgeDays ?? '?'].join('\t'));
  }
  if (r.top.length) {
    lines.push('', 'target\ttool\trows\tnewest\toldest-marker');
    for (const p of r.top) lines.push([p.target, p.tool, p.rows, p.newest, p.oldestMarker].join('\t'));
  }
  return lines.join('\n') + '\n';
}
