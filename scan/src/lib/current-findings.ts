import type Database from 'better-sqlite3';

/** Tools whose findings are asserted by hand or by synthesis and never close. */
export const STICKY_TOOLS = ['synthesize-eol', 'manual', 'manual-triage'] as const;

export function tableExists(db: Database.Database, name: string): boolean {
  return !!db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
    .get(name);
}

export interface CurrentFindingsOpts {
  /** Join tool_coverage for the watermark. Callers get it from findingsRuleOpts(db). */
  coverage: boolean;
  /** Skip rows of partial runs when picking the watermark. Callers get it from findingsRuleOpts(db). */
  partial: boolean;
  /** Named SQL parameter (e.g. '@t') that limits the result to one target. */
  targetParam?: string;
}

/**
 * Rule 3's newest stamp when partial runs are skipped: t.tmax if no partial run
 * wrote it, else the newest stamp of the pair that carries no marker, else ''
 * (every row of the pair is partial, so all stay current).
 */
const PARTIAL_TMAX = `CASE WHEN NOT EXISTS (SELECT 1 FROM partial_stamps p WHERE p.tool = t.tool AND p.seen_at = t.tmax)
              THEN t.tmax
              ELSE COALESCE((SELECT MAX(f.seen_at) FROM findings f WHERE f.target = t.target AND f.tool = t.tool
                             AND NOT EXISTS (SELECT 1 FROM partial_stamps p WHERE p.tool = f.tool AND p.seen_at = f.seen_at)), '') END`;

/** The options every reader of the closing rule passes, probed at query time. */
export type FindingsRuleOpts = Omit<CurrentFindingsOpts, 'targetParam'>;

export function findingsRuleOpts(db: Database.Database): FindingsRuleOpts {
  return { coverage: tableExists(db, 'tool_coverage'), partial: tableExists(db, 'partial_stamps') };
}

/**
 * SQL yielding one row per (target, tool) as `target, tool, w`. A row is
 * current when `seen_at >= w`. The watermark is '' for sticky tools (never
 * resolved), else the tool_coverage stamp when one exists, else the newest
 * `seen_at` of the pair that no partial run wrote (with `partial`), so a run
 * that reports nothing leaves older rows open until the tool reports something
 * else for that target.
 */
export function watermarkSelect(opts: CurrentFindingsOpts): string {
  const where = opts.targetParam ? ` WHERE target = ${opts.targetParam}` : '';
  const sticky = STICKY_TOOLS.map((t) => `'${t}'`).join(',');
  const join = opts.coverage
    ? ' LEFT JOIN tool_coverage c ON c.target = t.target AND c.tool = t.tool'
    : '';
  const tmax = opts.partial ? PARTIAL_TMAX : 't.tmax';
  const mark = opts.coverage ? `COALESCE(c.seen_at, ${tmax})` : tmax;
  return `SELECT t.target, t.tool,
         CASE WHEN t.tool IN (${sticky}) THEN '' ELSE ${mark} END AS w
         FROM (SELECT target, tool, MAX(seen_at) tmax FROM findings${where} GROUP BY target, tool) t${join}`;
}

/**
 * SQL for logical findings: every sighting of the same (target, tool, severity,
 * category, title) collapsed to one row with first/last seen and count.
 * `resolved` is 1 when last_seen predates the pair's watermark, else 0.
 */
export function currentFindingsSelect(opts: CurrentFindingsOpts): string {
  const where = opts.targetParam ? ` WHERE target = ${opts.targetParam}` : '';
  const materialized = opts.targetParam ? '' : ' MATERIALIZED';
  return `WITH logical AS${materialized} (
         SELECT target, tool, severity, category, title, MAX(cve) cve,
                MIN(seen_at) first_seen, MAX(seen_at) last_seen, COUNT(*) occ
         FROM findings${where} GROUP BY target, tool, severity, category, title),
       wm AS${materialized} (${watermarkSelect(opts)})
       SELECT l.target, l.tool, l.severity, l.category, l.title, l.cve,
              l.first_seen, l.last_seen, l.occ,
              CASE WHEN l.last_seen < wm.w THEN 1 ELSE 0 END resolved
       FROM logical l JOIN wm ON wm.target = l.target AND wm.tool = l.tool`;
}

/**
 * SQL for the raw rows a scorer reads: `target, tool, severity, title, cve,
 * needs_review` of every finding row with `seen_at >= w`. Filters on the raw
 * target, so call it before any identity folding.
 */
export function currentFindingRowsSelect(opts: CurrentFindingsOpts): string {
  return `WITH wm AS MATERIALIZED (${watermarkSelect(opts)})
       SELECT f.target, f.tool, f.severity, f.title, f.cve, f.needs_review
       FROM findings f JOIN wm ON wm.target = f.target AND wm.tool = f.tool
       WHERE f.seen_at >= wm.w`;
}

/**
 * FROM clause over raw finding rows `f` that are current under an existing
 * watermark CTE `wm` (columns target, tool, w), so one watermark scan can serve
 * several readers. Callers add their own WHERE with AND.
 */
export function currentRowsFrom(wm: string): string {
  return `findings f JOIN ${wm} ON ${wm}.target = f.target AND ${wm}.tool = f.tool AND f.seen_at >= ${wm}.w`;
}

/**
 * FROM clause over logical findings `l` (target, severity) that are open under
 * the watermark CTE `wm`: last_seen >= w.
 */
export function openLogicalFrom(wm: string): string {
  return `(SELECT target, tool, severity, MAX(seen_at) last_seen FROM findings
         GROUP BY target, tool, severity, category, title) l
       JOIN ${wm} ON ${wm}.target = l.target AND ${wm}.tool = l.tool AND l.last_seen >= ${wm}.w`;
}
