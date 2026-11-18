import type Database from 'better-sqlite3';

/** Tools whose findings are asserted by hand or by synthesis and never close. */
export const STICKY_TOOLS = ['synthesize-eol', 'manual', 'manual-triage'] as const;

export function tableExists(db: Database.Database, name: string): boolean {
  return !!db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
    .get(name);
}

export interface CurrentFindingsOpts {
  /** Read tool_coverage for the watermark. Not implemented yet; must be false. */
  coverage: boolean;
  /** Named SQL parameter (e.g. '@t') that limits the result to one target. */
  targetParam?: string;
}

function assertNoCoverage(opts: CurrentFindingsOpts): void {
  if (opts.coverage) throw new Error('tool_coverage watermark is not implemented');
}

/**
 * SQL yielding one row per (target, tool) as `target, tool, w`. A row is
 * current when `seen_at >= w`. The watermark is the newest `seen_at` of the
 * pair, so a run that reports nothing leaves older rows open until the tool
 * reports something else for that target.
 */
export function watermarkSelect(opts: CurrentFindingsOpts): string {
  assertNoCoverage(opts);
  const where = opts.targetParam ? ` WHERE target = ${opts.targetParam}` : '';
  return `SELECT target, tool, MAX(seen_at) AS w FROM findings${where} GROUP BY target, tool`;
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
