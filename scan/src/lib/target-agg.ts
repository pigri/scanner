// Shared per-target findings aggregate for the Targets ("hosts") list, so
// src/ui.ts and test/target-agg.test.ts use one SQL string (the news-sql.ts
// precedent — no drift). It runs standalone and interpolates into the `agg`
// CTE of targetRowsSql().
//
// Counts follow the one open/resolved rule in current-findings.ts. The severity
// columns and `findings` count OPEN logical findings. `cves` counts DISTINCT
// non-empty CVE ids among current rows, and `versionMatch` the distinct ones
// from `version-match` (the scorer's versionMatchCves set, lib/risk.ts).
import { currentFindingsSelect, watermarkSelect } from './current-findings.js';

/** `coverage` is tableExists(db, 'tool_coverage') at query time. */
export function targetAggSql(coverage: boolean): string {
  return `WITH sev AS MATERIALIZED (
       SELECT target,
         SUM(severity='critical') critical, SUM(severity='high') high,
         SUM(severity='medium') medium, SUM(severity='low') low, SUM(severity='info') info,
         COUNT(*) findings
       FROM (${currentFindingsSelect({ coverage })}) WHERE resolved = 0 GROUP BY target),
     cv AS MATERIALIZED (
       SELECT f.target,
         COUNT(DISTINCT CASE WHEN f.cve IS NOT NULL AND f.cve!='' THEN f.cve END) cves,
         COUNT(DISTINCT CASE WHEN f.tool='version-match' AND f.cve IS NOT NULL AND f.cve!='' THEN f.cve END) versionMatch
       FROM findings f
       JOIN (${watermarkSelect({ coverage })}) wm ON wm.target = f.target AND wm.tool = f.tool
       WHERE f.seen_at >= wm.w GROUP BY f.target)
     SELECT sev.target target, sev.critical critical, sev.high high, sev.medium medium,
       sev.low low, sev.info info, sev.findings findings,
       COALESCE(cv.cves,0) cves, COALESCE(cv.versionMatch,0) versionMatch
     FROM sev LEFT JOIN cv ON cv.target = sev.target`;
}
