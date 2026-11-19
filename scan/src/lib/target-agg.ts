// Shared per-target findings aggregate for the Targets ("hosts") list, so
// src/ui.ts and test/target-agg.test.ts use one SQL string (the news-sql.ts
// precedent — no drift). It runs standalone and interpolates into the `agg`
// CTE of targetRowsSql().
//
// Counts follow the one open/resolved rule in current-findings.ts. The severity
// columns and `findings` count OPEN logical findings. `cves` counts DISTINCT
// non-empty CVE ids among current rows, and `versionMatch` the distinct ones
// from `version-match` (the scorer's versionMatchCves set, lib/risk.ts).
import { currentRowsFrom, openLogicalFrom, watermarkSelect, type FindingsRuleOpts } from './current-findings.js';

/** `rule` is findingsRuleOpts(db) at query time. */
export function targetAggSql(rule: FindingsRuleOpts): string {
  return `WITH wm AS MATERIALIZED (${watermarkSelect(rule)}),
     sev AS MATERIALIZED (
       SELECT l.target target,
         SUM(l.severity='critical') critical, SUM(l.severity='high') high,
         SUM(l.severity='medium') medium, SUM(l.severity='low') low, SUM(l.severity='info') info,
         COUNT(*) findings
       FROM ${openLogicalFrom('wm')} GROUP BY l.target),
     cv AS MATERIALIZED (
       SELECT f.target target,
         COUNT(DISTINCT f.cve) cves,
         COUNT(DISTINCT CASE WHEN f.tool='version-match' THEN f.cve END) versionMatch
       FROM ${currentRowsFrom('wm')}
       WHERE f.cve IS NOT NULL AND f.cve!='' GROUP BY f.target)
     SELECT sev.target target, sev.critical critical, sev.high high, sev.medium medium,
       sev.low low, sev.info info, sev.findings findings,
       COALESCE(cv.cves,0) cves, COALESCE(cv.versionMatch,0) versionMatch
     FROM sev LEFT JOIN cv ON cv.target = sev.target`;
}
