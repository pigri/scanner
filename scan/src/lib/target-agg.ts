// Shared per-target findings aggregate for the Targets ("hosts") list, so
// src/ui.ts and test/target-agg.test.ts use one SQL string (the news-sql.ts
// precedent — no drift). It runs standalone (SELECT ... FROM findings GROUP BY
// target) and interpolates into the `agg` CTE of targetRows().
//
// `versionMatch` counts DISTINCT non-empty CVEs from `version-match` findings
// (banner-inferred CVEs), matching the scorer's definition in lib/risk.ts (the
// versionMatchCves set). The severity tallies and `cves` keep their existing
// meaning (row counts, not distinct), consistent with the sibling columns.
export const TARGET_AGG_SQL =
  `SELECT target,
     SUM(severity='critical') critical, SUM(severity='high') high,
     SUM(severity='medium') medium, SUM(severity='low') low, SUM(severity='info') info,
     COUNT(*) findings,
     SUM(CASE WHEN cve IS NOT NULL AND cve!='' THEN 1 ELSE 0 END) cves,
     COUNT(DISTINCT CASE WHEN tool='version-match' AND cve IS NOT NULL AND cve!='' THEN cve END) versionMatch
   FROM findings GROUP BY target`;
