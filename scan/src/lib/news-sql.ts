// Shared SQL for the UI's News view, so the server (src/ui.ts) and the query-plan
// test (test/news-sql.test.ts) use the exact same string — no drift between what
// ships and what the test pins.
//
// A "logical finding" is keyed by (target, tool, severity, category, title), with
// first_seen = MIN(seen_at) over the group, so re-scans that re-observe the same
// issue don't re-report it as new. idx_findings_logical (schema.sql) is a covering
// index on exactly these columns + seen_at + cve, so this aggregation is served in
// index order with no temp B-tree and no table reads.
export const NEWS_FIRSTS_SQL =
  `SELECT target, tool, severity, category, title, cve, MIN(seen_at) first_seen
   FROM findings GROUP BY target, tool, severity, category, title`;
