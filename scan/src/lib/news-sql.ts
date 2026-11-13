// Shared SQL for the UI's News view, so the server (src/ui.ts) and the query-plan
// test (test/news-sql.test.ts) use the exact same string — no drift between what
// ships and what the test pins.
//
// A "logical finding" is keyed by (target, tool, severity, category, title), with
// first_seen = MIN(seen_at) over the group, so re-scans that re-observe the same
// issue don't re-report it as new. idx_findings_logical (schema.sql) is a covering
// index on exactly these columns + seen_at + cve, so the inner aggregation is
// served in index order: no temp B-tree for the GROUP BY and no table reads.
// (The outer ORDER BY / GROUP BY day over the aggregated rows still sorts.)
export const NEWS_FIRSTS_SQL =
  `SELECT target, tool, severity, category, title, cve, MIN(seen_at) first_seen
   FROM findings GROUP BY target, tool, severity, category, title`;


export interface NewsFilter {
  /** Validated YYYY-MM-DD, or empty. */
  day?: string;
  /** Validated severity, or empty. */
  severity?: string;
  search?: string;
}

export interface NewsSql {
  rows: { sql: string; params: unknown[] };
  days: { sql: string };
}

// Filters sit on the outer query over the aggregated subquery. A bare
// `severity = ?` is pushed down into the subquery, where the planner then picks
// idx_findings_severity and a temp B-tree instead of the covering index; the
// unary plus on the column blocks that (same result for TEXT).
export function buildNewsSql(f: NewsFilter): NewsSql {
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (f.day) {
    clauses.push(`substr(first_seen,1,10) = ?`);
    params.push(f.day);
  }
  if (f.severity) {
    clauses.push('+severity = ?');
    params.push(f.severity);
  }
  if (f.search) {
    clauses.push('(target LIKE ? OR title LIKE ? OR cve LIKE ?)');
    params.push(`%${f.search}%`, `%${f.search}%`, `%${f.search}%`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  return {
    rows: {
      sql: `SELECT * FROM (${NEWS_FIRSTS_SQL}) ${where}
         ORDER BY first_seen DESC,
           CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 ELSE 4 END
         LIMIT 800`,
      params,
    },
    days: {
      sql: `SELECT substr(first_seen,1,10) day, COUNT(*) c FROM (${NEWS_FIRSTS_SQL}) GROUP BY day ORDER BY day DESC`,
    },
  };
}
