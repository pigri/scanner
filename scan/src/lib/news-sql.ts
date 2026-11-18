import { NUCLEI_FAMILY_SQL, riskToolKeySql } from './nuclei-tool.js';

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
//
// The two nuclei passes (lib/nuclei-tool.ts) are one tool here: the family
// branch groups them without the tool column and reports 'nuclei', so a match
// both passes found is one row with the earliest first_seen. Its GROUP BY
// spans two tools, so it needs one temp B-tree; the plain branch keeps the
// index order.
export const NEWS_FIRSTS_SQL =
  `SELECT target, tool, severity, category, title, cve, MIN(seen_at) first_seen
   FROM findings WHERE +tool NOT IN ${NUCLEI_FAMILY_SQL} GROUP BY target, tool, severity, category, title
   UNION ALL
   SELECT target, 'nuclei' tool, severity, category, title, MAX(cve) cve, MIN(seen_at) first_seen
   FROM findings WHERE +tool IN ${NUCLEI_FAMILY_SQL} GROUP BY target, severity, category, title`;

export interface NewSinceFilter {
  severity?: boolean;
  tool?: boolean;
}

/**
 * Rows whose (tool, target, category, title) was first seen at or after `?`
 * (the first parameter), then `severity` and `tool` parameters when asked for.
 * Both nuclei passes count as one tool, so a URL-pass re-observation of a
 * finding the host pass already had is not new. A `tool` filter matches the
 * row's own tool name.
 */
export function newSinceSql(f: NewSinceFilter): string {
  const key = riskToolKeySql('tool');
  return `WITH firsts AS (
        SELECT ${key} tk, target, COALESCE(category,'') cat, title, MIN(seen_at) first_seen
        FROM findings GROUP BY tk, target, cat, title
      )
      SELECT f.seen_at, f.tool, f.target, f.severity, f.title, f.cve
      FROM findings f
      JOIN firsts fi ON fi.tk = ${riskToolKeySql('f.tool')} AND fi.target = f.target
                    AND COALESCE(f.category,'') = fi.cat AND fi.title = f.title
                    AND fi.first_seen = f.seen_at
      WHERE fi.first_seen >= ?
      ${f.severity ? 'AND f.severity = ?' : ''}
      ${f.tool ? 'AND f.tool = ?' : ''}
      ORDER BY CASE f.severity
        WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
        f.seen_at DESC`;
}

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
