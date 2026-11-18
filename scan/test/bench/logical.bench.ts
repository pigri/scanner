// Reader cost of folding the two nuclei passes into one logical finding.
//   BENCH_DB=/home/pigri/tmp/bench-scan-<x>.db npx vitest bench test/bench/logical.bench.ts
// BENCH_DB must be a COPY of a scan database whose basename starts with
// `bench-`: the file is read, and the second suite adds rows to it.
// The `before` queries are the SQL as it was before the change, inlined.
import { describe, bench, afterAll } from 'vitest';
import path from 'node:path';
import Database from 'better-sqlite3';
import { currentFindingsSelect, currentRowsFrom, tableExists, watermarkSelect } from '../../src/lib/current-findings.js';
import { buildNewsSql, newSinceSql } from '../../src/lib/news-sql.js';
import { targetAggSql } from '../../src/lib/target-agg.js';

const dbPath = process.env.BENCH_DB;
const enabled = !!dbPath && path.basename(dbPath).startsWith('bench-');
if (dbPath && !enabled) throw new Error(`BENCH_DB basename must start with "bench-": ${dbPath}`);

const SAMPLES = { iterations: 10, warmupIterations: 1, time: 1, warmupTime: 1 };

const NEWS_FIRSTS_BEFORE =
  `SELECT target, tool, severity, category, title, cve, MIN(seen_at) first_seen
   FROM findings GROUP BY target, tool, severity, category, title`;
const NEWS_ORDER = `ORDER BY first_seen DESC,
  CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
  LIMIT 800`;
const newsRowsBefore = `SELECT * FROM (${NEWS_FIRSTS_BEFORE}) ${NEWS_ORDER}`;
const newsDaysBefore = `SELECT substr(first_seen,1,10) day, COUNT(*) c FROM (${NEWS_FIRSTS_BEFORE}) GROUP BY day ORDER BY day DESC`;
const newSinceBefore = `WITH firsts AS (
    SELECT tool, target, COALESCE(category,'') cat, title, MIN(seen_at) first_seen
    FROM findings GROUP BY tool, target, cat, title
  )
  SELECT f.seen_at, f.tool, f.target, f.severity, f.title, f.cve
  FROM findings f
  JOIN firsts fi ON fi.tool = f.tool AND fi.target = f.target
                AND COALESCE(f.category,'') = fi.cat AND fi.title = f.title
                AND fi.first_seen = f.seen_at
  WHERE fi.first_seen >= ?
  ORDER BY CASE f.severity
    WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
    f.seen_at DESC`;

function findingsBefore(coverage: boolean): string {
  return `WITH logical AS MATERIALIZED (
         SELECT target, tool, severity, category, title, MAX(cve) cve,
                MIN(seen_at) first_seen, MAX(seen_at) last_seen, COUNT(*) occ
         FROM findings GROUP BY target, tool, severity, category, title),
       wm AS MATERIALIZED (${watermarkSelect({ coverage })})
       SELECT l.target, l.tool, l.severity, l.category, l.title, l.cve,
              l.first_seen, l.last_seen, l.occ,
              CASE WHEN l.last_seen < wm.w THEN 1 ELSE 0 END resolved
       FROM logical l JOIN wm ON wm.target = l.target AND wm.tool = l.tool`;
}
function targetAggBefore(coverage: boolean): string {
  return `WITH wm AS MATERIALIZED (${watermarkSelect({ coverage })}),
     sev AS MATERIALIZED (
       SELECT l.target target,
         SUM(l.severity='critical') critical, SUM(l.severity='high') high,
         SUM(l.severity='medium') medium, SUM(l.severity='low') low, SUM(l.severity='info') info,
         COUNT(*) findings
       FROM (SELECT target, tool, severity, MAX(seen_at) last_seen FROM findings
         GROUP BY target, tool, severity, category, title) l
       JOIN wm ON wm.target = l.target AND wm.tool = l.tool AND l.last_seen >= wm.w GROUP BY l.target),
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

// Opened at collection time: benches run in definition order, and the cloned
// suite adds its rows only when its first bench starts.
const db = enabled ? new Database(dbPath!) : (undefined as unknown as Database.Database);
const coverage = enabled ? tableExists(db, 'tool_coverage') : false;
const since = enabled
  ? (db.prepare('SELECT MAX(seen_at) m FROM findings').get() as { m: string }).m.slice(0, 10) + 'T00:00:00Z'
  : '';
const nucleiCounts = () =>
  JSON.stringify(db.prepare("SELECT tool, COUNT(*) c FROM findings WHERE tool IN ('nuclei','nuclei-url') GROUP BY tool").all());

let cloned = false;
function cloneHalf(): void {
  if (cloned) return;
  cloned = true;
  console.log('rows before clone', nucleiCounts());
  db.exec(`INSERT INTO findings (tool, target, category, severity, title, cve, matched_at, meta_json, seen_at, run_id, needs_review)
           SELECT 'nuclei-url', target, category, severity, title, cve, matched_at, meta_json, seen_at, run_id, needs_review
           FROM findings WHERE tool = 'nuclei' AND id % 2 = 0`);
  console.log('rows after clone', nucleiCounts());
}

function registerCases(label: string, setup?: () => void): void {
  const pairs: [string, () => string, () => string, unknown[]][] = [
    ['findings list', () => findingsBefore(coverage), () => currentFindingsSelect({ coverage }), []],
    ['target counts', () => targetAggBefore(coverage), () => targetAggSql(coverage), []],
    ['news rows', () => newsRowsBefore, () => buildNewsSql({}).rows.sql, []],
    ['news days', () => newsDaysBefore, () => buildNewsSql({}).days.sql, []],
    ['new since', () => newSinceBefore, () => newSinceSql({}), [since]],
  ];
  for (const [name, before, after, params] of pairs) {
    const opts = setup ? { ...SAMPLES, setup } : SAMPLES;
    bench(`${label} / ${name} / before`, () => { db.prepare(before()).all(...params); }, opts);
    bench(`${label} / ${name} / after`, () => { db.prepare(after()).all(...params); }, opts);
  }
}

describe.skipIf(!enabled)('as is', () => registerCases('as is'));
describe.skipIf(!enabled)('half the nuclei rows cloned as nuclei-url', () => registerCases('cloned', cloneHalf));
afterAll(() => db?.close());
