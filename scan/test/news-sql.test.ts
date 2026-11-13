import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, rmSync } from 'node:fs';
import Database from 'better-sqlite3';
import { NEWS_FIRSTS_SQL, buildNewsSql } from '../src/lib/news-sql.js';

const SCHEMA = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '../src/lib/schema.sql'),
  'utf8',
);

// The planner needs a real file DB with the real schema+indexes to reproduce
// the production query plan; :memory: and tiny tables can mislead it.
const dbPaths: string[] = [];
function newDb(): Database.Database {
  const p = join(tmpdir(), `news-sql-test-${randomBytes(6).toString('hex')}.db`);
  dbPaths.push(p);
  const db = new Database(p);
  db.exec(SCHEMA);
  return db;
}
function insertFinding(db: Database.Database, f: Record<string, unknown>): void {
  db.prepare(
    `INSERT INTO findings (tool, target, category, severity, title, cve, seen_at)
     VALUES (@tool, @target, @category, @severity, @title, @cve, @seen_at)`,
  ).run({ cve: null, ...f });
}

afterEach(() => {
  for (const p of dbPaths.splice(0)) {
    for (const suffix of ['', '-wal', '-shm']) {
      try { rmSync(p + suffix); } catch { /* ignore */ }
    }
  }
});

describe('news aggregation query plan', () => {
  it('is served by a covering index with no temp B-tree', () => {
    const db = newDb();
    // A representative spread: many logical groups, each re-observed a few times,
    // so the planner faces a real GROUP BY + MIN, not a trivial one.
    for (let g = 0; g < 80; g++) {
      for (let seen = 0; seen < 4; seen++) {
        insertFinding(db, {
          tool: 'nuclei',
          target: `host${g % 20}.example.com`,
          category: `cat${g % 5}`,
          severity: ['critical', 'high', 'medium', 'low', 'info'][g % 5],
          title: `finding ${g}`,
          seen_at: `2026-10-${String(1 + (seen % 28)).padStart(2, '0')}T00:00:00Z`,
        });
      }
    }

    const plan = (db.prepare(`EXPLAIN QUERY PLAN ${NEWS_FIRSTS_SQL}`).all() as { detail: string }[])
      .map((r) => r.detail)
      .join('\n');
    db.close();

    // The whole point: aggregation reads the covering index in order, so there is
    // no temp B-tree sort and no table lookup. Dropping the index or breaking its
    // coverage reintroduces the temp B-tree and fails here.
    expect(plan).toContain('idx_findings_logical');
    expect(plan).toContain('COVERING INDEX');
    expect(plan).not.toContain('TEMP B-TREE');
  });
});

describe('news aggregation results', () => {
  it('collapses one logical finding to its MIN(seen_at) and keeps distinct ones separate', () => {
    const db = newDb();
    const key = { tool: 'nuclei', target: 'a.example.com', category: 'cve', severity: 'high', title: 'CVE-2021-1 on a' };
    insertFinding(db, { ...key, seen_at: '2026-10-10T00:00:00Z' });
    insertFinding(db, { ...key, seen_at: '2026-10-05T00:00:00Z' }); // earlier re-observation
    insertFinding(db, { tool: 'nuclei', target: 'b.example.com', category: 'cve', severity: 'low', title: 'other', seen_at: '2026-10-07T00:00:00Z' });

    const rows = db
      .prepare(`${NEWS_FIRSTS_SQL} ORDER BY target`)
      .all() as { target: string; first_seen: string }[];
    db.close();

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ target: 'a.example.com', first_seen: '2026-10-05T00:00:00Z' });
    expect(rows[1]).toMatchObject({ target: 'b.example.com', first_seen: '2026-10-07T00:00:00Z' });
  });
});

// Live DB has sqlite_stat1; without ANALYZE the planner can pick differently.
// Skewed severities (mostly info) and many groups make the stats realistic.
function seededDb(): Database.Database {
  const db = newDb();
  const sevs = ['info', 'info', 'info', 'info', 'low', 'low', 'medium', 'high', 'critical'];
  const ins = db.prepare(
    `INSERT INTO findings (tool, target, category, severity, title, cve, seen_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  db.transaction(() => {
    for (let g = 0; g < 3000; g++) {
      for (let seen = 0; seen < 3; seen++) {
        ins.run(
          g % 3 ? 'nuclei' : 'httpx',
          `host${g % 400}.example.com`,
          `cat${g % 7}`,
          sevs[g % sevs.length],
          `finding ${g}`,
          g % 11 ? null : `CVE-2021-${g}`,
          `2026-10-${String(1 + ((g + seen) % 28)).padStart(2, '0')}T00:00:00Z`,
        );
      }
    }
  })();
  db.exec('ANALYZE');
  return db;
}
const planOf = (db: Database.Database, sql: string, params: unknown[] = []): string =>
  (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...params) as { detail: string }[])
    .map((r) => r.detail)
    .join('\n');

describe('buildNewsSql query plans', () => {
  const cases: [string, Parameters<typeof buildNewsSql>[0]][] = [
    ['unfiltered', {}],
    ['severity-filtered', { severity: 'high' }],
    ['severity info', { severity: 'info' }],
    ['day-filtered', { day: '2026-10-05' }],
    ['search-filtered', { search: 'host1' }],
    ['all filters', { day: '2026-10-05', severity: 'low', search: 'host1' }],
  ];
  for (const [name, filter] of cases) {
    it(`${name}: inner grouping uses the covering index, no temp B-tree`, () => {
      const db = seededDb();
      const q = buildNewsSql(filter).rows;
      const plan = planOf(db, q.sql, q.params);
      db.close();
      expect(plan).toContain('COVERING INDEX idx_findings_logical');
      expect(plan).not.toContain('idx_findings_severity');
      expect(plan).not.toContain('TEMP B-TREE FOR GROUP BY');
    });
  }

  it("days query's inner scan uses the covering index", () => {
    const db = seededDb();
    const plan = planOf(db, buildNewsSql({}).days.sql);
    db.close();
    expect(plan).toContain('COVERING INDEX idx_findings_logical');
    expect(plan).not.toMatch(/SCAN findings(?! USING)/);
  });

  it('passes params in clause order and filters severity to exact matches', () => {
    const db = seededDb();
    const q = buildNewsSql({ day: '2026-10-05', severity: 'high', search: 'host1' }).rows;
    expect(q.params).toEqual(['2026-10-05', 'high', '%host1%', '%host1%', '%host1%']);
    const rows = db.prepare(q.sql).all(...q.params) as { severity: string; first_seen: string }[];
    db.close();
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) {
      expect(r.severity).toBe('high');
      expect(r.first_seen.slice(0, 10)).toBe('2026-10-05');
    }
  });
});
