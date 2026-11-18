import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, rmSync } from 'node:fs';
import Database from 'better-sqlite3';
import { targetAggSql } from '../src/lib/target-agg.js';

const SCHEMA = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '../src/lib/schema.sql'),
  'utf8',
);

const dbPaths: string[] = [];
function newDb(): Database.Database {
  const p = join(tmpdir(), `target-agg-test-${randomBytes(6).toString('hex')}.db`);
  dbPaths.push(p);
  const db = new Database(p);
  db.exec(SCHEMA);
  return db;
}
function ins(db: Database.Database, f: Record<string, unknown>): void {
  db.prepare(
    `INSERT INTO findings (tool, target, category, severity, title, cve, seen_at)
     VALUES (@tool, @target, @category, @severity, @title, @cve, @seen_at)`,
  ).run({ category: null, severity: null, title: 't', cve: null, seen_at: '2026-11-10T00:00:00Z', ...f });
}
afterEach(() => {
  for (const p of dbPaths.splice(0)) {
    for (const suffix of ['', '-wal', '-shm']) {
      try { rmSync(p + suffix); } catch { /* ignore */ }
    }
  }
});

describe('targetAggSql versionMatch', () => {
  it('counts distinct non-empty version-match CVEs per target; re-scans and null/empty excluded', () => {
    const db = newDb();
    // host x: 3 distinct version-match CVEs, one re-observed on a later run, plus
    // a null-cve and an empty-cve version-match finding that must not count.
    // A rescan re-reports its whole set, so every row is re-inserted at the later stamp.
    for (const seen_at of ['2026-11-10T00:00:00.000Z', '2026-11-11T00:00:00.000Z']) {
      ins(db, { target: 'x', tool: 'version-match', severity: 'critical', cve: 'CVE-1', seen_at });
      ins(db, { target: 'x', tool: 'version-match', severity: 'high', cve: 'CVE-2', seen_at });
      ins(db, { target: 'x', tool: 'version-match', severity: 'medium', cve: 'CVE-3', seen_at });
      ins(db, { target: 'x', tool: 'version-match', severity: 'low', cve: null, seen_at });
      ins(db, { target: 'x', tool: 'version-match', severity: 'low', cve: '', seen_at });
    }
    // a confirmed (non version-match) CVE must NOT count toward versionMatch
    ins(db, { target: 'x', tool: 'nuclei', severity: 'critical', cve: 'CVE-9' });
    // host y: no version-match findings at all
    ins(db, { target: 'y', tool: 'nuclei', severity: 'high', cve: 'CVE-7' });

    const agg = db.prepare(targetAggSql(false)).all() as {
      target: string; versionMatch: number; cves: number; findings: number;
    }[];
    const x = agg.find((r) => r.target === 'x');
    const y = agg.find((r) => r.target === 'y');
    expect(x).toBeDefined();
    expect(y).toBeDefined();
    expect(x!.versionMatch).toBe(3); // CVE-1,2,3 distinct; dup + null + '' + nuclei excluded
    expect(y!.versionMatch).toBe(0);
    // Siblings now count differently from the row counts they replaced (5 and 7):
    // CVE ids are distinct, and the null- and empty-cve rows are one logical finding.
    expect(x!.cves).toBe(4); // CVE-1,2,3,9; null/'' excluded
    expect(x!.findings).toBe(5); // critical, high, medium, low (null and '' share a title) + nuclei
  });
});

type Agg = Record<string, number | string>;
const aggOf = (db: Database.Database, coverage: boolean, target: string): Agg | undefined =>
  (db.prepare(targetAggSql(coverage)).all() as Agg[]).find((r) => r.target === target);
const T1 = '2026-11-10T00:00:00.000Z';
const T2 = '2026-11-11T00:00:00.000Z';
function withCoverage(db: Database.Database, rows: [string, string, string][]): void {
  const p = db.prepare('INSERT INTO tool_coverage (target, tool, seen_at, run_id) VALUES (?, ?, ?, NULL)');
  for (const r of rows) p.run(...r);
}

describe('targetAggSql open findings', () => {
  it('does not count findings a later run of the same tool stopped reporting', () => {
    const db = newDb();
    ins(db, { target: 'x', tool: 'nuclei', severity: 'critical', title: 'old', cve: 'CVE-1', seen_at: T1 });
    ins(db, { target: 'x', tool: 'nuclei', severity: 'high', title: 'kept', cve: 'CVE-2', seen_at: T1 });
    ins(db, { target: 'x', tool: 'nuclei', severity: 'high', title: 'kept', cve: 'CVE-2', seen_at: T2 });
    const x = aggOf(db, false, 'x');
    expect(x).toMatchObject({ critical: 0, high: 1, findings: 1, cves: 1 });
  });

  it('counts a CVE once when two rows carry it', () => {
    const db = newDb();
    ins(db, { target: 'x', tool: 'nuclei', severity: 'high', title: 'a', cve: 'CVE-1' });
    ins(db, { target: 'x', tool: 'nuclei', severity: 'high', title: 'b', cve: 'CVE-1' });
    ins(db, { target: 'x', tool: 'version-match', severity: 'high', title: 'c', cve: 'CVE-1' });
    ins(db, { target: 'x', tool: 'version-match', severity: 'high', title: 'd', cve: 'CVE-1' });
    expect(aggOf(db, false, 'x')).toMatchObject({ high: 4, findings: 4, cves: 1, versionMatch: 1 });
  });

  it('closes a tool\'s counts when coverage is newer than its rows, and only that tool', () => {
    const db = newDb();
    ins(db, { target: 'x', tool: 'version-match', severity: 'critical', title: 'v', cve: 'CVE-1', seen_at: T1 });
    ins(db, { target: 'x', tool: 'nuclei', severity: 'high', title: 'n', cve: 'CVE-2', seen_at: T1 });
    withCoverage(db, [['x', 'version-match', T2]]);
    expect(aggOf(db, true, 'x')).toMatchObject({ critical: 0, high: 1, findings: 1, cves: 1, versionMatch: 0 });
    // the same data read without the coverage table keeps both open (rule 3)
    expect(aggOf(db, false, 'x')).toMatchObject({ critical: 1, high: 1, findings: 2, cves: 2, versionMatch: 1 });
  });

  it('keeps rows at or after the coverage stamp open', () => {
    const db = newDb();
    ins(db, { target: 'x', tool: 'version-match', severity: 'critical', title: 'v', cve: 'CVE-1', seen_at: T2 });
    withCoverage(db, [['x', 'version-match', T2]]);
    expect(aggOf(db, true, 'x')).toMatchObject({ critical: 1, findings: 1, cves: 1, versionMatch: 1 });
  });

  it('counts sticky findings even when coverage is newer', () => {
    const db = newDb();
    ins(db, { target: 'x', tool: 'manual', severity: 'high', title: 'm', cve: 'CVE-5', seen_at: T1 });
    ins(db, { target: 'x', tool: 'synthesize-eol', severity: 'medium', title: 'e', seen_at: T1 });
    withCoverage(db, [['x', 'manual', T2], ['x', 'synthesize-eol', T2]]);
    expect(aggOf(db, true, 'x')).toMatchObject({ high: 1, medium: 1, findings: 2, cves: 1 });
  });

  it('counts a sticky finding seen at two stamps once', () => {
    const db = newDb();
    ins(db, { target: 'x', tool: 'synthesize-eol', severity: 'medium', title: 'e', seen_at: T1 });
    ins(db, { target: 'x', tool: 'synthesize-eol', severity: 'medium', title: 'e', seen_at: T2 });
    expect(aggOf(db, false, 'x')).toMatchObject({ medium: 1, findings: 1 });
  });

  it('runs without the tool_coverage table when coverage is false', () => {
    const db = newDb();
    db.exec('DROP TABLE tool_coverage');
    ins(db, { target: 'x', tool: 'nuclei', severity: 'high', title: 'n', cve: 'CVE-2' });
    expect(aggOf(db, false, 'x')).toMatchObject({ high: 1, findings: 1, cves: 1 });
  });
});
