import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, rmSync } from 'node:fs';
import Database from 'better-sqlite3';
import { TARGET_AGG_SQL } from '../src/lib/target-agg.js';

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

describe('TARGET_AGG_SQL versionMatch', () => {
  it('counts distinct non-empty version-match CVEs per target; re-scans and null/empty excluded', () => {
    const db = newDb();
    // host x: 3 distinct version-match CVEs, one re-observed on a later run, plus
    // a null-cve and an empty-cve version-match finding that must not count.
    ins(db, { target: 'x', tool: 'version-match', severity: 'critical', cve: 'CVE-1' });
    ins(db, { target: 'x', tool: 'version-match', severity: 'critical', cve: 'CVE-1', seen_at: '2026-11-11T00:00:00Z' });
    ins(db, { target: 'x', tool: 'version-match', severity: 'high', cve: 'CVE-2' });
    ins(db, { target: 'x', tool: 'version-match', severity: 'medium', cve: 'CVE-3' });
    ins(db, { target: 'x', tool: 'version-match', severity: 'low', cve: null });
    ins(db, { target: 'x', tool: 'version-match', severity: 'low', cve: '' });
    // a confirmed (non version-match) CVE must NOT count toward versionMatch
    ins(db, { target: 'x', tool: 'nuclei', severity: 'critical', cve: 'CVE-9' });
    // host y: no version-match findings at all
    ins(db, { target: 'y', tool: 'nuclei', severity: 'high', cve: 'CVE-7' });

    const agg = db.prepare(TARGET_AGG_SQL).all() as {
      target: string; versionMatch: number; cves: number; findings: number;
    }[];
    const x = agg.find((r) => r.target === 'x');
    const y = agg.find((r) => r.target === 'y');
    expect(x).toBeDefined();
    expect(y).toBeDefined();
    expect(x!.versionMatch).toBe(3); // CVE-1,2,3 distinct; dup + null + '' + nuclei excluded
    expect(y!.versionMatch).toBe(0);
    // sibling columns keep their existing meaning (count rows, not distinct CVEs)
    expect(x!.cves).toBe(5); // CVE-1 x2, CVE-2, CVE-3, CVE-9 non-empty; null/'' excluded
    expect(x!.findings).toBe(7);
  });
});
