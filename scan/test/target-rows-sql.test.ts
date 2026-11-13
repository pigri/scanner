import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, rmSync } from 'node:fs';
import Database from 'better-sqlite3';
import { TARGET_ROWS_SQL, riskLatestMissingMessage } from '../src/lib/target-rows-sql.js';

const SCHEMA = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '../src/lib/schema.sql'),
  'utf8',
);

const dbPaths: string[] = [];
function newDb(): Database.Database {
  const p = join(tmpdir(), `target-rows-test-${randomBytes(6).toString('hex')}.db`);
  dbPaths.push(p);
  const db = new Database(p);
  db.exec(SCHEMA);
  return db;
}
afterEach(() => {
  for (const p of dbPaths.splice(0)) {
    for (const suffix of ['', '-wal', '-shm']) {
      try { rmSync(p + suffix); } catch { /* ignore */ }
    }
  }
});

function seedFinding(db: Database.Database, target: string, cve: string): void {
  db.prepare(
    `INSERT INTO findings (tool, target, severity, title, cve, seen_at)
     VALUES ('version-match', ?, 'high', 't', ?, '2026-11-10T00:00:00Z')`,
  ).run(target, cve);
}

describe('TARGET_ROWS_SQL', () => {
  it('reads score and times from risk_latest and carries versionMatch through', () => {
    const db = newDb();
    seedFinding(db, 'a.example', 'CVE-2024-0001');
    seedFinding(db, 'a.example', 'CVE-2024-0002');
    // risk_scores holds an older, different score: it must not be read.
    db.prepare(`INSERT INTO risk_scores (target, score, breakdown_json, computed_at) VALUES ('a.example', 5, '{}', '2026-11-01T00:00:00Z')`).run();
    db.prepare(
      `INSERT INTO risk_latest (target, score, created_at, updated_at) VALUES ('a.example', 77, '2026-11-01T00:00:00Z', '2026-11-09T00:00:00Z')`,
    ).run();
    const rows = db.prepare(TARGET_ROWS_SQL).all() as Record<string, unknown>[];
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      target: 'a.example',
      score: 77,
      created_at: '2026-11-01T00:00:00Z',
      updated_at: '2026-11-09T00:00:00Z',
      versionMatch: 2,
      findings: 2,
      cves: 2,
      high: 2,
      active: 1,
    });
  });

  it('excludes URL targets and defaults the aggregate columns to 0', () => {
    const db = newDb();
    // URL targets only reach risk_scores/findings; writers never put them in risk_latest.
    db.prepare(`INSERT INTO risk_latest (target, score, created_at, updated_at) VALUES ('b.example', 1, 'c', 'u')`).run();
    const sc = db.prepare(`INSERT INTO risk_scores (target, score, breakdown_json, computed_at) VALUES (?, 1, '{}', 'c')`);
    const fd = db.prepare(`INSERT INTO findings (tool, target, category, severity, title, seen_at) VALUES ('nuclei', ?, 'x', 'high', 't', 's')`);
    for (const u of ['http://b.example', 'https://b.example']) { sc.run(u); fd.run(u); }
    const rows = db.prepare(TARGET_ROWS_SQL).all() as { target: string; versionMatch: number; findings: number }[];
    expect(rows.map((r) => r.target)).toEqual(['b.example']);
    expect(rows[0]).toMatchObject({ versionMatch: 0, findings: 0 });
  });
});

describe('riskLatestMissingMessage', () => {
  it('is null when the table exists', () => {
    expect(riskLatestMissingMessage(true)).toBeNull();
  });
  it('tells the operator to open the DB with a scan tool when it is missing', () => {
    expect(riskLatestMissingMessage(false)).toMatch(/risk_latest.*missing.*open the DB once with any scan tool/s);
  });
});
