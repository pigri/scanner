import { describe, it, expect } from 'vitest';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';
import {
  NO_URL,
  backfillRiskLatest,
  upsertRiskLatest,
  refreshRiskLatest,
} from '../src/lib/risk-latest.js';

type Raw = Database.Database;
const addScore = (raw: Raw, target: string, score: number, at: string) =>
  raw.prepare('INSERT INTO risk_scores(target, score, breakdown_json, computed_at) VALUES(?,?,?,?)')
    .run(target, score, '{}', at);
const latest = (raw: Raw, target: string) =>
  raw.prepare('SELECT * FROM risk_latest WHERE target = ?').get(target) as
    { target: string; score: number; created_at: string; updated_at: string } | undefined;
const count = (raw: Raw) => (raw.prepare('SELECT count(*) c FROM risk_latest').get() as { c: number }).c;

describe('schema', () => {
  it('creates risk_latest and its score index', () => {
    const { raw } = openDb(':memory:');
    const names = raw.prepare("SELECT name FROM sqlite_master WHERE tbl_name='risk_latest'").all().map((r: any) => r.name);
    expect(names).toContain('risk_latest');
    expect(names).toContain('idx_risk_latest_score');
  });
});

describe('NO_URL', () => {
  it('filters scheme-prefixed targets', () => {
    const { raw } = openDb(':memory:');
    for (const t of ['a.example.com', 'http://a.example.com', 'https://a.example.com']) addScore(raw, t, 1, '2026-01-01');
    const rows = raw.prepare(`SELECT target FROM risk_scores WHERE ${NO_URL}`).all() as { target: string }[];
    expect(rows.map((r) => r.target)).toEqual(['a.example.com']);
  });
});

describe('backfillRiskLatest', () => {
  it('picks the newest score per target, ties by highest id, and skips URL targets', () => {
    const { raw } = openDb(':memory:');
    addScore(raw, 'a.example.com', 10, '2026-01-01');
    addScore(raw, 'a.example.com', 30, '2026-01-03');
    addScore(raw, 'a.example.com', 20, '2026-01-02');
    addScore(raw, 'b.example.com', 5, '2026-01-01');
    addScore(raw, 'b.example.com', 7, '2026-01-01'); // tie: higher id wins
    addScore(raw, 'https://a.example.com', 99, '2026-01-05');
    backfillRiskLatest(raw);
    expect(count(raw)).toBe(2);
    expect(latest(raw, 'a.example.com')).toMatchObject({ score: 30, updated_at: '2026-01-03', created_at: '2026-01-01' });
    expect(latest(raw, 'b.example.com')?.score).toBe(7);
  });

  it('does nothing on a populated table', () => {
    const { raw } = openDb(':memory:');
    addScore(raw, 'a.example.com', 10, '2026-01-01');
    raw.prepare("INSERT INTO risk_latest(target, score, created_at, updated_at) VALUES('x.example.com', 1, 't', 't')").run();
    backfillRiskLatest(raw);
    expect(count(raw)).toBe(1);
    expect(latest(raw, 'a.example.com')).toBeUndefined();
  });

  it('runs from openDb on a database that has scores but no risk_latest rows', () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rl-')), 'scan.db');
    const first = openDb(file);
    addScore(first.raw, 'a.example.com', 42, '2026-01-01');
    first.raw.exec('DELETE FROM risk_latest');
    first.close();
    const second = openDb(file);
    expect(latest(second.raw, 'a.example.com')?.score).toBe(42);
    second.close();
  });
});

describe('upsertRiskLatest', () => {
  it('keeps created_at and updates score and updated_at', () => {
    const { raw } = openDb(':memory:');
    const up = upsertRiskLatest(raw);
    up.run('a.example.com', 10, '2026-01-01', '2026-01-01');
    up.run('a.example.com', 55, '2026-02-01', '2026-02-01');
    expect(latest(raw, 'a.example.com')).toEqual({
      target: 'a.example.com', score: 55, created_at: '2026-01-01', updated_at: '2026-02-01',
    });
  });

  it('works against the live shape (unique index, no primary key)', () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rl-')), 'live.db');
    const legacy = new Database(file);
    legacy.exec(`
      CREATE TABLE risk_latest(target TEXT, score INT, updated_at TEXT, created_at);
      CREATE UNIQUE INDEX idx_risk_latest_target ON risk_latest(target);
      CREATE INDEX idx_risk_latest_score ON risk_latest(score);
      INSERT INTO risk_latest VALUES('a.example.com', 5, '2026-01-01', '2026-01-01');
    `);
    legacy.close();
    const { raw, close } = openDb(file);
    const sql = (raw.prepare("SELECT sql FROM sqlite_master WHERE name='risk_latest'").get() as { sql: string }).sql;
    expect(sql).not.toMatch(/PRIMARY KEY/i);
    const indexes = raw.prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='risk_latest'").all();
    expect(indexes).toHaveLength(2);
    const up = upsertRiskLatest(raw);
    up.run('a.example.com', 9, '2026-03-01', '2026-03-01');
    up.run('b.example.com', 3, '2026-03-01', '2026-03-01');
    expect(latest(raw, 'a.example.com')).toMatchObject({ score: 9, updated_at: '2026-03-01', created_at: '2026-01-01' });
    expect(count(raw)).toBe(2);
    close();
  });
});

describe('refreshRiskLatest', () => {
  it('falls back to the previous score when the newest is gone', () => {
    const { raw } = openDb(':memory:');
    addScore(raw, 'a.example.com', 10, '2026-01-01');
    const newest = addScore(raw, 'a.example.com', 50, '2026-01-02').lastInsertRowid;
    backfillRiskLatest(raw);
    expect(latest(raw, 'a.example.com')?.score).toBe(50);
    raw.prepare('DELETE FROM risk_scores WHERE id = ?').run(newest);
    refreshRiskLatest(raw, ['a.example.com']);
    expect(latest(raw, 'a.example.com')).toMatchObject({ score: 10, updated_at: '2026-01-01' });
  });

  it('deletes the row when nothing remains', () => {
    const { raw } = openDb(':memory:');
    addScore(raw, 'a.example.com', 10, '2026-01-01');
    backfillRiskLatest(raw);
    raw.exec('DELETE FROM risk_scores');
    refreshRiskLatest(raw, ['a.example.com']);
    expect(latest(raw, 'a.example.com')).toBeUndefined();
  });
});
