import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDb } from '../src/lib/db.js';

const script = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'requeue-score-changed.mjs');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

type Score = [target: string, score: number];

function setup(runs: Score[][]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'requeue-'));
  dirs.push(dir);
  const dbPath = path.join(dir, 'scan.db');
  const db = openDb(dbPath);
  runs.forEach((rows, i) => {
    const at = `2026-01-0${i + 1}T00:00:00.000Z`;
    const runId = db.startRun('risk', {}, at);
    const ins = db.raw.prepare('INSERT INTO risk_scores(target, score, breakdown_json, computed_at, run_id) VALUES(?, ?, ?, ?, ?)');
    for (const [t, s] of rows) ins.run(t, s, '{}', at, runId);
  });
  db.close();
  return dbPath;
}

function requeue(dbPath: string): { target: string; status: string }[] {
  execFileSync(process.execPath, [script, dbPath], { stdio: 'pipe' });
  const db = openDb(dbPath);
  const rows = db.raw.prepare('SELECT target, status FROM report_queue ORDER BY target').all() as { target: string; status: string }[];
  db.close();
  return rows;
}

describe('requeue-score-changed', () => {
  it('does not queue a target the latest run did not score', () => {
    const db = setup([[['stale.example.com', 40]], [['a.example.com', 10]]]);
    expect(requeue(db).map((r) => r.target)).not.toContain('stale.example.com');
  });

  it('queues a target scored for the first time in the latest run', () => {
    const db = setup([[['a.example.com', 10]], [['a.example.com', 10], ['new.example.com', 5]]]);
    expect(requeue(db).map((r) => r.target)).toEqual(['new.example.com']);
  });

  it('queues a changed score and skips an unchanged one', () => {
    const db = setup([
      [['up.example.com', 10], ['same.example.com', 20]],
      [['up.example.com', 30], ['same.example.com', 20]],
    ]);
    expect(requeue(db).map((r) => r.target)).toEqual(['up.example.com']);
  });

  it('does not queue a target missing from the latest run whose last two scores differ', () => {
    const db = setup([
      [['gone.example.com', 10]],
      [['gone.example.com', 30]],
      [['a.example.com', 1]],
    ]);
    expect(requeue(db).map((r) => r.target)).not.toContain('gone.example.com');
  });

  it('resets an existing queue row to pending', () => {
    const dbPath = setup([[['up.example.com', 10]], [['up.example.com', 30]]]);
    const db = openDb(dbPath);
    db.raw.prepare("INSERT INTO report_queue(target, status, queued_at, attempts) VALUES('up.example.com', 'done', '2026-01-01T00:00:00.000Z', 2)").run();
    db.close();
    expect(requeue(dbPath)).toEqual([{ target: 'up.example.com', status: 'pending' }]);
  });
});
