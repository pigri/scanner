import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterAll } from 'vitest';
import { openDb } from '../../src/lib/db.js';

export const scanDir = path.resolve(__dirname, '..', '..');
const tsx = path.join(scanDir, 'node_modules', '.bin', 'tsx');
const dirs: string[] = [];
afterAll(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

export const T0 = '2026-11-10T10:00:00.000Z';
export const T1 = '2026-11-10T10:30:00.000Z';
export const T2 = '2026-11-10T12:00:00.000Z';
export const T3 = '2026-11-10T12:30:00.000Z';

export function tmpDb(): { dir: string; file: string; db: ReturnType<typeof openDb> } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-rule-'));
  dirs.push(dir);
  const file = path.join(dir, 'scan.db');
  return { dir, file, db: openDb(file) };
}

export function run(script: string, args: string[]): { out: string; status: number | null } {
  const r = spawnSync(tsx, [script, ...args], { cwd: scanDir, encoding: 'utf8', timeout: 30_000 });
  return { out: r.stdout, status: r.status };
}

/**
 * An older clean nuclei run saw `cve-a` (medium); a later nuclei run was killed
 * after writing one info row, so it must not close `cve-a`. The scan_queue
 * window is the later run's.
 */
export function seedKilledNuclei(db: ReturnType<typeof openDb>, target: string): void {
  const r1 = db.startRun('nuclei', {}, T0);
  db.insertFinding({ tool: 'nuclei', target, category: 'cve-a', severity: 'medium', title: 'cve-a' }, T0, r1);
  db.finishRun(r1, { at: T1 });
  const r2 = db.startRun('nuclei', {}, T2);
  db.insertFinding({ tool: 'nuclei', target, category: 'tech', severity: 'info', title: 'tech-detect' }, T2, r2);
  db.finishRun(r2, { at: T3, partial: true });
  db.raw.prepare(
    `INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES (?, 'done', ?, ?, ?)`,
  ).run(target, T0, T2, T3);
}
