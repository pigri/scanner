import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';

const scanDir = path.resolve(__dirname, '..');
const tsx = path.join(scanDir, 'node_modules', '.bin', 'tsx');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

describe('query-secrets', () => {
  it('reports a nuclei exposure finding from either pass', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'query-secrets-'));
    dirs.push(dir);
    const dbPath = path.join(dir, 'scan.db');
    const db = openDb(dbPath);
    const at = '2026-01-01T00:00:00.000Z';
    const runId = db.startRun('nuclei', {}, at);
    for (const tool of ['nuclei', 'nuclei-url']) {
      db.insertFinding({
        tool, target: `${tool}.example.test`, category: 'env-file-exposure', severity: 'high',
        title: 'exposed env', matched_at: null, meta: {},
      }, at, runId);
    }
    db.close();
    const out = execFileSync(tsx, ['src/query-secrets.ts', '--db', dbPath, '--format', 'json'], {
      cwd: scanDir, encoding: 'utf8', env: { PATH: process.env['PATH'] ?? '', HOME: dir },
    });
    const { rows } = JSON.parse(out) as { rows: { tool: string }[] };
    expect(rows.map((r) => r.tool).sort()).toEqual(['nuclei', 'nuclei-url']);
  }, 60_000);
});
