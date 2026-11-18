import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';

const scanDir = path.resolve(__dirname, '..');
const tsx = path.join(scanDir, 'node_modules', '.bin', 'tsx');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

const NOW = '2026-01-01T00:00:00.000Z';
const HOST = 'www.example.test';
const MISSED = 'skipped.example.test';

// A stand-in nuclei: copies $FAKE_ROWS to the file after -o and exits $FAKE_EXIT.
const FAKE_NUCLEI = `#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; fi
  shift
done
cp "$FAKE_ROWS" "$out"
exit "\${FAKE_EXIT:-0}"
`;

const row = (type: string, matchedAt: string, host = HOST) => JSON.stringify({
  'template-id': 't-' + type, type, info: { name: 'T', severity: 'info' }, host, 'matched-at': matchedAt,
});

function runNuclei(extra: string[], rows: string[], exit = 0) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nuclei-cov-'));
  dirs.push(dir);
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'nuclei'), FAKE_NUCLEI, { mode: 0o755 });
  const rowsFile = path.join(dir, 'rows.jsonl');
  fs.writeFileSync(rowsFile, rows.join('\n') + '\n');
  const dbPath = path.join(dir, 'scan.db');
  const db = openDb(dbPath);
  for (const h of [HOST, MISSED]) {
    db.raw.prepare('INSERT INTO http_probes(target, url, status_code, seen_at) VALUES (?,?,?,?)').run(h, `https://${h}/`, 200, NOW);
    db.raw.prepare('INSERT INTO discovered_urls(target, url, source, status, seen_at) VALUES (?,?,?,?,?)')
      .run(h, `https://${h}/app/login`, 'katana', 200, NOW);
  }
  db.close();
  const targets = path.join(dir, 'targets.txt');
  fs.writeFileSync(targets, `${HOST}\n${MISSED}\n`);
  return new Promise<{ code: number | null; stderr: string; db: string }>((resolve) => {
    const child = spawn(tsx, ['src/nuclei.ts', '--targets', targets, '--sqlite', dbPath,
      '--run-dir', path.join(dir, 'runs'), '--', '--live-only', ...extra], {
      cwd: scanDir,
      env: { PATH: `${bin}:${process.env['PATH'] ?? ''}`, HOME: dir, FAKE_ROWS: rowsFile, FAKE_EXIT: String(exit) },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (b) => (stderr += b));
    const timer = setTimeout(() => child.kill('SIGKILL'), 90_000);
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stderr, db: dbPath }); });
  });
}

const coverage = (dbPath: string) => {
  const db = openDb(dbPath);
  const rows = db.raw.prepare('SELECT target, tool, seen_at, run_id FROM tool_coverage ORDER BY target').all() as
    { target: string; tool: string; seen_at: string; run_id: number }[];
  const seen = db.raw.prepare('SELECT DISTINCT seen_at AS at FROM findings').all() as { at: string }[];
  db.close();
  return { rows, findingAts: seen.map((s) => s.at) };
};

describe('nuclei coverage', () => {
  it('records nothing on the host pass', async () => {
    const r = await runNuclei([], [row('ssl', `${HOST}:443`)]);
    expect(r.code, r.stderr).toBe(0);
    expect(coverage(r.db).rows).toEqual([]);
  }, 100_000);

  it('records only the host with a non-dns row, under nuclei-url, with the findings\' stamp', async () => {
    const r = await runNuclei(['--from-urls'], [
      row('ssl', `${HOST}:443`),
      row('dns', MISSED, MISSED),
    ]);
    expect(r.code, r.stderr).toBe(0);
    const c = coverage(r.db);
    expect(c.rows).toHaveLength(1);
    expect(c.rows[0]).toMatchObject({ target: HOST, tool: 'nuclei-url' });
    expect(c.findingAts).toHaveLength(1);
    expect(c.rows[0]!.seen_at).toBe(c.findingAts[0]);
    expect(c.rows[0]!.seen_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  }, 100_000);

  it('covers a host through a URL-sample row', async () => {
    const r = await runNuclei(['--from-urls'], [row('http', `https://${HOST}/app/login`)]);
    expect(coverage(r.db).rows.map((x) => x.target)).toEqual([HOST]);
  }, 100_000);

  it('records nothing when nuclei exits non-zero', async () => {
    const r = await runNuclei(['--from-urls'], [row('ssl', `${HOST}:443`)], 2);
    expect(coverage(r.db).rows).toEqual([]);
  }, 100_000);
});
