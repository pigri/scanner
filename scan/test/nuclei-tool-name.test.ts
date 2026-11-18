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

// A stand-in nuclei that writes one match for HOST to the file after -o.
const FAKE_NUCLEI = `#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; fi
  shift
done
echo '{"template-id":"ssh-terrapin","info":{"name":"Terrapin","severity":"medium"},"host":"${HOST}","matched-at":"${HOST}:22"}' > "$out"
`;

function runNuclei(extra: string[]): Promise<{ code: number | null; stderr: string; db: string }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nuclei-tool-'));
  dirs.push(dir);
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'nuclei'), FAKE_NUCLEI, { mode: 0o755 });
  const dbPath = path.join(dir, 'scan.db');
  const db = openDb(dbPath);
  db.raw.prepare('INSERT INTO http_probes(target, url, status_code, seen_at) VALUES (?,?,?,?)')
    .run(HOST, `https://${HOST}/`, 200, NOW);
  db.raw.prepare('INSERT INTO discovered_urls(target, url, source, status, seen_at) VALUES (?,?,?,?,?)')
    .run(HOST, `https://${HOST}/app/login`, 'katana', 200, NOW);
  db.close();
  const targets = path.join(dir, 'targets.txt');
  fs.writeFileSync(targets, `${HOST}\n`);
  return new Promise((resolve) => {
    const child = spawn(tsx, ['src/nuclei.ts', '--targets', targets, '--sqlite', dbPath,
      '--run-dir', path.join(dir, 'runs'), '--', '--live-only', ...extra], {
      cwd: scanDir,
      env: { PATH: `${bin}:${process.env['PATH'] ?? ''}`, HOME: dir },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (b) => (stderr += b));
    const timer = setTimeout(() => child.kill('SIGKILL'), 90_000);
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stderr, db: dbPath }); });
  });
}

const stored = (dbPath: string) => {
  const db = openDb(dbPath);
  const findings = db.raw.prepare('SELECT DISTINCT tool FROM findings').all() as { tool: string }[];
  const runs = db.raw.prepare("SELECT tool FROM runs WHERE tool LIKE 'nuclei%'").all() as { tool: string }[];
  db.close();
  return { findings: findings.map((r) => r.tool), runs: runs.map((r) => r.tool) };
};

describe('nuclei tool name', () => {
  it('stores a host pass under nuclei', async () => {
    const r = await runNuclei([]);
    expect(r.code, r.stderr).toBe(0);
    expect(stored(r.db)).toEqual({ findings: ['nuclei'], runs: ['nuclei'] });
  }, 100_000);

  it('stores a --from-urls pass under nuclei-url, finding and run alike', async () => {
    const r = await runNuclei(['--from-urls']);
    expect(r.code, r.stderr).toBe(0);
    expect(stored(r.db)).toEqual({ findings: ['nuclei-url'], runs: ['nuclei-url'] });
  }, 100_000);
});
