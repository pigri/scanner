import { describe, it, expect, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';
import { riskLatestMissingMessage } from '../src/lib/target-rows-sql.js';

const scanDir = path.resolve(__dirname, '..');
const tsx = path.join(scanDir, 'node_modules', '.bin', 'tsx');

const children: ChildProcess[] = [];
const dirs: string[] = [];

afterEach(() => {
  for (const c of children.splice(0)) if (c.exitCode === null) c.kill('SIGTERM');
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function makeDb(withRiskLatest: boolean): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-startup-'));
  dirs.push(dir);
  const file = path.join(dir, 'scan.db');
  const { raw } = openDb(file);
  if (!withRiskLatest) raw.exec('DROP TABLE risk_latest');
  raw.close();
  return file;
}

function startUi(db: string): { child: ChildProcess; stdout: () => string; stderr: () => string } {
  const child = spawn(tsx, ['src/ui.ts', '--sqlite', db, '--recon-db', path.join(path.dirname(db), 'none.db'), '--port', '0'], {
    cwd: scanDir,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let out = '';
  let err = '';
  child.stdout!.on('data', (b) => (out += b));
  child.stderr!.on('data', (b) => (err += b));
  return { child, stdout: () => out, stderr: () => err };
}

describe('ui startup', () => {
  it('exits 1 with the migration message when risk_latest is missing', async () => {
    const ui = startUi(makeDb(false));
    const code = await Promise.race([
      new Promise<number | null>((resolve) => ui.child.on('exit', resolve)),
      new Promise<string>((resolve) => setTimeout(() => resolve('still running after 10s'), 10_000)),
    ]);
    expect(code).toBe(1);
    expect(ui.stderr()).toContain(riskLatestMissingMessage(false)!);
  }, 30_000);

  it('keeps running and listens when risk_latest is present', async () => {
    const ui = startUi(makeDb(true));
    let exited: number | null | undefined;
    ui.child.on('exit', (c) => (exited = c));
    const deadline = Date.now() + 20_000;
    while (!ui.stdout().includes('Operation Hussar UI') && exited === undefined && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
    }
    expect(exited).toBeUndefined();
    expect(ui.stdout()).toContain('Operation Hussar UI');
    expect(ui.stderr()).not.toContain('risk_latest');
  }, 30_000);
});
