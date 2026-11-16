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

/** Every stage scan-all can run, read from its source so a new stage is skipped too. */
function otherStages(): string[] {
  const src = fs.readFileSync(path.join(scanDir, 'src', 'scan-all.ts'), 'utf8');
  const names = new Set([...src.matchAll(/runOne\('([^']+)'\)/g)].map((m) => m[1]!));
  names.delete('netinfo');
  names.add('smb');
  return [...names];
}

function runScanAll(env: Record<string, string>, args: string[]): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(tsx, ['src/scan-all.ts', ...args], {
      cwd: scanDir,
      env: { PATH: process.env['PATH'] ?? '', HOME: os.tmpdir(), ...env },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (b) => (stderr += b));
    const timer = setTimeout(() => child.kill('SIGKILL'), 90_000);
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stderr }); });
  });
}

describe('scan-all netinfo stage', () => {
  it('derives one target_network row with every other stage skipped', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-all-netinfo-'));
    dirs.push(dir);
    const targets = path.join(dir, 'targets.txt');
    const db = path.join(dir, 'scan.db');
    fs.writeFileSync(targets, '192.0.2.10\n');

    const skip = otherStages();
    expect(skip).toEqual(expect.arrayContaining(['httpx', 'nmap', 'dnsx', 'version-match', 'smb', 'data-integrity']));
    const r = await runScanAll(
      { SKIP: skip.join(','), NETINFO_FLAGS: `--mmdb ${path.join(dir, 'missing.mmdb')} --no-ptr` },
      ['--targets', targets, '--sqlite', db],
    );

    expect(r.stderr).toContain('>>> START netinfo');
    expect(r.stderr).toContain('netinfo: ptr: off');
    expect(r.code).toBe(0);
    const { raw } = openDb(db);
    try {
      const rows = raw.prepare('SELECT target, ip FROM target_network').all();
      expect(rows).toEqual([{ target: '192.0.2.10', ip: '192.0.2.10' }]);
      const tools = (raw.prepare('SELECT tool FROM runs').all() as Array<{ tool: string }>).map((x) => x.tool);
      expect(tools).toEqual(['netinfo']);
    } finally { raw.close(); }
  }, 120_000);

  // 10.0.0.5 is private: --ptr has nothing to look up, so no DNS is sent.
  it.each([
    ['passes --ptr by default', undefined, 'ptr: 0 looked up'],
    ['lets NETINFO_FLAGS=--no-ptr switch it off', '--no-ptr', 'ptr: off'],
  ])('%s', async (_name, extra, expected) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-all-netinfo-ptr-'));
    dirs.push(dir);
    const targets = path.join(dir, 'targets.txt');
    fs.writeFileSync(targets, '10.0.0.5\n');
    const flags = [`--mmdb ${path.join(dir, 'missing.mmdb')}`, extra].filter(Boolean).join(' ');
    const r = await runScanAll(
      { SKIP: otherStages().join(','), NETINFO_FLAGS: flags },
      ['--targets', targets, '--sqlite', path.join(dir, 'scan.db')],
    );
    expect(r.code).toBe(0);
    expect(r.stderr).toContain(`[netinfo] netinfo:`);
    expect(r.stderr).toContain(expected);
  }, 120_000);
});
