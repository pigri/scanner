import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';
import { mmdbAgeWarning, startNetinfoRun } from '../src/netinfo.js';

const scanDir = path.resolve(__dirname, '..');
const tsx = path.join(scanDir, 'node_modules', '.bin', 'tsx');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

function tmp(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'netinfo-cli-'));
  dirs.push(d);
  return d;
}

function runCli(args: string[]): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(tsx, ['src/netinfo.ts', ...args], { cwd: scanDir, stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (b) => (stderr += b));
    const timer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stderr }); });
  });
}

function setup(): { dir: string; db: string; targets: string; mmdb: string } {
  const dir = tmp();
  const targets = path.join(dir, 'targets.txt');
  fs.writeFileSync(targets, '192.0.2.10\n');
  return { dir, db: path.join(dir, 'scan.db'), targets, mmdb: path.join(dir, 'missing.mmdb') };
}

function readBack(db: string): { net: Array<{ target: string; ip: string; geo_checked_at: string | null }>; runs: Array<{ tool: string }> } {
  const { raw } = openDb(db);
  try {
    return {
      net: raw.prepare('SELECT target, ip, geo_checked_at FROM target_network').all() as never,
      runs: raw.prepare('SELECT tool FROM runs').all() as never,
    };
  } finally { raw.close(); }
}

describe('netinfo cli', () => {
  it('exits 0 with a missing mmdb and still writes the identity row', async () => {
    const s = setup();
    const r = await runCli(['--targets', s.targets, '--sqlite', s.db, '--mmdb', s.mmdb]);
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/mmdb/i);
    const out = readBack(s.db);
    expect(out.net).toEqual([{ target: '192.0.2.10', ip: '192.0.2.10', geo_checked_at: null }]);
    expect(out.runs.map((x) => x.tool)).toEqual(['netinfo']);
  });

  it('accepts its own flags after --', async () => {
    const s = setup();
    const r = await runCli(['--targets', s.targets, '--sqlite', s.db, '--', '--mmdb', s.mmdb]);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain(s.mmdb);
    expect(readBack(s.db).net).toHaveLength(1);
  });

  it('exits 0 with a garbage mmdb', async () => {
    const s = setup();
    fs.writeFileSync(s.mmdb, 'not a database\n'.repeat(50));
    const r = await runCli(['--targets', s.targets, '--sqlite', s.db, '--mmdb', s.mmdb]);
    expect(r.code).toBe(0);
    expect(readBack(s.db).net).toHaveLength(1);
  });

  it('exits 2 when neither --targets nor --all is given', async () => {
    const s = setup();
    const r = await runCli(['--sqlite', s.db, '--mmdb', s.mmdb]);
    expect(r.code).toBe(2);
    expect(fs.existsSync(s.db)).toBe(false);
  });

  it('--all derives rows from scan_queue', async () => {
    const s = setup();
    const seed = openDb(s.db);
    seed.raw.prepare('INSERT INTO scan_queue (target, queued_at) VALUES (?, ?)').run('192.0.2.11', '2026-11-01T00:00:00.000Z');
    seed.raw.close();
    const r = await runCli(['--all', '--sqlite', s.db, '--mmdb', s.mmdb]);
    expect(r.code).toBe(0);
    expect(readBack(s.db).net.map((x) => x.ip)).toEqual(['192.0.2.11']);
  });
});

describe('mmdbAgeWarning', () => {
  const now = new Date('2026-11-16T00:00:00.000Z');
  it('is silent for a fresh build', () => {
    expect(mmdbAgeWarning('2026-11-10T00:00:00.000Z', now)).toBeNull();
    expect(mmdbAgeWarning('2026-11-09T00:00:00.000Z', now)).toBeNull();
  });
  it('warns past the stale window', () => {
    expect(mmdbAgeWarning('2026-11-08T23:59:59.000Z', now)).toMatch(/older than 7 days/);
  });
  it('warns when the build time is unknown', () => {
    expect(mmdbAgeWarning(null, now)).toMatch(/unknown/);
  });
});

describe('startNetinfoRun', () => {
  it('has the 60s busy timeout in place when the first write happens', () => {
    const db = openDb(path.join(tmp(), 'scan.db'));
    try {
      expect(db.raw.pragma('busy_timeout', { simple: true })).toBe(5000);
      let seen: unknown = null;
      const realStart = db.startRun.bind(db);
      db.startRun = (tool, args, at) => {
        seen = db.raw.pragma('busy_timeout', { simple: true });
        return realStart(tool, args, at);
      };
      const id = startNetinfoRun(db, { mode: 'all' }, '2026-11-16T00:00:00.000Z');
      expect(id).toBeGreaterThan(0);
      expect(seen).toBe(60000);
    } finally {
      db.close();
    }
  });
});
