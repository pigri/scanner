import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';
import { DEFAULT_MMDB } from '../src/lib/geoip.js';
import { mmdbAgeWarning, startNetinfoRun, splitOwnFlags } from '../src/netinfo.js';

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

// 10.0.0.5 is private, so a --ptr run has nothing to look up and sends no DNS.
describe('netinfo cli ptr flags', () => {
  const setupPrivate = () => {
    const s = setup();
    fs.writeFileSync(s.targets, '10.0.0.5\n');
    return s;
  };

  it('is off by default', async () => {
    const s = setupPrivate();
    const r = await runCli(['--targets', s.targets, '--sqlite', s.db, '--mmdb', s.mmdb]);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain('ptr: off');
  });

  it('--ptr turns it on and reports counts, before or after --', async () => {
    for (const args of [['--ptr'], ['--', '--ptr', '--ptr-budget-sec', '5']]) {
      const s = setupPrivate();
      const r = await runCli(['--targets', s.targets, '--sqlite', s.db, '--mmdb', s.mmdb, ...args]);
      expect(r.code).toBe(0);
      expect(r.stderr).toMatch(/ptr: 0 looked up, 0 found, 0 empty, 0 failed, 0 skipped by budget/);
    }
  });

  it('the later of --ptr and --no-ptr wins', async () => {
    const s = setupPrivate();
    const r = await runCli(['--targets', s.targets, '--sqlite', s.db, '--mmdb', s.mmdb, '--ptr', '--no-ptr']);
    expect(r.stderr).toContain('ptr: off');
  });

  it('exits 2 on a bad budget', async () => {
    const s = setupPrivate();
    for (const bad of ['abc', '-1', '']) {
      const r = await runCli(['--targets', s.targets, '--sqlite', s.db, '--mmdb', s.mmdb, '--ptr-budget-sec', bad]);
      expect(r.code).toBe(2);
    }
  });
});

describe('netinfo cli --rebuild-history', () => {
  function seed(db: string): void {
    const d = openDb(db);
    try {
      const r1 = d.startRun('nmap', {}, '2026-08-31T10:00:00.000Z');
      const r2 = d.startRun('nmap', {}, '2026-09-04T10:00:00.000Z');
      d.insertPort({ target: 'a.example', ip: '192.0.2.10', port: 443, protocol: 'tcp' }, '2026-08-31T10:01:00.000Z', r1);
      d.insertPort({ target: 'a.example', ip: '198.51.100.7', port: 443, protocol: 'tcp' }, '2026-09-04T10:01:00.000Z', r2);
      d.raw.prepare("INSERT INTO scan_queue (target, queued_at) VALUES ('a.example', '2026-08-30T00:00:00.000Z')").run();
    } finally { d.close(); }
  }
  const read = (db: string) => {
    const d = openDb(db);
    try {
      return {
        ev: d.raw.prepare('SELECT ip, kind, at, source, run_id FROM target_network_events ORDER BY ip, at').all() as Array<{ ip: string; kind: string; at: string; source: string; run_id: number }>,
        net: (d.raw.prepare('SELECT count(*) n FROM target_network').get() as { n: number }).n,
        runs: d.raw.prepare('SELECT id, tool, args_json FROM runs WHERE tool = ?').all('netinfo') as Array<{ id: number; tool: string; args_json: string }>,
      };
    } finally { d.close(); }
  };

  it('writes reconstructed events under a netinfo run, touches no target_network row, and a second run adds none', async () => {
    const s = setup();
    seed(s.db);
    const first = await runCli(['--rebuild-history', '--sqlite', s.db]);
    expect(first.code).toBe(0);
    const a = read(s.db);
    expect(a.ev.map((e) => `${e.ip} ${e.kind} ${e.source}`)).toEqual([
      '192.0.2.10 ip_added reconstructed', '192.0.2.10 ip_gone reconstructed', '198.51.100.7 ip_added reconstructed',
    ]);
    expect(a.net).toBe(0);
    expect(a.runs).toHaveLength(1);
    expect(a.ev.every((e) => e.run_id === a.runs[0]!.id)).toBe(true);
    expect(JSON.parse(a.runs[0]!.args_json)).toMatchObject({ mode: 'rebuild-history' });
    const second = await runCli(['--rebuild-history', '--sqlite', s.db]);
    expect(second.code).toBe(0);
    expect(read(s.db).ev).toEqual(a.ev);
  });

  it('limits the rebuild to --targets', async () => {
    const s = setup();
    seed(s.db);
    const r = await runCli(['--rebuild-history', '--targets', s.targets, '--sqlite', s.db]);
    expect(r.code).toBe(0);
    expect(read(s.db).ev).toEqual([]);
  });
});

describe('splitOwnFlags', () => {
  const base = ['node', 'netinfo.ts'];
  it('defaults', () => {
    expect(splitOwnFlags(base)).toMatchObject({ ptr: false, ptrBudgetSec: 60, rebuild: false });
  });
  it('takes --rebuild-history before or after --', () => {
    expect(splitOwnFlags([...base, '--rebuild-history']).rebuild).toBe(true);
    expect(splitOwnFlags([...base, '--', '--rebuild-history']).rebuild).toBe(true);
  });
  it('takes the mmdb path from GEOIP_MMDB when set', () => {
    expect(splitOwnFlags(base, { GEOIP_MMDB: '/data/geo/x.mmdb' }).mmdb).toBe('/data/geo/x.mmdb');
  });
  it('keeps the default mmdb when GEOIP_MMDB is unset or empty', () => {
    expect(splitOwnFlags(base, {}).mmdb).toBe(DEFAULT_MMDB);
    expect(splitOwnFlags(base, { GEOIP_MMDB: '' }).mmdb).toBe(DEFAULT_MMDB);
  });
  it('lets --mmdb win over GEOIP_MMDB', () => {
    expect(splitOwnFlags([...base, '--mmdb', '/flag.mmdb'], { GEOIP_MMDB: '/env.mmdb' }).mmdb).toBe('/flag.mmdb');
  });
  it('last of --ptr / --no-ptr wins', () => {
    expect(splitOwnFlags([...base, '--ptr', '--no-ptr']).ptr).toBe(false);
    expect(splitOwnFlags([...base, '--no-ptr', '--ptr']).ptr).toBe(true);
    expect(splitOwnFlags([...base, '--ptr', '--', '--no-ptr']).ptr).toBe(false);
    expect(splitOwnFlags([...base, '--ptr', '--', '--no-ptr', '--ptr']).ptr).toBe(true);
  });
  it('takes the budget and keeps other args', () => {
    const o = splitOwnFlags([...base, '--targets', 't.txt', '--ptr-budget-sec', '7.5']);
    expect(o.ptrBudgetSec).toBe(7.5);
    expect(o.rest).toEqual([...base, '--targets', 't.txt']);
  });
  it('marks an invalid budget as NaN', () => {
    for (const bad of ['abc', '-1', '']) expect(Number.isNaN(splitOwnFlags([...base, '--ptr-budget-sec', bad]).ptrBudgetSec)).toBe(true);
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
