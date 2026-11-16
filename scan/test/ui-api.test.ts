import { describe, it, expect, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';

const scanDir = path.resolve(__dirname, '..');
const tsx = path.join(scanDir, 'node_modules', '.bin', 'tsx');
const children: ChildProcess[] = [];
const dirs: string[] = [];

afterAll(() => {
  for (const c of children.splice(0)) if (c.exitCode === null) c.kill('SIGTERM');
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

const NOW = Date.parse('2026-11-10T12:00:00.000Z');
const iso = (hoursAgo: number) => new Date(NOW - hoursAgo * 3600_000).toISOString();

function seed(dropTable: boolean): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-api-'));
  dirs.push(dir);
  const file = path.join(dir, 'scan.db');
  const { raw } = openDb(file);
  const ins = raw.prepare(
    `INSERT INTO target_network
       (target, ip, ip_version, ip_class, asn, as_name, as_domain, country_code, country,
        geo_checked_at, ptr_json, from_ports, from_dns, first_seen, last_seen)
     VALUES (@target, @ip, @v, @cls, @asn, @name, @dom, @cc, @c, @chk, @ptr, @fp, @fd, @first, @last)`,
  );
  const base = { target: 'host.example', v: 4, cls: 'public', asn: null, name: null, dom: null, cc: null, c: null, chk: null, ptr: null, fp: 1, fd: 0, first: iso(100), last: iso(0) };
  ins.run({ ...base, ip: '192.0.2.1', asn: 'AS64496', name: 'Example Net', dom: 'example.net', cc: 'HU', c: 'Hungary', chk: iso(0), ptr: '["h.example"]' });
  ins.run({ ...base, ip: '192.0.2.2', chk: iso(0), last: iso(30) });
  ins.run({ ...base, ip: '198.51.100.1', cls: 'private' });
  ins.run({ ...base, ip: '2001:db8::1', v: 6, fp: 0, fd: 1, ptr: '[]' });
  ins.run({ ...base, target: 'other.example', ip: '198.51.100.7' });
  if (dropTable) raw.exec('DROP TABLE target_network');
  raw.close();
  return file;
}

async function startUi(db: string): Promise<string> {
  const child = spawn(tsx, ['src/ui.ts', '--sqlite', db, '--recon-db', path.join(path.dirname(db), 'none.db'), '--port', '0'], {
    cwd: scanDir,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let out = '';
  child.stdout!.on('data', (b) => (out += b));
  child.stderr!.on('data', (b) => (out += b));
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const m = out.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
    if (m) return m[1]!;
    if (child.exitCode !== null) throw new Error(`ui exited: ${out}`);
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`ui did not start: ${out}`);
}

describe('GET /api/target network', () => {
  it('returns the target network rows with current flags and geo states', async () => {
    const base = await startUi(seed(false));
    const r = await fetch(`${base}/api/target?t=host.example`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as { network: any[] };
    expect(d.network.map((n) => n.ip)).toEqual(['192.0.2.1', '192.0.2.2', '198.51.100.1', '2001:db8::1']);
    const by = Object.fromEntries(d.network.map((n) => [n.ip, n]));
    expect(by['192.0.2.1']).toMatchObject({ geo: 'hit', asn: 'AS64496', country_code: 'HU', current: true, ptr: ['h.example'], seenVia: ['ports'] });
    expect(by['192.0.2.2']).toMatchObject({ geo: 'miss', current: false });
    expect(by['198.51.100.1']).toMatchObject({ geo: 'none', ipClass: 'private', ptr: null });
    expect(by['2001:db8::1']).toMatchObject({ ipVersion: 6, ptr: [], seenVia: ['dns'] });
  }, 40_000);

  it('returns an empty network, not a 500, when the table is missing', async () => {
    const base = await startUi(seed(true));
    const r = await fetch(`${base}/api/target?t=host.example`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as { network: unknown[] };
    expect(d.network).toEqual([]);
  }, 40_000);
});
