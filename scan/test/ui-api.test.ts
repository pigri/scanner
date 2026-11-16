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
  ins.run({ ...base, target: 'de.example', ip: '192.0.2.9', asn: 'AS64511', cc: 'DE', c: 'Germany', chk: iso(0) });
  const risk = raw.prepare('INSERT INTO risk_latest (target, score, created_at, updated_at) VALUES (?, ?, ?, ?)');
  for (const t of ['host.example', 'other.example', 'de.example']) risk.run(t, 10, iso(0), iso(0));
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

describe('GET /api/targets country and asn', () => {
  it('filters by country and returns the facets', async () => {
    const base = await startUi(seed(false));
    const all = (await (await fetch(`${base}/api/targets?limit=100`)).json()) as any;
    expect(all.rows.map((r: any) => r.target).sort()).toEqual(['de.example', 'host.example', 'other.example']);
    const byT = Object.fromEntries(all.rows.map((r: any) => [r.target, r]));
    expect(byT['host.example']).toMatchObject({ countries: ['HU'], asns: ['AS64496'] });
    expect(byT['other.example']).toMatchObject({ countries: [], asns: [] });
    expect(all.countries).toEqual([{ value: 'DE', c: 1 }, { value: 'HU', c: 1 }]);

    const r = await fetch(`${base}/api/targets?limit=100&country=DE`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as any;
    expect(d.rows.map((x: any) => x.target)).toEqual(['de.example']);
    expect(d.countries).toEqual([{ value: 'DE', c: 1 }, { value: 'HU', c: 1 }]);
    expect(d.asns).toEqual([{ value: 'AS64496', c: 1 }, { value: 'AS64511', c: 1 }]);

    const a = (await (await fetch(`${base}/api/targets?limit=100&asn=AS64496`)).json()) as any;
    expect(a.rows.map((x: any) => x.target)).toEqual(['host.example']);
  }, 40_000);

  it('still answers with empty arrays when the table is missing', async () => {
    const base = await startUi(seed(true));
    const r = await fetch(`${base}/api/targets?limit=100`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as any;
    expect(d.rows).toHaveLength(3);
    for (const row of d.rows) expect(row).toMatchObject({ countries: [], asns: [] });
    expect(d.countries).toEqual([]);
    expect(d.asns).toEqual([]);
  }, 40_000);
});

function seedLatestScan(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-api-'));
  dirs.push(dir);
  const file = path.join(dir, 'scan.db');
  const { raw } = openDb(file);
  const ins = raw.prepare(
    `INSERT INTO target_network (target, ip, ip_version, ip_class, asn, country_code, from_ports, from_dns, first_seen, last_seen)
     VALUES (?, ?, 4, 'public', ?, ?, ?, ?, ?, ?)`,
  );
  const q = raw.prepare(`INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES (?, 'done', ?, ?, ?)`);
  const dns = raw.prepare(`INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES (?, ?, 'A', ?, ?, ?)`);
  const risk = raw.prepare('INSERT INTO risk_latest (target, score, created_at, updated_at) VALUES (?, ?, ?, ?)');
  const scanStart = '2026-11-04T09:00:00.000Z';
  const scanEnd = '2026-11-04T09:30:00.000Z';
  // fileshare-shaped: port seen 2026-08-31, scanned 2026-11-04 without an answer.
  ins.run('fileshare.example', '192.0.2.50', 'AS64496', 'HU', 1, 0, '2026-08-31T08:00:00.000Z', '2026-08-31T08:00:00.000Z');
  q.run('fileshare.example', '2026-11-04T08:00:00.000Z', scanStart, scanEnd);
  dns.run('fileshare.example', 'fileshare.example', '192.0.2.50', '2026-08-31T08:00:00.000Z', '2026-11-04T09:10:00.000Z');
  // DNS-only, scanned before DNS tracking began, with an old untracked row.
  ins.run('dnsonly.example', '192.0.2.60', 'AS64511', 'DE', 0, 1, '2026-08-31T08:00:00.000Z', '2026-08-31T08:00:00.000Z');
  q.run('dnsonly.example', '2026-11-04T08:00:00.000Z', scanStart, scanEnd);
  dns.run('dnsonly.example', 'dnsonly.example', '192.0.2.60', '2026-08-31T08:00:00.000Z', null);
  for (const t of ['fileshare.example', 'dnsonly.example']) risk.run(t, 10, scanEnd, scanEnd);
  raw.close();
  return file;
}

describe('GET /api/targets uses the latest scan', () => {
  it('drops an ip not seen in the latest scan from the facets and filters, keeps unknown', async () => {
    const base = await startUi(seedLatestScan());
    const all = (await (await fetch(`${base}/api/targets?limit=100`)).json()) as any;
    const byT = Object.fromEntries(all.rows.map((r: any) => [r.target, r]));
    expect(byT['fileshare.example']).toMatchObject({ countries: [], asns: [] });
    expect(byT['dnsonly.example']).toMatchObject({ countries: ['DE'], asns: ['AS64511'] });
    expect(all.countries).toEqual([{ value: 'DE', c: 1 }]);
    expect(all.asns).toEqual([{ value: 'AS64511', c: 1 }]);
    const hu = (await (await fetch(`${base}/api/targets?limit=100&country=HU`)).json()) as any;
    expect(hu.rows).toEqual([]);
    const asn = (await (await fetch(`${base}/api/targets?limit=100&asn=AS64496`)).json()) as any;
    expect(asn.rows).toEqual([]);
    const de = (await (await fetch(`${base}/api/targets?limit=100&country=DE`)).json()) as any;
    expect(de.rows.map((x: any) => x.target)).toEqual(['dnsonly.example']);
  }, 40_000);
});

function seedScan(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-api-'));
  dirs.push(dir);
  const file = path.join(dir, 'scan.db');
  const { raw } = openDb(file);
  const net = raw.prepare(
    `INSERT INTO target_network (target, ip, ip_version, ip_class, from_ports, from_dns, first_seen, last_seen)
     VALUES (?, ?, 4, 'public', ?, ?, ?, ?)`,
  );
  const queue = raw.prepare(
    `INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES (?, ?, ?, ?, ?)`,
  );
  // Answered by port and HTTP months ago; the latest scan found nothing.
  net.run('files.example', '192.0.2.10', 1, 0, '2026-08-31T10:00:00.000Z', '2026-08-31T10:00:00.000Z');
  raw.prepare(`INSERT INTO ports (target, ip, port, protocol, seen_at) VALUES (?, ?, 80, 'tcp', ?)`).run('files.example', '192.0.2.10', '2026-08-31T10:00:00.000Z');
  raw.prepare(`INSERT INTO http_probes (target, url, status_code, seen_at) VALUES (?, ?, 200, ?)`).run('files.example', 'http://files.example/', '2026-09-04T22:01:00.000Z');
  queue.run('files.example', 'done', '2026-11-01T00:00:00.000Z', '2026-11-04T09:00:00.000Z', '2026-11-04T09:18:00.000Z');
  // DNS-only, written before last_seen existed; another target proves tracking started later.
  const dns = raw.prepare(`INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES (?, ?, 'A', ?, ?, ?)`);
  dns.run('dnsonly.example', 'dnsonly.example', '192.0.2.20', '2026-08-31T10:00:00.000Z', null);
  dns.run('tracked.example', 'tracked.example', '192.0.2.30', '2026-11-01T00:00:00.000Z', '2026-11-16T00:00:00.000Z');
  net.run('dnsonly.example', '192.0.2.20', 0, 1, '2026-08-31T10:00:00.000Z', '2026-08-31T10:00:00.000Z');
  queue.run('dnsonly.example', 'done', '2026-11-01T00:00:00.000Z', '2026-11-04T09:00:00.000Z', '2026-11-04T09:18:00.000Z');
  // No done scan: the old 24 h rule applies.
  net.run('queued.example', '192.0.2.40', 1, 0, '2026-08-01T00:00:00.000Z', '2026-08-31T10:00:00.000Z');
  net.run('queued.example', '192.0.2.41', 1, 0, '2026-08-01T00:00:00.000Z', '2026-09-30T10:00:00.000Z');
  raw.prepare(`INSERT INTO scan_queue (target, status, queued_at) VALUES (?, 'pending', ?)`).run('queued.example', '2026-11-10T00:00:00.000Z');
  raw.close();
  return file;
}

describe('GET /api/target latest scan', () => {
  it('marks an ip the latest scan missed, and reports what answered last', async () => {
    const base = await startUi(seedScan());
    const d = (await (await fetch(`${base}/api/target?t=files.example`)).json()) as any;
    expect(d.latestScan).toEqual({ started_at: '2026-11-04T09:00:00.000Z', finished_at: '2026-11-04T09:18:00.000Z', ports: 0, http: 0, dns: 0 });
    expect(d.lastAnswered).toEqual({ at: '2026-09-04T22:01:00.000Z', source: 'http' });
    expect(d.network[0]).toMatchObject({ ip: '192.0.2.10', scanStatus: 'no', current: false });
  }, 40_000);

  it('marks a DNS-only ip from before tracking as unknown and current', async () => {
    const base = await startUi(seedScan());
    const d = (await (await fetch(`${base}/api/target?t=dnsonly.example`)).json()) as any;
    expect(d.network[0]).toMatchObject({ scanStatus: 'unknown', current: true });
    expect(d.latestScan).toMatchObject({ dns: 0 });
    expect(d.lastAnswered).toEqual({ at: '2026-08-31T10:00:00.000Z', source: 'dns' });
  }, 40_000);

  it('falls back to the 24 h rule and the queue state when there is no done scan', async () => {
    const base = await startUi(seedScan());
    const d = (await (await fetch(`${base}/api/target?t=queued.example`)).json()) as any;
    expect(d.latestScan).toEqual({ state: 'queued' });
    expect(d.network.map((n: any) => [n.ip, n.scanStatus, n.current])).toEqual([
      ['192.0.2.40', 'none', false],
      ['192.0.2.41', 'none', true],
    ]);
  }, 40_000);

  it('returns a null latest scan and no answer for an unknown target', async () => {
    const base = await startUi(seedScan());
    const d = (await (await fetch(`${base}/api/target?t=nothing.example`)).json()) as any;
    expect(d.latestScan).toBeNull();
    expect(d.lastAnswered).toBeNull();
  }, 40_000);
});

describe('GET /api/target on a DB without dns_records.last_seen', () => {
  it('returns 200, reads seen_at, and marks the dns-only ip unknown', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-api-'));
    dirs.push(dir);
    const file = path.join(dir, 'scan.db');
    const { raw } = openDb(file);
    raw.exec(`DROP TABLE dns_records;
      CREATE TABLE dns_records (id INTEGER PRIMARY KEY, target TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL,
        value TEXT NOT NULL, ttl INTEGER, seen_at TEXT NOT NULL, run_id INTEGER, UNIQUE(target, name, type, value))`);
    raw.prepare(`INSERT INTO dns_records (target, name, type, value, seen_at) VALUES ('old.example', 'old.example', 'A', '192.0.2.50', '2026-08-31T10:00:00.000Z')`).run();
    raw.prepare(`INSERT INTO target_network (target, ip, ip_version, ip_class, from_ports, from_dns, first_seen, last_seen)
      VALUES ('old.example', '192.0.2.50', 4, 'public', 0, 1, '2026-08-31T10:00:00.000Z', '2026-08-31T10:00:00.000Z')`).run();
    raw.prepare(`INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES ('old.example', 'done', ?, ?, ?)`)
      .run('2026-11-01T00:00:00.000Z', '2026-11-04T09:00:00.000Z', '2026-11-04T09:18:00.000Z');
    raw.close();
    const base = await startUi(file);
    const r = await fetch(`${base}/api/target?t=old.example`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as any;
    expect(d.network[0]).toMatchObject({ scanStatus: 'unknown', current: true });
    expect(d.latestScan).toMatchObject({ dns: 0 });
    expect(d.lastAnswered).toEqual({ at: '2026-08-31T10:00:00.000Z', source: 'dns' });
    expect(d.dnsTrackedSince).toBeNull();
  }, 40_000);
});
