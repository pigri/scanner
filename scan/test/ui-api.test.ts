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

function seed(dropTable: boolean, mutate?: (raw: ReturnType<typeof openDb>['raw']) => void): string {
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
  mutate?.(raw);
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

function seedLatestScan(mutate?: (raw: ReturnType<typeof openDb>['raw']) => void): string {
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
  mutate?.(raw);
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

describe('GET /api/targets on older databases', () => {
  it('answers with the 24 h rule when scan_queue is missing', async () => {
    const base = await startUi(seed(false, (raw) => raw.exec('DROP TABLE scan_queue')));
    const r = await fetch(`${base}/api/targets?limit=100`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as any;
    const byT = Object.fromEntries(d.rows.map((x: any) => [x.target, x]));
    expect(byT['host.example']).toMatchObject({ countries: ['HU'], asns: ['AS64496'] });
    expect(d.countries).toEqual([{ value: 'DE', c: 1 }, { value: 'HU', c: 1 }]);
  }, 40_000);

  it('treats every dns target as untracked when dns_records has no last_seen', async () => {
    const file = seedLatestScan((raw) => {
      raw.exec('DROP TABLE dns_records');
      raw.exec(`CREATE TABLE dns_records (id INTEGER PRIMARY KEY, target TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL,
        value TEXT NOT NULL, ttl INTEGER, seen_at TEXT NOT NULL, run_id INTEGER)`);
      const ins = raw.prepare(`INSERT INTO dns_records (target, name, type, value, seen_at) VALUES (?, ?, 'A', ?, ?)`);
      ins.run('fileshare.example', 'fileshare.example', '192.0.2.50', '2026-08-31T08:00:00.000Z');
      ins.run('dnsonly.example', 'dnsonly.example', '192.0.2.60', '2026-08-31T08:00:00.000Z');
    });
    const base = await startUi(file);
    const r = await fetch(`${base}/api/targets?limit=100`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as any;
    const byT = Object.fromEntries(d.rows.map((x: any) => [x.target, x]));
    expect(byT['dnsonly.example']).toMatchObject({ countries: ['DE'], asns: ['AS64511'] });
    expect(byT['fileshare.example']).toMatchObject({ countries: ['HU'], asns: ['AS64496'] });
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

describe('a DB whose target_network predates from_http', () => {
  const dropFromHttp = (raw: ReturnType<typeof openDb>['raw']) => raw.exec('ALTER TABLE target_network DROP COLUMN from_http');

  it('answers /api/targets with 200', async () => {
    const base = await startUi(seed(false, dropFromHttp));
    const r = await fetch(`${base}/api/targets?limit=100`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as any;
    expect(d.rows.find((x: any) => x.target === 'host.example')).toMatchObject({ countries: ['HU'] });
  }, 40_000);

  it('answers /api/target with 200 and no http in seenVia', async () => {
    const base = await startUi(seed(false, dropFromHttp));
    const r = await fetch(`${base}/api/target?t=host.example`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as any;
    expect(d.network.length).toBeGreaterThan(0);
    expect(d.network.every((n: any) => !n.seenVia.includes('http'))).toBe(true);
  }, 40_000);
});

type EventSeed = { ip: string; kind: string; at: string; source?: string; oc?: string | null; nc?: string | null; oa?: string | null; na?: string | null };

function seedHistory(events: EventSeed[], dropTable = false): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-api-'));
  dirs.push(dir);
  const file = path.join(dir, 'scan.db');
  const { raw } = openDb(file);
  const ins = raw.prepare(
    `INSERT INTO target_network_events (target, ip, kind, at, old_country_code, new_country_code, old_asn, new_asn, source)
     VALUES ('files.example', @ip, @kind, @at, @oc, @nc, @oa, @na, @source)`,
  );
  for (const e of events) ins.run({ oc: null, nc: null, oa: null, na: null, source: 'scan', ...e });
  ins.run({ ip: '198.51.100.99', kind: 'ip_added', at: '2026-01-01T00:00:00.000Z', oc: null, nc: null, oa: null, na: null, source: 'scan' });
  raw.prepare(`UPDATE target_network_events SET target = 'other.example' WHERE ip = '198.51.100.99'`).run();
  if (dropTable) raw.exec('DROP TABLE target_network_events');
  raw.close();
  return file;
}

describe('GET /api/target history', () => {
  it('returns every event kind newest first, with old and new geo values, for this target only', async () => {
    const base = await startUi(seedHistory([
      { ip: '192.0.2.10', kind: 'ip_added', at: '2026-08-31T10:00:00.000Z' },
      { ip: '192.0.2.10', kind: 'geo_changed', at: '2026-10-01T00:00:00.000Z', oc: 'HU', nc: 'DE', oa: 'AS64496', na: 'AS64497' },
      { ip: '192.0.2.10', kind: 'ip_gone', at: '2026-11-04T09:00:00.000Z' },
      { ip: '192.0.2.10', kind: 'ip_back', at: '2026-11-08T09:00:00.000Z' },
    ]));
    const d = (await (await fetch(`${base}/api/target?t=files.example`)).json()) as any;
    expect(d.history.map((e: any) => e.kind)).toEqual(['ip_back', 'ip_gone', 'geo_changed', 'ip_added']);
    expect(d.history.every((e: any) => e.ip === '192.0.2.10')).toBe(true);
    expect(d.history[2]).toMatchObject({ old_country_code: 'HU', new_country_code: 'DE', old_asn: 'AS64496', new_asn: 'AS64497', inferred: false });
    expect(d.history[2].text).toBe('geo changed: country HU → DE, ASN AS64496 → AS64497');
    expect(d.history[3].text).toBe('added');
  }, 40_000);

  it('caps the list at 200 and keeps the newest', async () => {
    const events: EventSeed[] = [];
    for (let i = 0; i < 205; i++) {
      events.push({ ip: `192.0.2.${i % 200}`, kind: 'geo_changed', at: new Date(Date.parse('2026-01-01T00:00:00.000Z') + i * 60_000).toISOString(), oc: 'HU', nc: 'DE' });
    }
    const base = await startUi(seedHistory(events));
    const d = (await (await fetch(`${base}/api/target?t=files.example`)).json()) as any;
    expect(d.history).toHaveLength(200);
    expect(d.history[0].at).toBe(new Date(Date.parse('2026-01-01T00:00:00.000Z') + 204 * 60_000).toISOString());
    expect(d.history[199].at).toBe(new Date(Date.parse('2026-01-01T00:00:00.000Z') + 5 * 60_000).toISOString());
  }, 40_000);

  it('marks reconstructed events as inferred and scan events not', async () => {
    const base = await startUi(seedHistory([
      { ip: '192.0.2.10', kind: 'ip_added', at: '2026-08-31T10:00:00.000Z', source: 'reconstructed' },
      { ip: '192.0.2.10', kind: 'ip_gone', at: '2026-11-04T09:00:00.000Z', source: 'reconstructed' },
      { ip: '192.0.2.11', kind: 'ip_added', at: '2026-11-05T09:00:00.000Z', source: 'scan' },
    ]));
    const d = (await (await fetch(`${base}/api/target?t=files.example`)).json()) as any;
    expect(d.history.map((e: any) => [e.kind, e.inferred, e.text])).toEqual([
      ['ip_added', false, 'added'],
      ['ip_gone', true, 'gone (inferred)'],
      ['ip_added', true, 'added (inferred)'],
    ]);
  }, 40_000);

  it('shows added and gone (inferred) for a fileshare-shaped target', async () => {
    const base = await startUi(seedHistory([
      { ip: '192.0.2.10', kind: 'ip_added', at: '2026-08-31T10:00:00.000Z', source: 'reconstructed' },
      { ip: '192.0.2.10', kind: 'ip_gone', at: '2026-11-04T09:00:00.000Z', source: 'reconstructed' },
    ]));
    const d = (await (await fetch(`${base}/api/target?t=files.example`)).json()) as any;
    expect(d.history.map((e: any) => `${e.text} ${e.at.slice(0, 10)}`).reverse()).toEqual([
      'added (inferred) 2026-08-31',
      'gone (inferred) 2026-11-04',
    ]);
  }, 40_000);

  it('returns an empty history, not a 500, when the table is missing', async () => {
    const base = await startUi(seedHistory([], true));
    const r = await fetch(`${base}/api/target?t=files.example`);
    expect(r.status).toBe(200);
    expect(((await r.json()) as any).history).toEqual([]);
  }, 40_000);
});

describe('unreachable flag', () => {
  const S = '2026-11-04T09:00:00.000Z';
  function seedReach(mutate?: (raw: ReturnType<typeof openDb>['raw']) => void): string {
    return seedLatestScan((raw) => {
      const ins = raw.prepare(
        `INSERT INTO target_network (target, ip, ip_version, ip_class, asn, country_code, from_ports, from_dns, first_seen, last_seen)
         VALUES (?, ?, 4, 'public', 'AS64500', 'DE', 1, 0, ?, ?)`,
      );
      const q = raw.prepare(`INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES (?, ?, ?, ?, ?)`);
      const risk = raw.prepare('INSERT INTO risk_latest (target, score, created_at, updated_at) VALUES (?, ?, ?, ?)');
      // Answered in its latest scan.
      ins.run('alive.example', '192.0.2.70', '2026-08-31T08:00:00.000Z', '2026-11-04T09:10:00.000Z');
      q.run('alive.example', 'done', '2026-11-04T08:00:00.000Z', S, '2026-11-04T09:30:00.000Z');
      risk.run('alive.example', 10, '2026-11-04T09:30:00.000Z', '2026-11-04T09:30:00.000Z');
      // Not scanned yet: pending is not unreachable.
      ins.run('pending.example', '192.0.2.71', '2026-08-31T08:00:00.000Z', '2026-08-31T08:00:00.000Z');
      q.run('pending.example', 'pending', '2026-11-04T08:00:00.000Z', null, null);
      risk.run('pending.example', 10, '2026-11-04T09:30:00.000Z', '2026-11-04T09:30:00.000Z');
      mutate?.(raw);
    });
  }
  const list = async (base: string, qs = '') => ((await (await fetch(`${base}/api/targets?limit=100${qs}`)).json()) as any);

  it('flags the fileshare-shaped target with its scan date and leaves its score', async () => {
    const base = await startUi(seedReach());
    const d = await list(base);
    const by = Object.fromEntries(d.rows.map((r: any) => [r.target, r]));
    expect(by['fileshare.example']).toMatchObject({ unreachableSince: S, score: 10 });
    expect(by['dnsonly.example'].unreachableSince).toBeNull();
    expect(by['alive.example'].unreachableSince).toBeNull();
    expect(by['pending.example'].unreachableSince).toBeNull();
    const t = (await (await fetch(`${base}/api/target?t=fileshare.example`)).json()) as any;
    expect(t.unreachableSince).toBe(S);
    const ok = (await (await fetch(`${base}/api/target?t=alive.example`)).json()) as any;
    expect(ok.unreachableSince).toBeNull();
  }, 40_000);

  it('filters by reachable and sorts unreachable below reachable at the same score', async () => {
    const base = await startUi(seedReach());
    const all = await list(base);
    expect(all.rows.map((r: any) => r.target)).toEqual(['alive.example', 'dnsonly.example', 'pending.example', 'fileshare.example']);
    expect((await list(base, '&reachable=unreachable')).rows.map((r: any) => r.target)).toEqual(['fileshare.example']);
    expect((await list(base, '&reachable=reachable')).rows.map((r: any) => r.target)).toEqual(['alive.example', 'dnsonly.example', 'pending.example']);
  }, 40_000);

  it('answers 200 with no flag on a DB without scan_queue, target_network or dns_records', async () => {
    for (const drop of ['scan_queue', 'target_network', 'dns_records']) {
      const base = await startUi(seedReach((raw) => raw.exec(`DROP TABLE ${drop}`)));
      const r = await fetch(`${base}/api/targets?limit=100`);
      expect(r.status).toBe(200);
      const d = (await r.json()) as any;
      if (drop !== 'dns_records') expect(d.rows.every((x: any) => x.unreachableSince === null)).toBe(true);
      const t = await fetch(`${base}/api/target?t=fileshare.example`);
      expect(t.status).toBe(200);
      const td = (await t.json()) as any;
      if (drop !== 'dns_records') expect(td.unreachableSince).toBeNull();
    }
  }, 120_000);

  describe('target with no ips', () => {
    const noIp = (raw: ReturnType<typeof openDb>['raw']) => {
      const q = raw.prepare(`INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES (?, ?, ?, ?, ?)`);
      const risk = raw.prepare('INSERT INTO risk_latest (target, score, created_at, updated_at) VALUES (?, ?, ?, ?)');
      for (const t of ['silent', 'oldrows', 'portrow', 'httprow']) {
        q.run(`${t}.example`, 'done', '2026-11-04T08:00:00.000Z', S, '2026-11-04T09:30:00.000Z');
        risk.run(`${t}.example`, 7, '2026-11-04T09:30:00.000Z', '2026-11-04T09:30:00.000Z');
      }
      q.run('queued2.example', 'pending', '2026-11-04T08:00:00.000Z', null, null);
      risk.run('queued2.example', 7, '2026-11-04T09:30:00.000Z', '2026-11-04T09:30:00.000Z');
      raw.prepare(`INSERT INTO ports (target, ip, port, protocol, seen_at) VALUES (?, '192.0.2.80', 80, 'tcp', ?)`).run('oldrows.example', '2026-08-31T08:00:00.000Z');
      raw.prepare(`INSERT INTO ports (target, ip, port, protocol, seen_at) VALUES (?, '192.0.2.81', 80, 'tcp', ?)`).run('portrow.example', '2026-11-04T09:10:00.000Z');
      raw.prepare(`INSERT INTO http_probes (target, url, seen_at) VALUES (?, ?, ?)`).run('httprow.example', 'http://httprow.example/', '2026-11-04T09:10:00.000Z');
    };
    it('flags it only when nothing answered the scan, in the list and on the page', async () => {
      const base = await startUi(seedReach(noIp));
      const by = Object.fromEntries((await list(base)).rows.map((r: any) => [r.target, r]));
      expect(by['silent.example']).toMatchObject({ unreachableSince: S, score: 7 });
      expect(by['oldrows.example'].unreachableSince).toBe(S);
      expect(by['portrow.example'].unreachableSince).toBeNull();
      expect(by['httprow.example'].unreachableSince).toBeNull();
      expect(by['queued2.example'].unreachableSince).toBeNull();
      for (const [t, want] of [['silent', S], ['oldrows', S], ['portrow', null], ['httprow', null], ['queued2', null]] as const) {
        const d = (await (await fetch(`${base}/api/target?t=${t}.example`)).json()) as any;
        expect(d.unreachableSince).toBe(want);
      }
    }, 40_000);

    it('does not flag a port or http row seen exactly at the scan start', async () => {
      const base = await startUi(seedReach((raw) => {
        const q = raw.prepare(`INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES (?, 'done', ?, ?, ?)`);
        const risk = raw.prepare('INSERT INTO risk_latest (target, score, created_at, updated_at) VALUES (?, ?, ?, ?)');
        for (const t of ['edgeport', 'edgehttp']) {
          q.run(`${t}.example`, '2026-11-04T08:00:00.000Z', S, '2026-11-04T09:30:00.000Z');
          risk.run(`${t}.example`, 7, '2026-11-04T09:30:00.000Z', '2026-11-04T09:30:00.000Z');
        }
        raw.prepare(`INSERT INTO ports (target, ip, port, protocol, seen_at) VALUES ('edgeport.example', '192.0.2.82', 80, 'tcp', ?)`).run(S);
        raw.prepare(`INSERT INTO http_probes (target, url, seen_at) VALUES ('edgehttp.example', 'http://edgehttp.example/', ?)`).run(S);
      }));
      const by = Object.fromEntries((await list(base)).rows.map((r: any) => [r.target, r]));
      expect(by['edgeport.example'].unreachableSince).toBeNull();
      expect(by['edgehttp.example'].unreachableSince).toBeNull();
      for (const t of ['edgeport', 'edgehttp']) {
        const d = (await (await fetch(`${base}/api/target?t=${t}.example`)).json()) as any;
        expect(d.unreachableSince).toBeNull();
      }
    }, 40_000);

    it('answers /api/targets with 200 and the flag when the per-target indexes are missing', async () => {
      const base = await startUi(seedReach((raw) => {
        noIp(raw);
        raw.exec('DROP INDEX idx_ports_target; DROP INDEX idx_http_target');
      }));
      const r = await fetch(`${base}/api/targets?limit=100`);
      expect(r.status).toBe(200);
      const by = Object.fromEntries(((await r.json()) as any).rows.map((x: any) => [x.target, x]));
      expect(by['silent.example'].unreachableSince).toBe(S);
      expect(by['portrow.example'].unreachableSince).toBeNull();
      expect(by['httprow.example'].unreachableSince).toBeNull();
    }, 40_000);

    it('answers /api/targets with 200 when ports or http_probes is missing', async () => {
      for (const drop of ['ports', 'http_probes']) {
        const base = await startUi(seedReach((raw) => { noIp(raw); raw.exec(`DROP TABLE ${drop}`); }));
        const r = await fetch(`${base}/api/targets?limit=100`);
        expect(r.status).toBe(200);
        const by = Object.fromEntries(((await r.json()) as any).rows.map((x: any) => [x.target, x]));
        expect(by['silent.example'].unreachableSince).toBe(S);
      }
    }, 120_000);
  });
});

describe('GET /api/target score dates', () => {
  const addScore = (raw: ReturnType<typeof openDb>['raw'], target: string, at: string) =>
    raw
      .prepare(`INSERT INTO risk_scores (target, score, breakdown_json, computed_at) VALUES (?, 10, '{}', ?)`)
      .run(target, at);

  it('keeps created and updated from risk_latest when the older risk_scores rows are gone', async () => {
    const base = await startUi(
      seed(false, (raw) => {
        raw.prepare(`UPDATE risk_latest SET created_at = ?, updated_at = ? WHERE target = 'host.example'`)
          .run('2026-08-01T00:00:00.000Z', '2026-11-09T00:00:00.000Z');
        addScore(raw, 'host.example', '2026-10-20T00:00:00.000Z');
      }),
    );
    const d = (await (await fetch(`${base}/api/target?t=host.example`)).json()) as any;
    expect(d.created_at).toBe('2026-08-01T00:00:00.000Z');
    expect(d.updated_at).toBe('2026-11-09T00:00:00.000Z');
  }, 40_000);

  it('takes a URL target dates from risk_scores, which risk_latest never holds', async () => {
    const base = await startUi(
      seed(false, (raw) => {
        addScore(raw, 'https://url.example', '2026-09-01T00:00:00.000Z');
        addScore(raw, 'https://url.example', '2026-11-02T00:00:00.000Z');
      }),
    );
    const d = (await (await fetch(`${base}/api/target?t=${encodeURIComponent('https://url.example')}`)).json()) as any;
    expect(d.created_at).toBe('2026-09-01T00:00:00.000Z');
    expect(d.updated_at).toBe('2026-11-02T00:00:00.000Z');
  }, 40_000);
});

describe('findings open/resolved follows tool_coverage', () => {
  const seedCoverage = (dropTable: boolean) =>
    seed(false, (raw) => {
      const ins = raw.prepare(
        `INSERT INTO findings (target, tool, severity, category, title, seen_at)
         VALUES ('host.example', ?, 'high', 'cve', ?, ?)`,
      );
      ins.run('version-match', 'gone', iso(5));
      ins.run('version-match', 'kept', iso(2));
      ins.run('version-match', 'current', iso(1));
      ins.run('nuclei', 'n1', iso(5));
      ins.run('manual', 'm1', iso(10));
      ins.run('checkdmarc', 'd1', iso(5));
      const cov = raw.prepare('INSERT INTO tool_coverage (target, tool, seen_at, run_id) VALUES (?, ?, ?, NULL)');
      cov.run('host.example', 'version-match', iso(1));
      cov.run('host.example', 'manual', iso(0));
      cov.run('host.example', 'checkdmarc', iso(1));
      if (dropTable) raw.exec('DROP TABLE tool_coverage');
    });
  const statusOf = (rows: { title: string; resolved: number }[]) =>
    Object.fromEntries(rows.map((r) => [r.title, r.resolved]));

  it('closes what a conclusive run no longer reports in /api/target and /api/findings', async () => {
    const base = await startUi(seedCoverage(false));
    const d = (await (await fetch(`${base}/api/target?t=host.example`)).json()) as any;
    expect(statusOf(d.findings)).toEqual({ gone: 1, kept: 1, current: 0, n1: 0, m1: 0, d1: 1 });
    expect(d.findingsSummary).toEqual({ open: 3, resolved: 3 });
    const open = (await (await fetch(`${base}/api/findings?status=open&limit=100`)).json()) as any;
    expect(open.rows.map((r: any) => r.title).sort()).toEqual(['current', 'm1', 'n1']);
    expect(open.statusCounts).toEqual({ open: 3, resolved: 3 });
  }, 40_000);

  it('answers 200 and falls back to the newest row per tool when the table is missing', async () => {
    const base = await startUi(seedCoverage(true));
    const r = await fetch(`${base}/api/target?t=host.example`);
    expect(r.status).toBe(200);
    const d = (await r.json()) as any;
    expect(statusOf(d.findings)).toEqual({ gone: 1, kept: 1, current: 0, n1: 0, m1: 0, d1: 0 });
    const l = await fetch(`${base}/api/findings?status=open&limit=100`);
    expect(l.status).toBe(200);
    expect(((await l.json()) as any).rows.map((x: any) => x.title).sort()).toEqual(['current', 'd1', 'm1', 'n1']);
  }, 40_000);
});

describe('overview and targets count open findings', () => {
  const seedCounts = (dropTable: boolean) =>
    seed(false, (raw) => {
      const ins = raw.prepare(
        `INSERT INTO findings (target, tool, severity, category, title, cve, seen_at)
         VALUES ('host.example', ?, ?, 'cve', ?, ?, ?)`,
      );
      ins.run('nuclei', 'critical', 'old', 'CVE-2026-0001', iso(5));
      ins.run('nuclei', 'high', 'kept', 'CVE-2026-0002', iso(5));
      ins.run('nuclei', 'high', 'kept', 'CVE-2026-0002', iso(1));
      ins.run('version-match', 'critical', 'covered', 'CVE-2026-0003', iso(5));
      raw.prepare('INSERT INTO tool_coverage (target, tool, seen_at, run_id) VALUES (?, ?, ?, NULL)')
        .run('host.example', 'version-match', iso(1));
      if (dropTable) raw.exec('DROP TABLE tool_coverage');
    });

  it('shows open counts in /api/overview and /api/targets', async () => {
    const base = await startUi(seedCounts(false));
    const o = (await (await fetch(`${base}/api/overview`)).json()) as any;
    expect(o.severity).toMatchObject({ critical: 0, high: 1 });
    expect(o.recentTargets.find((t: any) => t.target === 'host.example')).toMatchObject({ critical: 0, high: 1, findings: 1 });
    const t = (await (await fetch(`${base}/api/targets?limit=100`)).json()) as any;
    expect(t.rows.find((r: any) => r.target === 'host.example')).toMatchObject({ critical: 0, high: 1, findings: 1, cves: 1 });
  }, 40_000);

  it('answers 200 with rule 3 counts when tool_coverage is missing', async () => {
    const base = await startUi(seedCounts(true));
    const o = await fetch(`${base}/api/overview`);
    expect(o.status).toBe(200);
    expect(((await o.json()) as any).severity).toMatchObject({ critical: 1, high: 1 });
    const t = (await (await fetch(`${base}/api/targets?limit=100`)).json()) as any;
    expect(t.rows.find((r: any) => r.target === 'host.example')).toMatchObject({ critical: 1, high: 1, findings: 2 });
  }, 40_000);
});
