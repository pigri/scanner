import { describe, it, expect, beforeEach } from 'vitest';
import { openDb, readEnrichedFromDb, type Db } from '../src/lib/db.js';

let db: Db;
beforeEach(() => {
  db = openDb(':memory:');
});

describe('openDb', () => {
  it('creates required tables', () => {
    const tables = db.raw
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all()
      .map((r: any) => r.name);
    expect(tables).toContain('hosts');
    expect(tables).toContain('sources');
    expect(tables).toContain('ips');
    expect(tables).toContain('resolutions');
    expect(tables).toContain('ptr_records');
    expect(tables).toContain('runs');
  });
});

describe('upsertHost', () => {
  it('inserts a new host and records the source', () => {
    const id = db.upsertHost('foo.example.com', 'ddg', '2026-08-01T00:00:00Z');
    expect(typeof id).toBe('number');
    const row = db.raw.prepare('SELECT * FROM hosts WHERE id = ?').get(id) as any;
    expect(row.name).toBe('foo.example.com');
    expect(row.first_seen).toBe('2026-08-01T00:00:00Z');
    expect(row.last_seen).toBe('2026-08-01T00:00:00Z');
    const sources = db.raw.prepare('SELECT source FROM sources WHERE host_id = ?').all(id);
    expect(sources).toEqual([{ source: 'ddg' }]);
  });

  it('updates last_seen and appends source on re-insert', () => {
    const id = db.upsertHost('foo.example.com', 'ddg', '2026-08-01T00:00:00Z');
    const id2 = db.upsertHost('foo.example.com', 'ct-certspotter', '2026-08-10T00:00:00Z');
    expect(id2).toBe(id);
    const row = db.raw.prepare('SELECT first_seen, last_seen FROM hosts WHERE id = ?').get(id) as any;
    expect(row.first_seen).toBe('2026-08-01T00:00:00Z');
    expect(row.last_seen).toBe('2026-08-10T00:00:00Z');
    const sources = db.raw.prepare('SELECT source FROM sources WHERE host_id = ? ORDER BY id').all(id);
    expect(sources).toEqual([{ source: 'ddg' }, { source: 'ct-certspotter' }]);
  });
});

describe('upsertIp', () => {
  it('inserts IP with geo attributes', () => {
    db.upsertIp('1.2.3.4', {
      family: 4,
      asn: 'AS100', as_name: 'Example', as_domain: 'example.com',
      country_code: 'HU', country: 'Hungary', continent_code: 'EU',
    }, '2026-08-01T00:00:00Z');
    const row = db.raw.prepare('SELECT * FROM ips WHERE ip = ?').get('1.2.3.4') as any;
    expect(row.asn).toBe('AS100');
    expect(row.country_code).toBe('HU');
    expect(row.first_seen).toBe('2026-08-01T00:00:00Z');
  });

  it('updates last_seen and geo on re-insert', () => {
    db.upsertIp('1.2.3.4', { family: 4, asn: 'AS100' } as any, '2026-08-01T00:00:00Z');
    db.upsertIp('1.2.3.4', { family: 4, asn: 'AS200' } as any, '2026-08-15T00:00:00Z');
    const row = db.raw.prepare('SELECT asn, first_seen, last_seen FROM ips WHERE ip = ?').get('1.2.3.4') as any;
    expect(row.asn).toBe('AS200');
    expect(row.first_seen).toBe('2026-08-01T00:00:00Z');
    expect(row.last_seen).toBe('2026-08-15T00:00:00Z');
  });
});

describe('addResolution + addPtr', () => {
  it('logs a resolution row', () => {
    const hid = db.upsertHost('foo.example.com', 'ddg', '2026-08-01T00:00:00Z');
    db.upsertIp('1.2.3.4', { family: 4 } as any, '2026-08-01T00:00:00Z');
    db.addResolution(hid, '1.2.3.4', 4, '2026-08-01T00:00:00Z');
    db.addResolution(hid, '1.2.3.4', 4, '2026-08-02T00:00:00Z');
    const rows = db.raw.prepare('SELECT * FROM resolutions WHERE host_id = ? ORDER BY seen_at').all(hid) as any[];
    expect(rows).toHaveLength(2);
  });
  it('logs PTR observations', () => {
    db.addPtr('1.2.3.4', 'host.example.com', '2026-08-01T00:00:00Z');
    const rows = db.raw.prepare('SELECT * FROM ptr_records WHERE ip = ?').all('1.2.3.4') as any[];
    expect(rows).toHaveLength(1);
    expect(rows[0].name).toBe('host.example.com');
  });
});

describe('date-range queries', () => {
  beforeEach(() => {
    db.upsertHost('old.example.com', 'ddg', '2026-01-01T00:00:00Z');
    db.upsertHost('mid.example.com', 'ddg', '2026-06-01T00:00:00Z');
    db.upsertHost('new.example.com', 'ddg', '2026-08-15T00:00:00Z');
  });

  it('hostsFirstSeenBetween returns hosts within an inclusive range', () => {
    const rows = db.hostsFirstSeenBetween('2026-05-01T00:00:00Z', '2026-08-01T00:00:00Z');
    expect(rows.map((r) => r.name)).toEqual(['mid.example.com']);
  });

  it('hostsFirstSeenBetween with only start date', () => {
    const rows = db.hostsFirstSeenBetween('2026-07-01T00:00:00Z', null);
    expect(rows.map((r) => r.name).sort()).toEqual(['new.example.com']);
  });

  it('countBySource returns aggregated counts', () => {
    db.upsertHost('a.example.com', 'ct-certspotter', '2026-08-01T00:00:00Z');
    db.upsertHost('b.example.com', 'ct-certspotter', '2026-08-01T00:00:00Z');
    const counts = db.countBySource();
    expect(counts).toContainEqual({ source: 'ct-certspotter', n: 2 });
    expect(counts.find((c) => c.source === 'ddg')?.n).toBe(3);
  });
});

describe('readEnrichedFromDb', () => {
  beforeEach(() => {
    const hid = db.upsertHost('foo.example.com', 'ddg', '2026-08-01T00:00:00Z');
    db.upsertIp('1.2.3.4', { family: 4, asn: 'AS100', as_name: 'Example', country_code: 'HU', country: 'Hungary', continent_code: 'EU' }, '2026-08-01T00:00:00Z');
    db.addResolution(hid, '1.2.3.4', 4, '2026-08-01T00:00:00Z');
    db.addPtr('1.2.3.4', 'reverse.example.com', '2026-08-01T00:00:00Z');

    const hid2 = db.upsertHost('bar.example.com', 'ct-certspotter', '2026-08-15T00:00:00Z');
    db.upsertIp('5.6.7.8', { family: 4, asn: 'AS200' }, '2026-08-15T00:00:00Z');
    db.addResolution(hid2, '5.6.7.8', 4, '2026-08-15T00:00:00Z');
  });

  it('returns EnrichedRow[] shaped for buildGraph', () => {
    const rows = readEnrichedFromDb(db);
    expect(rows).toHaveLength(2);
    const foo = rows.find((r) => r.domain === 'foo.example.com')!;
    expect(foo.addresses).toHaveLength(1);
    expect(foo.addresses[0]!.ip).toBe('1.2.3.4');
    expect(foo.addresses[0]!.asn).toBe('AS100');
    expect(foo.addresses[0]!.ptr).toContain('reverse.example.com');
  });

  it('filters by resolution date window', () => {
    const rows = readEnrichedFromDb(db, { since: '2026-08-10T00:00:00Z', until: null });
    expect(rows.map((r) => r.domain)).toEqual(['bar.example.com']);
  });

  it('returns empty when window excludes everything', () => {
    const rows = readEnrichedFromDb(db, { since: '2027-01-01T00:00:00Z', until: null });
    expect(rows).toEqual([]);
  });
});

describe('startRun / finishRun', () => {
  it('records a run with duration + delta', () => {
    const runId = db.startRun('refresh', { seclist: 'top-5000' }, '2026-08-19T00:00:00Z');
    db.finishRun(runId, { addedHosts: 42, addedIps: 10, notes: 'ok', at: '2026-08-19T00:01:00Z' });
    const row = db.raw.prepare('SELECT * FROM runs WHERE id = ?').get(runId) as any;
    expect(row.tool).toBe('refresh');
    expect(row.added_hosts).toBe(42);
    expect(row.finished_at).toBe('2026-08-19T00:01:00Z');
    expect(JSON.parse(row.args_json)).toEqual({ seclist: 'top-5000' });
  });
});
