import { describe, it, expect } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { runNetinfo } from '../src/lib/netinfo.js';
import type { GeoLookup, GeoRow } from '../src/lib/geoip.js';

const T0 = '2026-11-01T00:00:00.000Z';
const T1 = '2026-11-05T00:00:00.000Z';
const T2 = '2026-11-09T00:00:00.000Z';
const NOW = new Date('2026-11-10T12:00:00.000Z');
const NOW_ISO = NOW.toISOString();

type Row = {
  target: string; ip: string; ip_version: number; ip_class: string;
  asn: string | null; as_name: string | null; as_domain: string | null;
  country_code: string | null; country: string | null; geo_checked_at: string | null;
  ptr_json: string | null; from_ports: number; from_dns: number; first_seen: string; last_seen: string;
};

const rows = (db: Db, where = '1=1'): Row[] =>
  db.raw.prepare(`SELECT * FROM target_network WHERE ${where} ORDER BY target, ip`).all() as Row[];

const port = (db: Db, target: string, ip: string | null, at: string) =>
  db.insertPort({ target, ip, port: 443, protocol: 'tcp' }, at, null);
const dns = (db: Db, target: string, type: string, value: string, at: string) =>
  db.insertDnsRecord({ target, name: target, type, value }, at, null);

function fakeGeo(table: Record<string, GeoRow>): GeoLookup & { calls: string[] } {
  const calls: string[] = [];
  return { calls, buildAt: null, get: (ip) => { calls.push(ip); return table[ip] ?? null; } };
}

const AS1: GeoRow = { asn: 'AS64496', as_name: 'Example Net', as_domain: 'example.net', country_code: 'XX', country: 'Exampleland' };

describe('runNetinfo evidence', () => {
  it('merges ports and dns evidence for v4 and v6 with flags and times', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    port(db, 'a.example', '192.0.2.10', T1);
    dns(db, 'a.example', 'A', '192.0.2.10', T0);
    dns(db, 'a.example', 'A', '192.0.2.10', T2);
    dns(db, 'a.example', 'AAAA', '2001:db8::10', T1);
    dns(db, 'a.example', 'CNAME', 'b.example', T1);
    port(db, 'other.example', '198.51.100.1', T1);

    const r = runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });

    expect(r).toMatchObject({ targets: 1, rowsWritten: 2, skippedInvalid: 0 });
    const out = rows(db);
    expect(out.map((x) => [x.target, x.ip, x.ip_version, x.from_ports, x.from_dns, x.first_seen, x.last_seen])).toEqual([
      ['a.example', '192.0.2.10', 4, 1, 1, T0, T2],
      ['a.example', '2001:db8::10', 6, 0, 1, T1, T1],
    ]);
    expect(out.every((x) => x.ptr_json === null)).toBe(true);
  });

  it('uses seen_at when a dns row has no last_seen', () => {
    const db = openDb(':memory:');
    db.raw.prepare("INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES ('a.example','a.example','A','192.0.2.10',?,NULL)").run(T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    expect(rows(db)[0]).toMatchObject({ first_seen: T1, last_seen: T1 });
  });

  it('collapses two textual forms of one IPv6 address into one row', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '2001:DB8:0:0:0:0:0:1', T0);
    dns(db, 'a.example', 'AAAA', '2001:db8::1', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    expect(rows(db)).toHaveLength(1);
    expect(rows(db)[0]).toMatchObject({ ip: '2001:db8::1', from_ports: 1, from_dns: 1, first_seen: T0, last_seen: T1 });
  });

  it('skips and counts invalid ports.ip values without throwing', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    port(db, 'a.example', 'not-an-ip', T0);
    port(db, 'a.example', '192.0.2.1/24', T0);
    port(db, 'a.example', '', T0);
    port(db, 'a.example', null, T0);
    const r = runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    expect(r.skippedInvalid).toBe(2);
    expect(rows(db).map((x) => x.ip)).toEqual(['192.0.2.10']);
  });

  it('gives an IP-literal target an identity row even without evidence', () => {
    const db = openDb(':memory:');
    const r = runNetinfo({ db, targets: ['192.0.2.20', '[2001:db8::20]', 'nothing.example'], geo: null, now: NOW });
    expect(r.targets).toBe(3);
    expect(rows(db).map((x) => [x.target, x.ip, x.from_ports, x.from_dns, x.first_seen, x.last_seen])).toEqual([
      ['192.0.2.20', '192.0.2.20', 0, 0, NOW_ISO, NOW_ISO],
      ['[2001:db8::20]', '2001:db8::20', 0, 0, NOW_ISO, NOW_ISO],
    ]);
  });

  it('keeps the old row, with its old last_seen, when the IP changes', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    port(db, 'a.example', '192.0.2.11', T2);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    expect(rows(db).map((x) => [x.ip, x.last_seen])).toEqual([['192.0.2.10', T0], ['192.0.2.11', T2]]);
  });
});

describe('runNetinfo upsert', () => {
  it('keeps the earliest first_seen and the latest last_seen when evidence is later pruned', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    port(db, 'a.example', '192.0.2.10', T2);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    db.raw.prepare('DELETE FROM ports').run();
    port(db, 'a.example', '192.0.2.10', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    expect(rows(db)[0]).toMatchObject({ first_seen: T0, last_seen: T2 });
  });

  it('keeps a source flag once set', () => {
    const db = openDb(':memory:');
    dns(db, 'a.example', 'A', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    db.raw.prepare('DELETE FROM dns_records').run();
    port(db, 'a.example', '192.0.2.10', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    expect(rows(db)[0]).toMatchObject({ from_dns: 1, from_ports: 1 });
  });
});

describe('runNetinfo geo', () => {
  it('records hit, miss and no-mmdb as three distinct states', () => {
    const db = openDb(':memory:');
    port(db, 'hit.example', '192.0.2.10', T0);
    port(db, 'miss.example', '192.0.2.11', T0);
    port(db, 'none.example', '192.0.2.12', T0);
    const geo = fakeGeo({ '192.0.2.10': AS1 });

    runNetinfo({ db, targets: ['hit.example', 'miss.example'], geo, now: NOW });
    runNetinfo({ db, targets: ['none.example'], geo: null, now: NOW });

    const by = Object.fromEntries(rows(db).map((x) => [x.target, x]));
    expect(by['hit.example']).toMatchObject({ asn: 'AS64496', as_name: 'Example Net', as_domain: 'example.net', country_code: 'XX', country: 'Exampleland', geo_checked_at: NOW_ISO });
    expect(by['miss.example']).toMatchObject({ asn: null, country_code: null, geo_checked_at: NOW_ISO });
    expect(by['none.example']).toMatchObject({ asn: null, country_code: null, geo_checked_at: null });
  });

  it('counts geo hits and misses', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    port(db, 'a.example', '192.0.2.11', T0);
    const r = runNetinfo({ db, targets: ['a.example'], geo: fakeGeo({ '192.0.2.10': AS1 }), now: NOW });
    expect(r).toMatchObject({ geoHits: 1, geoMisses: 1 });
  });

  it('never passes a non-public ip to the lookup', () => {
    const db = openDb(':memory:');
    for (const ip of ['10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.1.1', '224.0.0.1', '0.0.0.0', '240.0.0.1', 'fc00::1', 'fe80::1', '::1']) port(db, 'a.example', ip, T0);
    port(db, 'a.example', '192.0.2.10', T0);
    const geo = fakeGeo({});
    runNetinfo({ db, targets: ['a.example'], geo, now: NOW });
    expect(geo.calls).toEqual(['192.0.2.10']);
    const nonPublic = rows(db, "ip_class != 'public'");
    expect(nonPublic).toHaveLength(10);
    expect(nonPublic.every((x) => x.geo_checked_at === null && x.asn === null)).toBe(true);
    expect(new Set(nonPublic.map((x) => x.ip_class))).toEqual(new Set(['private', 'cgnat', 'loopback', 'link-local', 'multicast', 'unspecified', 'reserved']));
  });

  it('keeps stored geo when a later run has no lookup', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: fakeGeo({ '192.0.2.10': AS1 }), now: NOW });
    const before = rows(db);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: new Date('2026-11-11T00:00:00.000Z') });
    expect(rows(db)).toEqual(before);
  });

  it('replaces stored geo when a later lookup answers differently', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: fakeGeo({ '192.0.2.10': AS1 }), now: NOW });
    runNetinfo({ db, targets: ['a.example'], geo: fakeGeo({}), now: NOW });
    expect(rows(db)[0]).toMatchObject({ asn: null, country_code: null, geo_checked_at: NOW_ISO });
  });

  it('changes only geo_checked_at on an identical second run', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    dns(db, 'a.example', 'AAAA', '2001:db8::1', T1);
    const geo = fakeGeo({ '192.0.2.10': AS1 });
    runNetinfo({ db, targets: ['a.example'], geo, now: NOW });
    const before = rows(db);
    runNetinfo({ db, targets: ['a.example'], geo, now: new Date('2026-11-11T00:00:00.000Z') });
    const after = rows(db);
    expect(after.map((x) => ({ ...x, geo_checked_at: null }))).toEqual(before.map((x) => ({ ...x, geo_checked_at: null })));
    expect(after.map((x) => x.geo_checked_at)).toEqual(['2026-11-11T00:00:00.000Z', '2026-11-11T00:00:00.000Z']);
  });

  it('does not touch ptr_json', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    db.raw.prepare("UPDATE target_network SET ptr_json = '[\"host.example\"]'").run();
    runNetinfo({ db, targets: ['a.example'], geo: fakeGeo({ '192.0.2.10': AS1 }), now: NOW });
    expect(rows(db)[0]!.ptr_json).toBe('["host.example"]');
  });
});

describe('runNetinfo writes', () => {
  it('writes in chunks of the given size', () => {
    const db = openDb(':memory:');
    for (let i = 1; i <= 7; i++) port(db, 'a.example', `192.0.2.${i}`, T0);
    let txs = 0;
    const spy = db.raw.transaction.bind(db.raw);
    (db.raw as unknown as { transaction: typeof spy }).transaction = ((fn: never) => { txs++; return spy(fn); }) as typeof spy;
    const r = runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW, chunkSize: 3 });
    expect(r.rowsWritten).toBe(7);
    expect(rows(db)).toHaveLength(7);
    expect(txs).toBe(3);
  });

  it('sets a long busy_timeout on the connection', () => {
    const db = openDb(':memory:');
    runNetinfo({ db, targets: [], geo: null, now: NOW });
    expect(db.raw.pragma('busy_timeout', { simple: true })).toBe(60000);
  });

  it('does all lookups before any write', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    port(db, 'b.example', '192.0.2.11', T0);
    const seen: number[] = [];
    const geo: GeoLookup = {
      buildAt: null,
      get: () => { seen.push((db.raw.prepare('SELECT count(*) n FROM target_network').get() as { n: number }).n); return null; },
    };
    runNetinfo({ db, targets: ['a.example', 'b.example'], geo, now: NOW, chunkSize: 1 });
    expect(seen).toEqual([0, 0]);
  });
});

describe('runNetinfo --all', () => {
  it('reads targets from scan_queue and times identity rows from the queue', () => {
    const db = openDb(':memory:');
    const q = db.raw.prepare('INSERT INTO scan_queue (target, queued_at, started_at, finished_at) VALUES (?,?,?,?)');
    q.run('a.example', T0, null, null);
    q.run('192.0.2.30', T0, T1, T2);
    q.run('192.0.2.31', T0, T1, null);
    q.run('192.0.2.32', T0, null, null);
    port(db, 'a.example', '192.0.2.10', T0);
    port(db, 'unqueued.example', '192.0.2.99', T0);

    const r = runNetinfo({ db, targets: 'all', geo: null, now: NOW });

    expect(r.targets).toBe(4);
    expect(rows(db).map((x) => [x.target, x.ip, x.first_seen, x.last_seen])).toEqual([
      ['192.0.2.30', '192.0.2.30', T2, T2],
      ['192.0.2.31', '192.0.2.31', T1, T1],
      ['192.0.2.32', '192.0.2.32', T0, T0],
      ['a.example', '192.0.2.10', T0, T0],
    ]);
  });
});
