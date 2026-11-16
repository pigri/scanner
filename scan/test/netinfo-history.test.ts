import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb, type Db } from '../src/lib/db.js';
import { runNetinfo } from '../src/lib/netinfo.js';
import type { GeoLookup, GeoRow } from '../src/lib/geoip.js';

const T0 = '2026-11-01T00:00:00.000Z';
const T1 = '2026-11-05T00:00:00.000Z';
const T2 = '2026-11-09T00:00:00.000Z';
const NOW = new Date('2026-11-10T12:00:00.000Z');
const LATER = new Date('2026-11-11T12:00:00.000Z');

type Ev = {
  target: string; ip: string; kind: string; at: string;
  old_country_code: string | null; new_country_code: string | null;
  old_asn: string | null; new_asn: string | null; run_id: number | null; source: string;
};

const events = (db: Db): Ev[] =>
  db.raw.prepare('SELECT target, ip, kind, at, old_country_code, new_country_code, old_asn, new_asn, run_id, source FROM target_network_events ORDER BY id').all() as Ev[];
const kinds = (db: Db): string[] => events(db).map((e) => `${e.kind}@${e.at}`);

const port = (db: Db, target: string, ip: string, at: string) =>
  db.insertPort({ target, ip, port: 443, protocol: 'tcp' }, at, null);
const inProgress = (db: Db, target: string, startedAt: string) =>
  db.raw.prepare("INSERT OR REPLACE INTO scan_queue (target, queued_at, status, started_at) VALUES (?, ?, 'in_progress', ?)").run(target, T0, startedAt);

const geo = (table: Record<string, GeoRow>): GeoLookup => ({ buildAt: null, get: (ip) => table[ip] ?? null });
const AS1: GeoRow = { asn: 'AS64496', as_name: 'Example Net', as_domain: 'example.net', country_code: 'XA', country: 'Exampleland' };
const AS2: GeoRow = { asn: 'AS64497', as_name: 'Other Net', as_domain: 'other.example', country_code: 'XB', country: 'Otherland' };

describe('netinfo events: ip_added and geo_changed', () => {
  it('records ip_added at first_seen with the looked-up geo, the run id and source scan', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    port(db, 'a.example', '192.0.2.10', T1);
    runNetinfo({ db, targets: ['a.example'], geo: geo({ '192.0.2.10': AS1 }), now: NOW, runId: null });
    expect(events(db)).toEqual([{
      target: 'a.example', ip: '192.0.2.10', kind: 'ip_added', at: T0,
      old_country_code: null, new_country_code: 'XA', old_asn: null, new_asn: 'AS64496', run_id: null, source: 'scan',
    }]);
  });

  it('stores the netinfo run id on the event', () => {
    const db = openDb(':memory:');
    const runId = db.startRun('netinfo', {}, T0);
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW, runId });
    expect(events(db)[0]!.run_id).toBe(runId);
  });

  it('adds nothing on a second identical run', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    const g = geo({ '192.0.2.10': AS1 });
    runNetinfo({ db, targets: ['a.example'], geo: g, now: NOW });
    runNetinfo({ db, targets: ['a.example'], geo: g, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`]);
  });

  it('records geo_changed at now when a swapped database answers differently', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: geo({ '192.0.2.10': AS1 }), now: NOW });
    runNetinfo({ db, targets: ['a.example'], geo: geo({ '192.0.2.10': AS2 }), now: LATER });
    expect(events(db)[1]).toMatchObject({
      kind: 'geo_changed', at: LATER.toISOString(), old_country_code: 'XA', new_country_code: 'XB',
      old_asn: 'AS64496', new_asn: 'AS64497', source: 'scan',
    });
    expect(events(db)).toHaveLength(2);
  });

  it('records geo_changed when only the asn differs', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: geo({ '192.0.2.10': AS1 }), now: NOW });
    runNetinfo({ db, targets: ['a.example'], geo: geo({ '192.0.2.10': { ...AS1, asn: 'AS64498' } }), now: LATER });
    expect(events(db)[1]).toMatchObject({ kind: 'geo_changed', old_country_code: 'XA', new_country_code: 'XA', old_asn: 'AS64496', new_asn: 'AS64498' });
  });

  it('emits no geo_changed without a lookup, or when the stored geo was empty', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    runNetinfo({ db, targets: ['a.example'], geo: geo({ '192.0.2.10': AS1 }), now: NOW });
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`]);
  });

  it('emits no geo_changed for an unchanged lookup', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: geo({ '192.0.2.10': AS1 }), now: NOW });
    runNetinfo({ db, targets: ['a.example'], geo: geo({ '192.0.2.10': { ...AS1, as_name: 'Renamed' } }), now: LATER });
    expect(events(db)).toHaveLength(1);
  });

  it('records ip_added for a row that appears later, and nothing for the existing one', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    port(db, 'a.example', '198.51.100.7', T2);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(events(db).map((e) => [e.ip, e.kind, e.at])).toEqual([
      ['192.0.2.10', 'ip_added', T0],
      ['198.51.100.7', 'ip_added', T2],
    ]);
  });
});

describe('netinfo events: ip_gone and ip_back (--targets in a worker batch)', () => {
  it('records ip_gone at the batch start for an ip the batch did not see', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    inProgress(db, 'a.example', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_gone@${T1}`]);
    expect(events(db)[1]).toMatchObject({ source: 'scan', ip: '192.0.2.10' });
  });

  it('does not repeat ip_gone while the ip stays unseen', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    inProgress(db, 'a.example', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    inProgress(db, 'a.example', T2);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_gone@${T1}`]);
  });

  it('records ip_back when a gone ip is seen in a later batch', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    inProgress(db, 'a.example', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    port(db, 'a.example', '192.0.2.10', '2026-11-09T00:05:00.000Z');
    inProgress(db, 'a.example', T2);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_gone@${T1}`, `ip_back@${T2}`]);
  });

  it('treats last_seen equal to the batch start as present', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T1);
    inProgress(db, 'a.example', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    expect(kinds(db)).toEqual([`ip_added@${T1}`]);
  });

  it('emits no ip_gone when dns status is unknown', () => {
    const db = openDb(':memory:');
    db.raw.prepare("INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES ('a.example','a.example','A','192.0.2.10',?,NULL)").run(T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    inProgress(db, 'a.example', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`]);
  });

  it('emits ip_gone for an untracked dns target once the scan is after tracking began', () => {
    const db = openDb(':memory:');
    db.raw.prepare("INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES ('a.example','a.example','A','192.0.2.10',?,NULL)").run(T0);
    db.raw.prepare("INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES ('b.example','b.example','A','198.51.100.1',?,?)").run(T0, T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    inProgress(db, 'a.example', T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_gone@${T1}`]);
  });

  it('emits nothing when the target has no in_progress row', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    db.raw.prepare("INSERT INTO scan_queue (target, queued_at, status, started_at) VALUES ('a.example', ?, 'done', ?)").run(T0, T1);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`]);
  });

  it('emits no ip_gone or ip_back in --all mode', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    db.raw.prepare("INSERT INTO scan_queue (target, queued_at, status, started_at) VALUES ('a.example', ?, 'in_progress', ?)").run(T0, T1);
    runNetinfo({ db, targets: 'all', geo: null, now: NOW });
    runNetinfo({ db, targets: 'all', geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`]);
    // Make it gone via a targets run, then see it again in --all: still no back.
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_gone@${T1}`]);
    port(db, 'a.example', '192.0.2.10', T2);
    runNetinfo({ db, targets: 'all', geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_gone@${T1}`]);
  });
});

describe('netinfo events: gone and back alongside reconstructed events', () => {
  const recon = (db: Db, kind: string, at: string) =>
    db.raw.prepare("INSERT INTO target_network_events (target, ip, kind, at, source) VALUES ('a.example', '192.0.2.10', ?, ?, 'reconstructed')").run(kind, at);

  it('writes no second ip_gone when the latest event, from either source, is already a gone', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    recon(db, 'ip_gone', T1);
    inProgress(db, 'a.example', T2);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_gone@${T1}`]);
  });

  it('writes ip_back when the latest event is a reconstructed gone and the ip is seen again', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    recon(db, 'ip_gone', T1);
    port(db, 'a.example', '192.0.2.10', '2026-11-09T00:05:00.000Z');
    inProgress(db, 'a.example', T2);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_gone@${T1}`, `ip_back@${T2}`]);
  });

  it('writes no ip_back when the latest event, from either source, is a present one', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    recon(db, 'ip_back', T1);
    port(db, 'a.example', '192.0.2.10', '2026-11-09T00:05:00.000Z');
    inProgress(db, 'a.example', T2);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: LATER });
    expect(kinds(db)).toEqual([`ip_added@${T0}`, `ip_back@${T1}`]);
  });
});

describe('netinfo events: writes', () => {
  it('writes events in the same transaction as the upsert', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', T0);
    port(db, 'a.example', '192.0.2.11', T0);
    let txs = 0;
    const spy = db.raw.transaction.bind(db.raw);
    (db.raw as unknown as { transaction: typeof spy }).transaction = ((fn: never) => { txs++; return spy(fn); }) as typeof spy;
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW, chunkSize: 1 });
    expect(txs).toBe(2);
    expect(events(db)).toHaveLength(2);
  });

  it('creates the table on open for a database that predates it, and reopening is a no-op', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'netinfo-hist-'));
    try {
      const file = path.join(dir, 'scan.db');
      const first = openDb(file);
      first.raw.exec('DROP TABLE target_network_events');
      first.close();
      const second = openDb(file);
      expect(() => second.raw.prepare('SELECT count(*) FROM target_network_events').get()).not.toThrow();
      second.close();
      const third = openDb(file);
      third.close();
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
