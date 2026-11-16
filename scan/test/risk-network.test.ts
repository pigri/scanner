import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { openDb, type Db } from '../src/lib/db.js';
import { computeScore, NETWORK_CHANGED_BUMP, type TargetSignals } from '../src/lib/risk.js';
import { recentNetworkChange, pickCountry, type NetworkEvent } from '../src/lib/risk-network.js';
import { loadRiskSignals } from '../src/risk.js';
import { dryRun, formatReport, parseDryRunArgs } from '../src/risk-dry-run.js';

const NOW = '2026-11-16T12:00:00.000Z';
const DAY = 86_400_000;
const ago = (ms: number): string => new Date(Date.parse(NOW) - ms).toISOString();

const ev = (o: Partial<NetworkEvent> & Pick<NetworkEvent, 'kind' | 'at'>): NetworkEvent => ({
  target: 'a.example', ip: '192.0.2.1', old_country_code: null, new_country_code: null,
  old_asn: null, new_asn: null, source: 'scan', run_id: null, ...o,
});

const base = (): TargetSignals => ({
  target: 'a.example', findings: [], ports: [], http: [], hostShared: 0,
  hostCountryCode: null, firstSeen: null, now: NOW,
});

describe('recentNetworkChange', () => {
  it('counts a geo_changed with a new country', () => {
    const r = recentNetworkChange([ev({ kind: 'geo_changed', at: ago(DAY), old_country_code: 'HU', new_country_code: 'DE', old_asn: 'AS64496', new_asn: 'AS64496' })], NOW);
    expect(r.count).toBe(1);
  });
  it('counts a geo_changed with a new ASN only', () => {
    const r = recentNetworkChange([ev({ kind: 'geo_changed', at: ago(DAY), old_country_code: 'HU', new_country_code: 'HU', old_asn: 'AS64496', new_asn: 'AS64497' })], NOW);
    expect(r.count).toBe(1);
  });
  it('ignores a geo_changed that lost its data', () => {
    const r = recentNetworkChange([ev({ kind: 'geo_changed', at: ago(DAY), old_country_code: 'HU', new_country_code: null, old_asn: 'AS64496', new_asn: null })], NOW);
    expect(r.count).toBe(0);
  });
  it('counts an ip_added whose ASN is new to the target', () => {
    const r = recentNetworkChange([
      ev({ kind: 'ip_added', at: ago(60 * DAY), ip: '192.0.2.1', new_asn: 'AS64496' }),
      ev({ kind: 'ip_added', at: ago(2 * DAY), ip: '192.0.2.2', new_asn: 'AS64497' }),
    ], NOW);
    expect(r.count).toBe(1);
  });
  it('does not count an ip_added whose ASN the target already had', () => {
    const r = recentNetworkChange([
      ev({ kind: 'ip_added', at: ago(60 * DAY), ip: '192.0.2.1', new_asn: 'AS64496' }),
      ev({ kind: 'ip_added', at: ago(2 * DAY), ip: '192.0.2.2', new_asn: 'AS64496' }),
    ], NOW);
    expect(r.count).toBe(0);
  });
  it('never counts the first IPs of a new target, even several at once', () => {
    const r = recentNetworkChange([
      ev({ kind: 'ip_added', at: ago(DAY), ip: '192.0.2.1', new_asn: 'AS64496' }),
      ev({ kind: 'ip_added', at: ago(DAY), ip: '198.51.100.1', new_asn: 'AS64497' }),
    ], NOW);
    expect(r.count).toBe(0);
  });
  it('treats an ASN reached through an earlier geo_changed as known', () => {
    const r = recentNetworkChange([
      ev({ kind: 'ip_added', at: ago(80 * DAY), ip: '192.0.2.1', new_asn: 'AS64496' }),
      ev({ kind: 'geo_changed', at: ago(50 * DAY), ip: '192.0.2.1', old_asn: 'AS64496', new_asn: 'AS64498', old_country_code: 'HU', new_country_code: 'HU' }),
      ev({ kind: 'ip_added', at: ago(2 * DAY), ip: '192.0.2.2', new_asn: 'AS64498' }),
    ], NOW);
    expect(r.count).toBe(0);
  });
  it('does not count an ip_added with an unknown ASN', () => {
    const r = recentNetworkChange([
      ev({ kind: 'ip_added', at: ago(60 * DAY), ip: '192.0.2.1', new_asn: 'AS64496' }),
      ev({ kind: 'ip_added', at: ago(2 * DAY), ip: '192.0.2.2', new_asn: null }),
    ], NOW);
    expect(r.count).toBe(0);
  });

  describe('the first batch of a target', () => {
    const MIN = 60_000;
    const H = 3_600_000;
    const add = (hAgo: number, ip: string, asn: string, o: Partial<NetworkEvent> = {}): NetworkEvent =>
      ev({ kind: 'ip_added', at: ago(hAgo * H), ip, new_asn: asn, ...o });
    it('does not count first IPs found minutes apart in different ASNs', () => {
      const r = recentNetworkChange([add(5, '192.0.2.1', 'AS64496'), { ...add(5, '192.0.2.2', 'AS64497'), at: ago(5 * H - 3 * MIN) }], NOW);
      expect(r.count).toBe(0);
    });
    it('does not count first IPs 2 h apart, inside the window', () => {
      expect(recentNetworkChange([add(5, '192.0.2.1', 'AS64496'), add(3, '192.0.2.2', 'AS64497')], NOW).count).toBe(0);
    });
    it('keeps an IP exactly 3 h after the first one in the first batch', () => {
      expect(recentNetworkChange([add(10, '192.0.2.1', 'AS64496'), add(7, '192.0.2.2', 'AS64497')], NOW).count).toBe(0);
    });
    it('counts an IP 3 h and 1 ms after the first one', () => {
      expect(recentNetworkChange([add(10, '192.0.2.1', 'AS64496'), { ...add(7, '192.0.2.2', 'AS64497'), at: ago(7 * H - 1) }], NOW).count).toBe(1);
    });
    it('does not count a same-run first batch spread past the window', () => {
      expect(recentNetworkChange([
        add(20, '192.0.2.1', 'AS64496', { run_id: 7 }),
        add(10, '192.0.2.2', 'AS64497', { run_id: 7 }),
      ], NOW).count).toBe(0);
    });
    it('does not treat the run of a history rebuild as one batch', () => {
      const rec = { run_id: 9, source: 'reconstructed' };
      expect(recentNetworkChange([
        add(20 * 24, '192.0.2.1', 'AS64496', rec),
        add(10 * 24, '192.0.2.2', 'AS64497', rec),
      ], NOW).count).toBe(1);
    });
    it('does not join a reconstructed event to a scan batch by run id', () => {
      expect(recentNetworkChange([
        add(20, '192.0.2.1', 'AS64496', { run_id: 7 }),
        add(10, '192.0.2.2', 'AS64497', { run_id: 7, source: 'reconstructed' }),
      ], NOW).count).toBe(1);
    });
    it('does not join a scan event to a reconstructed first event by run id', () => {
      expect(recentNetworkChange([
        add(20, '192.0.2.1', 'AS64496', { run_id: 7, source: 'reconstructed' }),
        add(10, '192.0.2.2', 'AS64497', { run_id: 7 }),
      ], NOW).count).toBe(1);
    });
    it('counts an IP 4 h after the first batch with a new ASN', () => {
      expect(recentNetworkChange([add(10, '192.0.2.1', 'AS64496'), add(6, '192.0.2.2', 'AS64497')], NOW).count).toBe(1);
    });
    it('uses first-batch ASNs as known', () => {
      expect(recentNetworkChange([add(10, '192.0.2.1', 'AS64496'), add(10, '192.0.2.3', 'AS64497'), add(6, '192.0.2.2', 'AS64497')], NOW).count).toBe(0);
    });
    it('counts the new-ASN IP of a later batch, not its known-ASN neighbour', () => {
      expect(recentNetworkChange([
        add(20, '192.0.2.1', 'AS64496'),
        add(5, '192.0.2.2', 'AS64496'),
        { ...add(5, '192.0.2.3', 'AS64497'), at: ago(5 * H - 3 * MIN) },
      ], NOW).count).toBe(1);
    });
  });

  describe('the 30 day window', () => {
    const e = (at: string): NetworkEvent[] => [ev({ kind: 'geo_changed', at, old_country_code: 'HU', new_country_code: 'DE' })];
    it('includes an event exactly 30 days old', () => {
      expect(recentNetworkChange(e(ago(30 * DAY)), NOW).count).toBe(1);
    });
    it('excludes an event 1 ms older', () => {
      expect(recentNetworkChange(e(ago(30 * DAY + 1)), NOW).count).toBe(0);
    });
    it('applies the same window to reconstructed events', () => {
      const rec = (at: string): NetworkEvent[] => [{ ...e(at)[0]!, source: 'reconstructed' }];
      expect(recentNetworkChange(rec(ago(29 * DAY)), NOW).count).toBe(1);
      expect(recentNetworkChange(rec(ago(31 * DAY)), NOW).count).toBe(0);
    });
    it('ignores an event after now', () => {
      expect(recentNetworkChange(e(new Date(Date.parse(NOW) + 1).toISOString()), NOW).count).toBe(0);
    });
    it('ignores a future event time that cannot be parsed', () => {
      expect(recentNetworkChange(e('not-a-date'), NOW).count).toBe(0);
    });
  });
});

describe('pickCountry', () => {
  it('takes the most frequent country', () => {
    expect(pickCountry(['DE', 'HU', 'HU'])).toEqual({ code: 'HU', counts: { DE: 1, HU: 2 }, tie: false });
  });
  it('breaks a tie by the lowest country code, and says so', () => {
    expect(pickCountry(['HU', 'DE', 'HU', 'DE'])).toEqual({ code: 'DE', counts: { DE: 2, HU: 2 }, tie: true });
  });
  it('is null with no country', () => {
    expect(pickCountry([])).toBeNull();
  });
});

describe('computeScore: networkChanged', () => {
  const changed = { count: 2 };
  it('NETWORK_CHANGED_BUMP is 5', () => {
    expect(NETWORK_CHANGED_BUMP).toBe(5);
  });
  it('adds the default bump once when the target changed network', () => {
    const r = computeScore({ ...base(), networkChange: changed });
    expect(r.score).toBe(computeScore(base()).score + 5);
    expect(r.breakdown.networkChanged).toBe(5);
  });
  it('adds the injected bump once, whatever the event count, and shows it', () => {
    const s = { ...base(), networkChange: changed };
    const r = computeScore(s, { networkChangedBump: 3 });
    expect(r.score).toBe(3);
    expect(r.breakdown.networkChanged).toBe(3);
    expect(r.breakdown.networkChangedEvents).toBe(2);
    expect(r.breakdown.total).toBe(3);
  });
  it('leaves the score unchanged with an injected bump of 0', () => {
    const s = { ...base(), networkChange: changed };
    expect(computeScore(s, { networkChangedBump: 0 }).score).toBe(computeScore(base()).score);
    expect(computeScore(s, { networkChangedBump: 0 }).breakdown.networkChanged).toBe(0);
  });
  it('leaves the score unchanged with no events, even with a bump', () => {
    expect(computeScore(base(), { networkChangedBump: 5 }).score).toBe(0);
    expect(computeScore({ ...base(), networkChange: { count: 0 } }, { networkChangedBump: 5 }).breakdown.networkChanged).toBe(0);
  });
  it('records the country choice in the breakdown', () => {
    const s = { ...base(), hostCountryDetail: { code: 'DE', source: 'network' as const, counts: { DE: 2, HU: 2 }, tie: true } };
    expect(computeScore(s).breakdown.hostCountry).toEqual({ code: 'DE', source: 'network', counts: { DE: 2, HU: 2 }, tie: true });
  });
});

// ---- database fixtures -------------------------------------------------

const T0 = '2026-11-10T00:00:00.000Z';

function addNet(db: Db, target: string, ip: string, cc: string | null, asn: string | null, lastSeen = T0, cls = 'public'): void {
  db.raw.prepare(`INSERT INTO target_network(target, ip, ip_version, ip_class, asn, country_code, first_seen, last_seen)
    VALUES(?, ?, 4, ?, ?, ?, ?, ?)`).run(target, ip, cls, asn, cc, T0, lastSeen);
}
function addScan(db: Db, target: string, startedAt: string): void {
  db.raw.prepare("INSERT INTO scan_queue(target, status, queued_at, started_at) VALUES(?, 'done', ?, ?)").run(target, startedAt, startedAt);
}
function addEvent(db: Db, e: NetworkEvent): void {
  db.raw.prepare(`INSERT INTO target_network_events(target, ip, kind, at, old_country_code, new_country_code, old_asn, new_asn, source)
    VALUES(?,?,?,?,?,?,?,?,?)`).run(e.target, e.ip, e.kind, e.at, e.old_country_code, e.new_country_code, e.old_asn, e.new_asn, e.source);
}
function addFinding(db: Db, target: string): void {
  db.raw.prepare("INSERT INTO findings(tool, target, severity, title, seen_at) VALUES('nuclei', ?, 'low', 't', ?)").run(target, T0);
}
const opts = { discoveryDb: null, hostSuffix: null } as const;
const sig = (db: Db, t: string, source: 'network' | 'discovery' = 'network'): TargetSignals =>
  loadRiskSignals(db.raw, { ...opts, countrySource: source }, NOW).get(t)!;

describe('loadRiskSignals: hostCountryCode from target_network', () => {
  it('uses the most frequent country among current public IPs', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    addNet(db, 'a.example', '192.0.2.1', 'HU', 'AS64496');
    addNet(db, 'a.example', '192.0.2.2', 'HU', 'AS64496');
    addNet(db, 'a.example', '198.51.100.1', 'DE', 'AS64497');
    const s = sig(db, 'a.example');
    expect(s.hostCountryCode).toBe('HU');
    expect(s.hostCountryDetail).toEqual({ code: 'HU', source: 'network', counts: { DE: 1, HU: 2 }, tie: false });
  });
  it('breaks a tie by the lowest code', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    addNet(db, 'a.example', '192.0.2.1', 'HU', 'AS64496');
    addNet(db, 'a.example', '198.51.100.1', 'DE', 'AS64497');
    const s = sig(db, 'a.example');
    expect(s.hostCountryCode).toBe('DE');
    expect(s.hostCountryDetail?.tie).toBe(true);
  });
  it('ignores an IP the latest scan did not see and a non-public IP', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    addScan(db, 'a.example', '2026-11-12T00:00:00.000Z');
    addNet(db, 'a.example', '192.0.2.1', 'HU', 'AS64496', '2026-11-12T01:00:00.000Z');
    addNet(db, 'a.example', '198.51.100.1', 'DE', 'AS64497', T0);             // not seen: 'no'
    addNet(db, 'a.example', '198.51.100.2', 'DE', 'AS64497', '2026-11-12T01:00:00.000Z', 'private');
    expect(sig(db, 'a.example').hostCountryCode).toBe('HU');
  });
  it('applies the 24 h rule when the target has no done scan', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    addNet(db, 'a.example', '192.0.2.1', 'HU', 'AS64496', '2026-11-10T00:00:00.000Z');
    addNet(db, 'a.example', '198.51.100.1', 'DE', 'AS64497', '2026-11-01T00:00:00.000Z');
    expect(sig(db, 'a.example').hostCountryCode).toBe('HU');
  });
  it('counts an unknown-status IP as current', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    db.raw.prepare("INSERT INTO dns_records(target, name, type, value, seen_at, last_seen) VALUES('a.example','a.example','A','192.0.2.1',?,NULL)").run(T0);
    addScan(db, 'a.example', '2026-11-12T00:00:00.000Z');
    addNet(db, 'a.example', '192.0.2.1', 'DE', 'AS64496', T0);
    expect(sig(db, 'a.example').hostCountryCode).toBe('DE');
  });
  it('falls back to the old source when no current IP has a country', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    addNet(db, 'a.example', '192.0.2.1', null, null);
    const s = loadRiskSignals(db.raw, { ...opts, countrySource: 'network' }, NOW).get('a.example')!;
    expect(s.hostCountryCode).toBeNull();
    expect(s.hostCountryDetail?.source).toBe('none');
  });
  it('keeps the old source in discovery mode', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    addNet(db, 'a.example', '192.0.2.1', 'HU', 'AS64496');
    const s = sig(db, 'a.example', 'discovery');
    expect(s.hostCountryCode).toBeNull();
    expect(s.networkChange).toBeUndefined();
  });
  it('survives a database without target_network_events', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    addNet(db, 'a.example', '192.0.2.1', 'HU', 'AS64496');
    db.raw.exec('DROP TABLE target_network_events');
    const s = sig(db, 'a.example');
    expect(s.hostCountryCode).toBe('HU');
    expect(s.networkChange?.count ?? 0).toBe(0);
  });
  it('survives a database without target_network', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    db.raw.exec('DROP TABLE target_network_events; DROP TABLE target_network');
    expect(sig(db, 'a.example').hostCountryCode).toBeNull();
  });
  it('reads events into networkChange', () => {
    const db = openDb(':memory:');
    addFinding(db, 'a.example');
    addEvent(db, ev({ kind: 'geo_changed', at: ago(DAY), old_country_code: 'HU', new_country_code: 'DE' }));
    expect(sig(db, 'a.example').networkChange?.count).toBe(1);
  });
});

describe('dry run', () => {
  const build = (file: string): void => {
    const db = openDb(file);
    for (const t of ['a.example', 'b.example', 'c.example']) addFinding(db, t);
    addNet(db, 'a.example', '192.0.2.1', 'DE', 'AS64496');
    addNet(db, 'b.example', '192.0.2.2', 'HU', 'AS64497');
    addEvent(db, ev({ target: 'a.example', kind: 'geo_changed', at: ago(DAY), old_country_code: 'HU', new_country_code: 'DE' }));
    db.close();
  };
  const tmp = (): string => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'risk-dry-')), 'scan.db');

  it('reports the country-source effect and each bump, with samples', () => {
    const file = tmp();
    build(file);
    const raw = new Database(file, { readonly: true });
    const r = dryRun(raw, { discoveryDb: null, hostSuffix: 'hu', bumps: [1, 5], now: NOW, sample: 2 });
    raw.close();
    expect(r.targets).toBe(3);
    // a.example is hosted in DE under a hu suffix: foreign +15, which the old source (no discovery db) missed
    expect(r.countrySource.changed).toBe(1);
    expect(r.countrySource.deltas).toEqual({ 15: 1 });
    expect(r.countrySource.samples).toEqual({ 15: ['a.example'] });
    expect(r.countrySource.bandCrossings).toBe(1);
    expect(r.bumps.map((b) => b.bump)).toEqual([1, 5]);
    expect(r.bumps[1]!.affected).toBe(1);
    expect(r.bumps[1]!.deltas).toEqual({ 5: 1 });
    expect(r.bumps[1]!.samples).toEqual({ 5: ['a.example'] });
    expect(r.bumps[0]!.bandCrossings).toBe(0);
    const text = formatReport(r);
    expect(text).toContain('a.example');
  });

  it('does not write to the database', () => {
    const file = tmp();
    build(file);
    const before = fs.readFileSync(file);
    const raw = new Database(file, { readonly: true });
    const v0 = raw.pragma('data_version', { simple: true });
    dryRun(raw, { discoveryDb: null, hostSuffix: 'hu', bumps: [1, 2, 3, 5], now: NOW, sample: 3 });
    expect(raw.pragma('data_version', { simple: true })).toBe(v0);
    raw.close();
    expect(fs.readFileSync(file).equals(before)).toBe(true);
    // A reader of a WAL database makes empty -shm/-wal sidecars; no frame is written.
    const walFile = `${file}-wal`;
    expect(fs.existsSync(walFile) ? fs.statSync(walFile).size : 0).toBe(0);
    expect(fs.readdirSync(path.dirname(file)).filter((f) => !/^scan\.db(-shm|-wal)?$/.test(f))).toEqual([]);
  });
});

describe('dry-run arguments', () => {
  const parse = (...a: string[]) => parseDryRunArgs(['node', 'x', ...a]);
  it('accepts the documented flags', () => {
    const o = parse('--sqlite', 'f.db', '--bumps', '1,2', '--sample', '3', '--suffix', 'hu');
    expect(o).toMatchObject({ db: 'f.db', bumps: [1, 2], sample: 3, hostSuffix: 'hu' });
  });
  it('rejects --bumps without a value', () => {
    expect(() => parse('--bumps')).toThrow(/usage/i);
  });
  it('rejects an empty or non-numeric --bumps', () => {
    expect(() => parse('--bumps', '')).toThrow(/usage/i);
    expect(() => parse('--bumps', '1,x')).toThrow(/usage/i);
    expect(() => parse('--bumps', '1,,2')).toThrow(/usage/i);
  });
  it('rejects a non-numeric --sample', () => {
    expect(() => parse('--sample', 'abc')).toThrow(/usage/i);
    expect(() => parse('--sample')).toThrow(/usage/i);
  });
});
