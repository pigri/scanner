import { describe, it, expect } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { runNetinfo } from '../src/lib/netinfo.js';
import { clusterWindows, rebuildHistory, WINDOW_GAP_MS } from '../src/lib/netinfo-rebuild.js';
import type { GeoLookup } from '../src/lib/geoip.js';

const iso = (ms: number): string => new Date(ms).toISOString();
const D0 = Date.parse('2026-08-31T10:00:00.000Z');
const H = 3600_000;
const DAY = 24 * H;
const NOW = new Date('2026-11-20T00:00:00.000Z');

const run = (db: Db, at: number): number => db.startRun('nmap', {}, iso(at));
const port = (db: Db, target: string, ip: string, at: number, runId: number | null = null) =>
  db.insertPort({ target, ip, port: 443, protocol: 'tcp' }, iso(at), runId);
const probe = (db: Db, target: string, ip: string | null, at: number, runId: number) =>
  db.insertHttpProbe({ target, url: `https://${target}/`, ip, status_code: 200 }, iso(at), runId);
const finding = (db: Db, target: string, at: number, runId: number) =>
  db.insertFinding({ tool: 'nuclei', target, title: 'x' }, iso(at), runId);

type Ev = { ip: string; kind: string; at: string; source: string; run_id: number | null; new_country_code: string | null };
const events = (db: Db, where = '1=1'): Ev[] =>
  db.raw.prepare(`SELECT ip, kind, at, source, run_id, new_country_code FROM target_network_events WHERE ${where} ORDER BY ip, at, id`).all() as Ev[];
const brief = (db: Db): string[] => events(db).map((e) => `${e.ip} ${e.kind} ${e.at}`);
const evidenceTargets = (db: Db): string[] =>
  (db.raw.prepare('SELECT target FROM ports UNION SELECT target FROM findings UNION SELECT target FROM dns_records UNION SELECT target FROM http_probes').all() as { target: string }[]).map((r) => r.target);
const rebuild = (db: Db, extra: Partial<Parameters<typeof rebuildHistory>[0]> = {}) =>
  rebuildHistory({ db, targets: evidenceTargets(db), now: NOW, ...extra });
const queue = (db: Db, target: string, status: string, startedAt: number | null) =>
  db.raw.prepare('INSERT INTO scan_queue (target, queued_at, status, started_at) VALUES (?, ?, ?, ?)').run(target, iso(D0 - DAY), status, startedAt === null ? null : iso(startedAt));

describe('clusterWindows', () => {
  it('puts runs exactly 3 h apart in one window and a millisecond more in two', () => {
    const same = clusterWindows([{ at: iso(D0), runId: 1 }, { at: iso(D0 + WINDOW_GAP_MS), runId: 2 }]);
    expect(same).toHaveLength(1);
    expect(same[0]).toMatchObject({ start: iso(D0), end: iso(D0 + 2 * WINDOW_GAP_MS) });
    expect([...same[0]!.runIds]).toEqual([1, 2]);
    const split = clusterWindows([{ at: iso(D0), runId: 1 }, { at: iso(D0 + WINDOW_GAP_MS + 1), runId: 2 }]);
    expect(split.map((w) => w.start)).toEqual([iso(D0), iso(D0 + WINDOW_GAP_MS + 1)]);
  });

  it('chains runs, sorts the input and ignores unparsable times', () => {
    const w = clusterWindows([
      { at: iso(D0 + 5 * H), runId: 3 }, { at: 'garbage', runId: 9 }, { at: iso(D0), runId: 1 }, { at: iso(D0 + 2.5 * H), runId: 2 }, { at: iso(D0 + DAY), runId: 4 },
    ]);
    expect(w.map((x) => [x.start, [...x.runIds]])).toEqual([[iso(D0), [1, 2, 3]], [iso(D0 + DAY), [4]]]);
  });

  it('keeps a window for a pseudo-run that has no run id', () => {
    const w = clusterWindows([{ at: iso(D0), runId: null }]);
    expect(w).toHaveLength(1);
    expect(w[0]!.runIds.size).toBe(0);
  });

  it('returns no window for no runs', () => {
    expect(clusterWindows([])).toEqual([]);
  });
});

describe('rebuildHistory', () => {
  it('reconstructs ip_added, ip_gone and ip_back from the windows that saw each ip', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY), r3 = run(db, D0 + 2 * DAY);
    port(db, 'a.example', '192.0.2.10', D0 + 60_000, r1);
    port(db, 'a.example', '198.51.100.7', D0 + DAY + 60_000, r2);
    port(db, 'a.example', '192.0.2.10', D0 + 2 * DAY + 60_000, r3);
    const res = rebuild(db);
    expect(brief(db)).toEqual([
      `192.0.2.10 ip_added ${iso(D0)}`,
      `192.0.2.10 ip_gone ${iso(D0 + DAY)}`,
      `192.0.2.10 ip_back ${iso(D0 + 2 * DAY)}`,
      `198.51.100.7 ip_added ${iso(D0 + DAY)}`,
      `198.51.100.7 ip_gone ${iso(D0 + 2 * DAY)}`,
    ]);
    expect(res).toMatchObject({ targets: 1, inserted: 5 });
  });

  it('marks every event reconstructed, with the rebuild run id, and writes nothing else', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    const rid = db.startRun('netinfo', {}, iso(D0));
    rebuild(db, { runId: rid });
    expect(events(db).every((e) => e.source === 'reconstructed' && e.run_id === rid)).toBe(true);
    expect((db.raw.prepare('SELECT count(*) n FROM target_network').get() as { n: number }).n).toBe(0);
  });

  it('adds nothing on a second run and keeps the first run rows', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    port(db, 'a.example', '198.51.100.7', D0 + DAY, r2);
    rebuild(db);
    const before = db.raw.prepare('SELECT * FROM target_network_events ORDER BY id').all();
    const again = rebuild(db);
    expect(again.inserted).toBe(0);
    expect(db.raw.prepare('SELECT * FROM target_network_events ORDER BY id').all()).toEqual(before);
  });

  it('treats runs within 3 h as one window and runs further apart as two', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + 3 * H), r3 = run(db, D0 + 3 * H + 3 * H + 1);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    port(db, 'a.example', '198.51.100.7', D0 + 3 * H, r2);
    port(db, 'a.example', '198.51.100.7', D0 + 6 * H + 1, r3);
    rebuild(db);
    // r1 and r2 are one window (gap exactly 3 h): 192.0.2.10 is not gone there. r3 is a new window.
    expect(brief(db)).toEqual([
      `192.0.2.10 ip_added ${iso(D0)}`,
      `192.0.2.10 ip_gone ${iso(D0 + 6 * H + 1)}`,
      `198.51.100.7 ip_added ${iso(D0)}`,
    ]);
  });

  it('counts a run that only left findings as a window that did not see the ip', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    finding(db, 'a.example', D0 + DAY, r2);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`, `192.0.2.10 ip_gone ${iso(D0 + DAY)}`]);
  });

  it('counts an http probe that stored its ip as a sighting; one without an ip is inconclusive, not an absence', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY), r3 = run(db, D0 + 2 * DAY);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    probe(db, 'a.example', '192.0.2.10', D0 + DAY, r2);
    probe(db, 'a.example', null, D0 + 2 * DAY, r3);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`]);
  });

  it('counts a dns record whose seen_at or last_seen falls in a window', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY), r3 = run(db, D0 + 2 * DAY);
    finding(db, 'a.example', D0, r1);
    finding(db, 'a.example', D0 + DAY, r2);
    finding(db, 'a.example', D0 + 2 * DAY, r3);
    db.raw.prepare("INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES ('a.example','a.example','A','192.0.2.10',?,?)").run(iso(D0 + H), iso(D0 + 2 * DAY + H));
    rebuild(db);
    // Seen in window 1 (seen_at) and window 3 (last_seen); window 2 has neither.
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`, `192.0.2.10 ip_gone ${iso(D0 + DAY)}`, `192.0.2.10 ip_back ${iso(D0 + 2 * DAY)}`]);
  });

  it('emits no ip_gone for a window whose dns status is unknown', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY);
    db.raw.prepare("INSERT INTO dns_records (target, name, type, value, seen_at, last_seen, run_id) VALUES ('a.example','a.example','A','192.0.2.10',?,NULL,?)").run(iso(D0), r1);
    finding(db, 'a.example', D0 + DAY, r2);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`]);
  });

  it('yields only ip_added when every dns time is NULL and nothing is tracked', () => {
    const db = openDb(':memory:');
    const runs = [0, 1, 2, 3].map((d) => run(db, D0 + d * DAY));
    db.raw.prepare("INSERT INTO dns_records (target, name, type, value, seen_at, last_seen, run_id) VALUES ('a.example','a.example','A','192.0.2.10',?,NULL,?)").run(iso(D0), runs[0]!);
    for (const [i, r] of runs.entries()) if (i > 0) finding(db, 'a.example', D0 + i * DAY, r);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`]);
  });

  it('adds the latest done scan_queue start as a window', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    queue(db, 'a.example', 'done', D0 + 60 * DAY);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`, `192.0.2.10 ip_gone ${iso(D0 + 60 * DAY)}`]);
  });

  it('ignores a scan_queue row that is not done', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    queue(db, 'a.example', 'in_progress', D0 + 60 * DAY);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`]);
  });

  it('emits nothing for evidence with no run, and leaves gaps as gaps', () => {
    const db = openDb(':memory:');
    port(db, 'a.example', '192.0.2.10', D0, null);
    rebuild(db);
    expect(events(db)).toEqual([]);
    const r1 = run(db, D0), r2 = run(db, D0 + 100 * DAY);
    port(db, 'b.example', '192.0.2.20', D0, r1);
    port(db, 'b.example', '192.0.2.20', D0 + 100 * DAY, r2);
    rebuild(db);
    expect(events(db, "ip = '192.0.2.20'").map((e) => e.kind)).toEqual(['ip_added']);
  });

  it('never sees the identity ip of an ip-literal target as gone', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY);
    finding(db, '192.0.2.30', D0, r1);
    finding(db, '192.0.2.30', D0 + DAY, r2);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.30 ip_added ${iso(D0)}`]);
  });

  it('copies today geo from the stored row onto ip_added', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    const geo: GeoLookup = { buildAt: null, get: () => ({ asn: 'AS64496', country_code: 'XA' }) };
    runNetinfo({ db, targets: ['a.example'], geo, now: NOW });
    db.raw.prepare('DELETE FROM target_network_events').run();
    rebuild(db);
    expect(events(db)[0]).toMatchObject({ kind: 'ip_added', new_country_code: 'XA' });
  });

  it("takes the scan_queue targets for 'all'", () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    port(db, 'b.example', '198.51.100.7', D0, r1);
    queue(db, 'a.example', 'pending', null);
    const res = rebuildHistory({ db, targets: 'all', now: NOW });
    expect(res.targets).toBe(1);
    expect(events(db).map((e) => e.ip)).toEqual(['192.0.2.10']);
  });

  it('restricts to the given targets', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    port(db, 'b.example', '198.51.100.7', D0, r1);
    rebuild(db, { targets: ['b.example'] });
    expect(events(db).map((e) => e.ip)).toEqual(['198.51.100.7']);
  });

  it('writes in chunks of the given size', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0);
    for (let i = 1; i <= 5; i++) port(db, `t${i}.example`, `192.0.2.${i}`, D0, r1);
    let txs = 0;
    const spy = db.raw.transaction.bind(db.raw);
    (db.raw as unknown as { transaction: typeof spy }).transaction = ((fn: never) => { txs++; return spy(fn); }) as typeof spy;
    rebuild(db, { chunkSize: 2 });
    expect(txs).toBe(3);
    expect(events(db)).toHaveLength(5);
  });
});

describe('rebuildHistory and scan events', () => {
  it('never alters or removes a scan event', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    port(db, 'a.example', '198.51.100.7', D0 + DAY, r2);
    db.raw.prepare("INSERT INTO target_network_events (target, ip, kind, at, source) VALUES ('a.example','192.0.2.10','ip_gone',?, 'scan')").run(iso(D0 + 10 * DAY));
    const before = db.raw.prepare("SELECT * FROM target_network_events WHERE source = 'scan'").all();
    rebuild(db);
    rebuild(db);
    expect(db.raw.prepare("SELECT * FROM target_network_events WHERE source = 'scan'").all()).toEqual(before);
  });

  it('skips reconstructed events at or after the earliest scan event of the same ip', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + DAY);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    port(db, 'a.example', '198.51.100.7', D0 + DAY, r2);
    db.raw.prepare("INSERT INTO target_network_events (target, ip, kind, at, source) VALUES ('a.example','192.0.2.10','ip_added',?, 'scan')").run(iso(D0 + DAY));
    rebuild(db);
    // The gone at D0 + DAY would be at the scan event's time: left to the scan writer.
    expect(events(db, "ip = '192.0.2.10'").map((e) => `${e.kind} ${e.source}`)).toEqual(['ip_added reconstructed', 'ip_added scan']);
  });

  it('does not let a later scan run duplicate what a rebuild recorded for a gone ip', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    queue(db, 'a.example', 'done', D0 + 60 * DAY);
    rebuild(db);
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    db.raw.prepare("UPDATE scan_queue SET status = 'in_progress' WHERE target = 'a.example'").run();
    runNetinfo({ db, targets: ['a.example'], geo: null, now: NOW });
    expect(events(db).filter((e) => e.kind === 'ip_gone')).toHaveLength(1);
  });
});

describe('inconclusive windows', () => {
  const sighting = (db: Db, at: number) => port(db, 'a.example', '192.0.2.10', at, run(db, at));
  const nullProbe = (db: Db, at: number) => probe(db, 'a.example', null, at, run(db, at));

  it('a window with an answer but no ip, between two sightings, emits nothing', () => {
    const db = openDb(':memory:');
    sighting(db, D0);
    nullProbe(db, D0 + 4 * DAY);
    sighting(db, D0 + 8 * DAY);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`]);
  });

  it('a null-ip port row is inconclusive too', () => {
    const db = openDb(':memory:');
    sighting(db, D0);
    db.insertPort({ target: 'a.example', ip: null, port: 443, protocol: 'tcp' }, iso(D0 + 4 * DAY), run(db, D0 + 4 * DAY));
    sighting(db, D0 + 8 * DAY);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`]);
  });

  it('an inconclusive window followed by an empty one is gone at the empty window', () => {
    const db = openDb(':memory:');
    sighting(db, D0);
    nullProbe(db, D0 + 4 * DAY);
    queue(db, 'a.example', 'done', D0 + 65 * DAY);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`, `192.0.2.10 ip_gone ${iso(D0 + 65 * DAY)}`]);
  });

  it('a window whose ip rows exclude the ip is still an absence', () => {
    const db = openDb(':memory:');
    sighting(db, D0);
    port(db, 'a.example', '198.51.100.7', D0 + 4 * DAY, run(db, D0 + 4 * DAY));
    rebuild(db);
    expect(brief(db)).toContain(`192.0.2.10 ip_gone ${iso(D0 + 4 * DAY)}`);
  });
});

describe('fileshare-shaped history', () => {
  it('added at the first sighting, gone at the rescan that found nothing; the old null-ip probe is inconclusive', () => {
    const db = openDb(':memory:');
    const r1 = run(db, D0), r2 = run(db, D0 + 4 * DAY);
    port(db, 'a.example', '192.0.2.10', D0, r1);
    probe(db, 'a.example', null, D0 + 4 * DAY, r2);
    queue(db, 'a.example', 'done', D0 + 65 * DAY);
    rebuild(db);
    expect(brief(db)).toEqual([`192.0.2.10 ip_added ${iso(D0)}`, `192.0.2.10 ip_gone ${iso(D0 + 65 * DAY)}`]);
  });
});

describe('event order across sources', () => {
  const scanEv = (db: Db, ip: string, kind: string, at: number) =>
    db.raw.prepare("INSERT INTO target_network_events (target, ip, kind, at, source) VALUES ('a.example', ?, ?, ?, 'scan')").run(ip, kind, iso(at));
  // sighting, absence, sighting: reconstructed added, gone, back
  const seed = (db: Db) => {
    port(db, 'a.example', '192.0.2.10', D0, run(db, D0));
    port(db, 'a.example', '198.51.100.7', D0 + 4 * DAY, run(db, D0 + 4 * DAY));
    port(db, 'a.example', '192.0.2.10', D0 + 8 * DAY, run(db, D0 + 8 * DAY));
  };
  const kinds = (db: Db) => events(db, "ip = '192.0.2.10'").map((e) => `${e.kind} ${e.source}`);

  it('a first scan ip_gone needs the ip present just before it: a trailing reconstructed gone is dropped', () => {
    const db = openDb(':memory:');
    seed(db);
    scanEv(db, '192.0.2.10', 'ip_gone', D0 + 20 * DAY);
    // seen only in the first window, so the rebuild would end on a gone at +4d
    db.raw.prepare("DELETE FROM ports WHERE run_id = (SELECT id FROM runs WHERE started_at = ?) AND ip = '192.0.2.10'").run(iso(D0 + 8 * DAY));
    rebuild(db);
    expect(kinds(db)).toEqual(['ip_added reconstructed', 'ip_gone scan']);
  });

  it('a first scan ip_back needs the ip absent just before it: a trailing reconstructed back is dropped', () => {
    const db = openDb(':memory:');
    seed(db);
    scanEv(db, '192.0.2.10', 'ip_back', D0 + 20 * DAY);
    rebuild(db);
    expect(kinds(db)).toEqual(['ip_added reconstructed', 'ip_gone reconstructed', 'ip_back scan']);
  });

  it('keeps a trailing transition that already fits the scan event', () => {
    const db = openDb(':memory:');
    seed(db);
    scanEv(db, '192.0.2.10', 'ip_gone', D0 + 20 * DAY);
    rebuild(db);
    expect(kinds(db)).toEqual(['ip_added reconstructed', 'ip_gone reconstructed', 'ip_back reconstructed', 'ip_gone scan']);
  });

  it('never alters scan events', () => {
    const db = openDb(':memory:');
    seed(db);
    scanEv(db, '192.0.2.10', 'ip_back', D0 + 20 * DAY);
    const before = events(db, "source = 'scan'");
    rebuild(db);
    expect(events(db, "source = 'scan'")).toEqual(before);
  });

  it('after a rebuild every (target, ip) alternates present and absent', () => {
    const db = openDb(':memory:');
    seed(db);
    port(db, 'b.example', '203.0.113.5', D0, run(db, D0));
    db.insertPort({ target: 'b.example', ip: '203.0.113.5', port: 80, protocol: 'tcp' }, iso(D0 + 4 * DAY), run(db, D0 + 4 * DAY));
    scanEv(db, '192.0.2.10', 'ip_back', D0 + 20 * DAY);
    rebuild(db);
    rebuild(db);
    const rows = db.raw.prepare("SELECT target, ip, kind FROM target_network_events ORDER BY target, ip, at, id").all() as { target: string; ip: string; kind: string }[];
    const last = new Map<string, boolean>();
    for (const r of rows) {
      const k = `${r.target}|${r.ip}`;
      const present = r.kind !== 'ip_gone';
      if (last.has(k)) expect(present).toBe(!last.get(k));
      else expect(r.kind).toBe('ip_added');
      last.set(k, present);
    }
    expect(last.size).toBe(3);
  });
});
