import { describe, it, expect } from 'vitest';
import type Database from 'better-sqlite3';
import { runRetention, type RetentionOpts } from '../src/retention.js';
import { openDb, type Db } from '../src/lib/db.js';
import { recordRiskScores, deleteRiskScoresForRuns } from '../src/lib/risk-latest.js';

const NOW = '2026-09-01T00:00:00Z';
const OLD = '2026-03-01T00:00:00Z'; // 184 days before NOW
const OLD2 = '2026-04-01T00:00:00Z'; // 153 days
const RECENT = '2026-08-20T00:00:00Z'; // 12 days
const opts = (over: Partial<RetentionOpts> = {}): RetentionOpts => ({ olderThanDays: 90, now: NOW, apply: true, ...over });

const port = (db: Db, target: string, run: number, at: string, p = 80) =>
  db.insertPort({ target, ip: null, port: p, protocol: 'tcp', service: null, product: null, version: null, tunnel: null, extrainfo: null }, at, run);
const probe = (raw: Database.Database, target: string, run: number | null) =>
  raw.prepare('INSERT INTO http_probes(target, url, seen_at, run_id) VALUES(?, ?, ?, ?)').run(target, `http://${target}/`, OLD, run);
// Stamped with its run's started_at, as the tools do; OLD when there is no run.
const finding = (raw: Database.Database, target: string, run: number | null) =>
  raw.prepare("INSERT INTO findings(tool, target, title, seen_at, run_id) VALUES('nuclei', ?, 't', COALESCE((SELECT started_at FROM runs WHERE id = ?), ?), ?)").run(target, run, OLD, run);
const shot = (raw: Database.Database, target: string, run: number | null) =>
  raw.prepare("INSERT INTO screenshots(target, url, path, seen_at, run_id) VALUES(?, ?, 'p.png', ?, ?)").run(target, `http://${target}/`, OLD, run);
const count = (raw: Database.Database, table: string, where = '1=1'): number =>
  (raw.prepare(`SELECT count(*) c FROM ${table} WHERE ${where}`).get() as { c: number }).c;
const runIds = (raw: Database.Database): number[] =>
  (raw.prepare('SELECT id FROM runs ORDER BY id').all() as { id: number }[]).map((r) => r.id);

const mk = (db: Db, tool: string, at: string, finished = true): number => {
  const id = db.startRun(tool, {}, at);
  if (finished) db.finishRun(id, { targetsCount: 1, findingsCount: 0, at });
  return id;
};

describe('runRetention (per-target rule)', () => {
  it('keeps every row of a target whose runs are all old', () => {
    const db = openDb(':memory:');
    const r = mk(db, 'nmap', OLD);
    port(db, 'only-old.example.com', r, OLD);
    probe(db.raw, 'only-old.example.com', r);
    finding(db.raw, 'only-old.example.com', r);
    shot(db.raw, 'only-old.example.com', r);
    const res = runRetention(db.raw, opts());
    expect(res.runs).toEqual([]);
    expect(count(db.raw, 'ports')).toBe(1);
    expect(count(db.raw, 'http_probes')).toBe(1);
    expect(count(db.raw, 'findings')).toBe(1);
    expect(count(db.raw, 'screenshots')).toBe(1);
    expect(runIds(db.raw)).toEqual([r]);
  });

  it('prunes a superseded old row and keeps the newer one', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT);
    port(db, 'a.example.com', r1, OLD);
    port(db, 'a.example.com', r2, RECENT);
    runRetention(db.raw, opts());
    expect(db.raw.prepare('SELECT run_id FROM ports').all()).toEqual([{ run_id: r2 }]);
    expect(runIds(db.raw)).toEqual([r2]);
  });

  it('prunes in all four tables', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT);
    for (const r of [r1, r2]) {
      port(db, 'a.example.com', r, OLD);
      probe(db.raw, 'a.example.com', r);
      finding(db.raw, 'a.example.com', r);
      shot(db.raw, 'a.example.com', r);
    }
    const res = runRetention(db.raw, opts());
    expect(res.rows).toEqual({ findings: 1, ports: 1, http_probes: 1, screenshots: 1 });
    for (const t of ['ports', 'http_probes', 'findings', 'screenshots']) expect(count(db.raw, t, `run_id = ${r2}`)).toBe(1);
    for (const t of ['ports', 'http_probes', 'findings', 'screenshots']) expect(count(db.raw, t)).toBe(1);
  });

  it('keeps the newest old row when the newer run is also old (it is still the latest)', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', OLD2);
    port(db, 'a.example.com', r1, OLD);
    port(db, 'a.example.com', r2, OLD2);
    runRetention(db.raw, opts());
    expect(db.raw.prepare('SELECT run_id FROM ports').all()).toEqual([{ run_id: r2 }]);
  });

  it('only a newer run of the same tool supersedes', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'httpx', RECENT);
    port(db, 'a.example.com', r1, OLD);
    probe(db.raw, 'a.example.com', r2);
    runRetention(db.raw, opts());
    expect(count(db.raw, 'ports')).toBe(1);
    expect(runIds(db.raw)).toEqual([r1, r2]);
  });

  it('keeps another target of the same old run, and removes the run only once empty', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT);
    port(db, 'rescanned.example.com', r1, OLD);
    port(db, 'stale.example.com', r1, OLD);
    port(db, 'rescanned.example.com', r2, RECENT);
    const res = runRetention(db.raw, opts());
    expect(res.runs).toEqual([]);
    expect(runIds(db.raw)).toEqual([r1, r2]);
    expect(db.raw.prepare('SELECT target, run_id FROM ports ORDER BY id').all()).toEqual([
      { target: 'stale.example.com', run_id: r1 },
      { target: 'rescanned.example.com', run_id: r2 },
    ]);
  });

  it('an unfinished newer run does not supersede older complete evidence', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT, false);
    port(db, 'a.example.com', r1, OLD);
    port(db, 'a.example.com', r2, RECENT);
    const res = runRetention(db.raw, opts());
    expect(res.rows.ports).toBe(0);
    expect(count(db.raw, 'ports')).toBe(2);
    expect(runIds(db.raw)).toEqual([r1, r2]);
  });

  it('a finished run still supersedes when an even newer run is unfinished', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', OLD2);
    const r3 = mk(db, 'nmap', RECENT, false);
    port(db, 'a.example.com', r1, OLD);
    port(db, 'a.example.com', r2, OLD2);
    port(db, 'a.example.com', r3, RECENT);
    runRetention(db.raw, opts());
    expect(db.raw.prepare('SELECT run_id FROM ports ORDER BY id').all()).toEqual([{ run_id: r2 }, { run_id: r3 }]);
  });

  it('a newer run with rows only in ports does not prune the other tables', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT);
    port(db, 'a.example.com', r1, OLD);
    probe(db.raw, 'a.example.com', r1);
    finding(db.raw, 'a.example.com', r1);
    shot(db.raw, 'a.example.com', r1);
    port(db, 'a.example.com', r2, RECENT);
    const res = runRetention(db.raw, opts());
    expect(res.rows).toEqual({ findings: 0, ports: 1, http_probes: 0, screenshots: 0 });
    expect(count(db.raw, 'http_probes')).toBe(1);
    expect(count(db.raw, 'findings')).toBe(1);
    expect(count(db.raw, 'screenshots')).toBe(1);
    expect(runIds(db.raw)).toEqual([r1, r2]);
  });

  it('an unparsable started_at neither aborts the run nor supersedes or gets pruned', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const bad = mk(db, 'nmap', 'not-a-date');
    port(db, 'a.example.com', r1, OLD);
    port(db, 'a.example.com', bad, OLD);
    port(db, 'b.example.com', bad, OLD);
    const res = runRetention(db.raw, opts());
    expect(res.rows.ports).toBe(0);
    expect(count(db.raw, 'ports')).toBe(3);
  });

  it('breaks a started_at tie by run id', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', OLD);
    port(db, 'a.example.com', r1, OLD);
    port(db, 'a.example.com', r2, OLD);
    runRetention(db.raw, opts());
    expect(db.raw.prepare('SELECT run_id FROM ports').all()).toEqual([{ run_id: r2 }]);
  });

  it('keeps old rows when their newer run is younger than the cutoff only for other targets', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT);
    port(db, 'a.example.com', r1, OLD);
    port(db, 'b.example.com', r2, RECENT);
    runRetention(db.raw, opts());
    expect(count(db.raw, 'ports')).toBe(2);
  });

  it('never prunes a row younger than the cutoff, even if superseded', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', RECENT);
    const r2 = mk(db, 'nmap', '2026-08-25T00:00:00Z');
    port(db, 'a.example.com', r1, RECENT);
    port(db, 'a.example.com', r2, '2026-08-25T00:00:00Z');
    runRetention(db.raw, opts());
    expect(count(db.raw, 'ports')).toBe(2);
  });

  it('keeps rows with no run', () => {
    const db = openDb(':memory:');
    const r2 = mk(db, 'nmap', RECENT);
    probe(db.raw, 'a.example.com', null);
    port(db, 'a.example.com', r2, RECENT);
    runRetention(db.raw, opts());
    expect(count(db.raw, 'http_probes')).toBe(1);
  });

  const referencing: [string, (raw: Database.Database, run: number) => void][] = [
    ['dns_records', (raw, r) => raw.prepare("INSERT INTO dns_records(target, name, type, value, seen_at, run_id) VALUES('a.example.com','a.example.com','A','1.1.1.1',?,?)").run(OLD, r)],
    ['scan_queue', (raw, r) => raw.prepare("INSERT INTO scan_queue(target, queued_at, run_id) VALUES('q.example.com', ?, ?)").run(OLD, r)],
    ['report_queue', (raw, r) => raw.prepare("INSERT INTO report_queue(target, queued_at, run_id) VALUES('q.example.com', ?, ?)").run(OLD, r)],
    ['certificates', (raw, r) => raw.prepare("INSERT INTO certificates(target, port, fingerprint_sha256, seen_at, run_id) VALUES('a.example.com', 443, 'ff', ?, ?)").run(OLD, r)],
    ['discovered_urls', (raw, r) => raw.prepare("INSERT INTO discovered_urls(target, url, source, seen_at, run_id) VALUES('a.example.com', 'http://a.example.com/x', 'katana', ?, ?)").run(OLD, r)],
    ['risk_scores', (raw, r) => recordRiskScores(raw, [{ target: 'a.example.com', score: 10, breakdownJson: '{}' }], OLD, r)],
  ];
  it.each(referencing)('keeps a run that %s still references, and leaves that table alone', (table, insert) => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT);
    port(db, 'a.example.com', r1, OLD);
    port(db, 'a.example.com', r2, RECENT);
    insert(db.raw, r1);
    const res = runRetention(db.raw, opts());
    expect(res.rows.ports).toBe(1);
    expect(res.runs).toEqual([]);
    expect(runIds(db.raw)).toEqual([r1, r2]);
    expect(count(db.raw, table, `run_id = ${r1}`)).toBe(1);
  });

  it('does not touch runs that never had prunable rows (empty marker runs)', () => {
    const db = openDb(':memory:');
    const marker = mk(db, 'version-match-sweep', OLD);
    const res = runRetention(db.raw, opts());
    expect(res.runs).toEqual([]);
    expect(runIds(db.raw)).toEqual([marker]);
  });

  it('dry-run changes nothing but reports the same plan as apply', () => {
    const build = () => {
      const db = openDb(':memory:');
      const r1 = mk(db, 'nmap', OLD);
      const r2 = mk(db, 'nmap', RECENT);
      port(db, 'a.example.com', r1, OLD);
      port(db, 'a.example.com', r2, RECENT);
      finding(db.raw, 'a.example.com', r1);
      finding(db.raw, 'a.example.com', r2);
      return db;
    };
    const dry = build();
    const plan = runRetention(dry.raw, opts({ apply: false }));
    expect(count(dry.raw, 'ports')).toBe(2);
    expect(count(dry.raw, 'findings')).toBe(2);
    expect(runIds(dry.raw)).toEqual([1, 2]);
    expect(plan.rows).toEqual({ findings: 1, ports: 1, http_probes: 0, screenshots: 0 });
    expect(plan.runs).toEqual([1]);
    const real = build();
    expect(runRetention(real.raw, opts())).toEqual(plan);
    expect(runIds(real.raw)).toEqual([2]);
  });

  it('deletes in bounded chunks and still reaches every row', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT);
    for (let i = 0; i < 7; i++) port(db, 'a.example.com', r1, OLD, 1000 + i);
    port(db, 'a.example.com', r2, RECENT);
    const res = runRetention(db.raw, opts({ chunkSize: 2 }));
    expect(res.rows.ports).toBe(7);
    expect(count(db.raw, 'ports')).toBe(1);
    expect(runIds(db.raw)).toEqual([r2]);
  });
});

describe('deleteRiskScoresForRuns (retention)', () => {
  it('falls back to the previous score when the newest run is deleted', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, '2026-01-01T00:00:00Z');
    const r2 = db.startRun('risk', {}, '2026-01-02T00:00:00Z');
    recordRiskScores(db.raw, [{ target: 'a.example.com', score: 10, breakdownJson: '{}' }], '2026-01-01T00:00:00Z', r1);
    recordRiskScores(db.raw, [{ target: 'a.example.com', score: 50, breakdownJson: '{}' }], '2026-01-02T00:00:00Z', r2);
    db.raw.transaction(() => deleteRiskScoresForRuns(db.raw, [r2]))();
    expect(db.raw.prepare('SELECT score FROM risk_latest WHERE target = ?').get('a.example.com')).toEqual({ score: 10 });
  });

  it('removes the row when the only run is deleted', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, '2026-01-01T00:00:00Z');
    recordRiskScores(db.raw, [{ target: 'a.example.com', score: 10, breakdownJson: '{}' }], '2026-01-01T00:00:00Z', r1);
    db.raw.transaction(() => deleteRiskScoresForRuns(db.raw, [r1]))();
    expect(db.raw.prepare('SELECT * FROM risk_latest').all()).toEqual([]);
  });
});

describe('runRetention keeps risk_latest in step', () => {
  it('leaves risk_scores and risk_latest alone', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, OLD);
    const r2 = db.startRun('risk', {}, RECENT);
    recordRiskScores(db.raw, [{ target: 'a.example.com', score: 10, breakdownJson: '{}' }], OLD, r1);
    recordRiskScores(db.raw, [{ target: 'a.example.com', score: 50, breakdownJson: '{}' }], RECENT, r2);
    runRetention(db.raw, opts());
    expect(count(db.raw, 'risk_scores')).toBe(2);
    expect(db.raw.prepare('SELECT score FROM risk_latest').all()).toEqual([{ score: 50 }]);
    expect(runIds(db.raw)).toEqual([r1, r2]);
  });
});

describe('runRetention risk_scores window (--risk-older-than)', () => {
  const T = 'a.example.com';
  const score = (db: Db, target: string, at: string, runId: number | null, s = 10) =>
    runId === null
      ? db.raw.prepare("INSERT INTO risk_scores(target, score, breakdown_json, computed_at, run_id) VALUES(?, ?, '{}', ?, NULL)").run(target, s, at)
      : recordRiskScores(db.raw, [{ target, score: s, breakdownJson: '{}' }], at, runId);
  const riskOpts = (over: Partial<RetentionOpts> = {}) => opts({ riskOlderThanDays: 30, ...over });
  const riskIds = (raw: Database.Database): number[] =>
    (raw.prepare('SELECT id FROM risk_scores ORDER BY id').all() as { id: number }[]).map((r) => r.id);

  it('deletes old rows but keeps each target latest, even when older than the cutoff', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, OLD);
    const r2 = db.startRun('risk', {}, OLD2);
    const r3 = db.startRun('risk', {}, RECENT);
    score(db, T, OLD, r1);
    score(db, T, OLD2, r2);
    score(db, 'b.example.com', OLD, r1);
    score(db, 'c.example.com', OLD, r1);
    score(db, 'c.example.com', RECENT, r3);
    const res = runRetention(db.raw, riskOpts());
    expect(res.riskScores).toBe(2);
    expect(db.raw.prepare('SELECT target, computed_at FROM risk_scores ORDER BY id').all()).toEqual([
      { target: T, computed_at: OLD2 },
      { target: 'b.example.com', computed_at: OLD },
      { target: 'c.example.com', computed_at: RECENT },
    ]);
  });

  it('keeps rows inside the window', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, RECENT);
    const r2 = db.startRun('risk', {}, '2026-08-25T00:00:00Z');
    score(db, T, RECENT, r1);
    score(db, T, '2026-08-25T00:00:00Z', r2);
    const res = runRetention(db.raw, riskOpts());
    expect(res.riskScores).toBe(0);
    expect(count(db.raw, 'risk_scores')).toBe(2);
  });

  it('does not touch risk_scores without the flag', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, OLD);
    const r2 = db.startRun('risk', {}, RECENT);
    score(db, T, OLD, r1);
    score(db, T, RECENT, r2);
    const res = runRetention(db.raw, opts());
    expect(res.riskScores).toBe(0);
    expect(count(db.raw, 'risk_scores')).toBe(2);
  });

  it('with two rows sharing computed_at, the higher id stays', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, OLD);
    score(db, T, OLD, r1, 10);
    score(db, T, OLD, r1, 20);
    runRetention(db.raw, riskOpts());
    expect(db.raw.prepare('SELECT id, score FROM risk_scores').all()).toEqual([{ id: 2, score: 20 }]);
  });

  it('keeps the latest per URL target too', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, OLD);
    const r2 = db.startRun('risk', {}, OLD2);
    score(db, 'https://a.example.com', OLD, r1);
    score(db, 'https://a.example.com', OLD2, r2);
    runRetention(db.raw, riskOpts());
    expect(db.raw.prepare('SELECT run_id FROM risk_scores').all()).toEqual([{ run_id: r2 }]);
  });

  it('prunes an old row that has no run', () => {
    const db = openDb(':memory:');
    const r2 = db.startRun('risk', {}, RECENT);
    score(db, T, OLD, null);
    score(db, T, RECENT, r2);
    const res = runRetention(db.raw, riskOpts());
    expect(res.riskScores).toBe(1);
    expect(res.runs).toEqual([]);
    expect(riskIds(db.raw)).toEqual([2]);
  });

  it('removes a risk run whose rows are all pruned, and keeps one that keeps a row', () => {
    const db = openDb(':memory:');
    const gone = db.startRun('risk', {}, OLD);
    const kept = db.startRun('risk', {}, OLD2);
    const last = db.startRun('risk', {}, RECENT);
    score(db, T, OLD, gone);
    score(db, T, OLD2, kept);
    score(db, 'b.example.com', OLD, kept);
    score(db, T, RECENT, last);
    const res = runRetention(db.raw, riskOpts());
    expect(res.runs).toEqual([gone]);
    expect(runIds(db.raw)).toEqual([kept, last]);
    expect(count(db.raw, 'risk_scores')).toBe(2);
  });

  it('leaves risk_latest unchanged after an apply', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, OLD);
    const r2 = db.startRun('risk', {}, RECENT);
    score(db, T, OLD, r1, 10);
    score(db, T, RECENT, r2, 50);
    const before = db.raw.prepare('SELECT * FROM risk_latest ORDER BY target').all();
    runRetention(db.raw, riskOpts());
    expect(count(db.raw, 'risk_scores')).toBe(1);
    expect(db.raw.prepare('SELECT * FROM risk_latest ORDER BY target').all()).toEqual(before);
  });

  it('a dry run deletes nothing and reports the count', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, OLD);
    const r2 = db.startRun('risk', {}, RECENT);
    score(db, T, OLD, r1);
    score(db, T, RECENT, r2);
    const plan = runRetention(db.raw, riskOpts({ apply: false }));
    expect(plan.riskScores).toBe(1);
    expect(plan.runs).toEqual([r1]);
    expect(count(db.raw, 'risk_scores')).toBe(2);
    expect(runIds(db.raw)).toEqual([r1, r2]);
  });

  it('deletes in bounded chunks and still reaches every row', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, OLD);
    const r2 = db.startRun('risk', {}, RECENT);
    for (let i = 0; i < 7; i++) score(db, T, `2026-03-0${i + 1}T00:00:00Z`, r1);
    score(db, T, RECENT, r2);
    const res = runRetention(db.raw, riskOpts({ chunkSize: 2 }));
    expect(res.riskScores).toBe(7);
    expect(riskIds(db.raw)).toEqual([8]);
  });
});

describe('runRetention keeps findings that are still current', () => {
  const F_OLD = new Date(OLD).toISOString();
  const F_RECENT = new Date(RECENT).toISOString();
  const row = (raw: Database.Database, tool: string, target: string, run: number, at: string, title = 't') =>
    raw.prepare('INSERT INTO findings(tool, target, title, seen_at, run_id) VALUES(?, ?, ?, ?, ?)').run(tool, target, title, at, run).lastInsertRowid as number;
  const cover = (raw: Database.Database, tool: string, target: string, at: string) =>
    raw.prepare('INSERT INTO tool_coverage(target, tool, seen_at, run_id) VALUES(?, ?, ?, NULL)').run(target, tool, at);
  const ids = (raw: Database.Database): number[] =>
    (raw.prepare('SELECT id FROM findings ORDER BY id').all() as { id: number }[]).map((r) => r.id);

  it('keeps the covering run rows after a later partial run that did not cover the target', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nuclei', OLD);
    const r2 = mk(db, 'nuclei', RECENT);
    const covered = row(db.raw, 'nuclei', 'a.example.com', r1, F_OLD, 'covered');
    const partial = row(db.raw, 'nuclei', 'a.example.com', r2, F_RECENT, 'partial');
    cover(db.raw, 'nuclei', 'a.example.com', F_OLD);
    const res = runRetention(db.raw, opts());
    expect(res.rows.findings).toBe(0);
    expect(ids(db.raw)).toEqual([covered, partial]);
  });

  it('still prunes rows that predate the coverage stamp', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nuclei', OLD);
    const r2 = mk(db, 'nuclei', RECENT);
    row(db.raw, 'nuclei', 'a.example.com', r1, F_OLD);
    const kept = row(db.raw, 'nuclei', 'a.example.com', r2, F_RECENT);
    cover(db.raw, 'nuclei', 'a.example.com', F_RECENT);
    const res = runRetention(db.raw, opts());
    expect(res.rows.findings).toBe(1);
    expect(ids(db.raw)).toEqual([kept]);
  });

  it('keeps old sticky rows', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'synthesize-eol', OLD);
    const r2 = mk(db, 'synthesize-eol', RECENT);
    const a = row(db.raw, 'synthesize-eol', 'a.example.com', r1, F_OLD);
    const b = row(db.raw, 'synthesize-eol', 'a.example.com', r2, F_RECENT);
    const res = runRetention(db.raw, opts());
    expect(res.rows.findings).toBe(0);
    expect(ids(db.raw)).toEqual([a, b]);
  });

  it('maps the watermark by the row tool, not the run tool', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nmap', OLD);
    const r2 = mk(db, 'nmap', RECENT);
    const a = row(db.raw, 'nmap-vulners', 'a.example.com', r1, F_OLD);
    const b = row(db.raw, 'nmap-vulners', 'a.example.com', r2, F_RECENT);
    cover(db.raw, 'nmap-vulners', 'a.example.com', F_OLD);
    expect(runRetention(db.raw, opts({ apply: false })).rows.findings).toBe(0);
    expect(ids(db.raw)).toEqual([a, b]);
  });

  it('a dry run reports only the rows that are not kept', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nuclei', OLD);
    const r2 = mk(db, 'nuclei', RECENT);
    row(db.raw, 'nuclei', 'a.example.com', r1, F_OLD);
    row(db.raw, 'nuclei', 'a.example.com', r2, F_RECENT);
    row(db.raw, 'nuclei', 'b.example.com', r1, F_OLD);
    row(db.raw, 'nuclei', 'b.example.com', r2, F_RECENT);
    cover(db.raw, 'nuclei', 'a.example.com', F_OLD);
    expect(runRetention(db.raw, opts({ apply: false })).rows.findings).toBe(1);
    expect(count(db.raw, 'findings')).toBe(4);
  });

  it('keeps a row that is the newest of its tool when a tied later run supersedes its run', () => {
    const db = openDb(':memory:');
    const r1 = mk(db, 'nuclei', OLD);
    const r2 = mk(db, 'nuclei', OLD);
    const a = row(db.raw, 'nuclei', 'a.example.com', r1, F_OLD);
    const b = row(db.raw, 'nuclei', 'a.example.com', r2, F_OLD);
    const res = runRetention(db.raw, opts());
    expect(res.rows.findings).toBe(0);
    expect(ids(db.raw)).toEqual([a, b]);
  });

  it('without tool_coverage prunes exactly the same rows as with an empty one', () => {
    const build = (dropTable: boolean): number[] => {
      const db = openDb(':memory:');
      const r1 = mk(db, 'nuclei', OLD);
      const r2 = mk(db, 'nuclei', OLD2);
      const r3 = mk(db, 'nuclei', RECENT);
      const o = [
        row(db.raw, 'nuclei', 'a.example.com', r1, F_OLD, 'x'),
        row(db.raw, 'nuclei', 'a.example.com', r2, new Date(OLD2).toISOString(), 'y'),
        row(db.raw, 'nuclei', 'a.example.com', r3, F_RECENT, 'z'),
        row(db.raw, 'nuclei', 'b.example.com', r1, F_OLD, 'x'),
      ];
      if (dropTable) db.raw.exec('DROP TABLE tool_coverage');
      const before = ids(db.raw);
      runRetention(db.raw, opts());
      const after = new Set(ids(db.raw));
      expect(o).toEqual(before);
      return before.filter((i) => !after.has(i));
    };
    const withoutTable = build(true);
    expect(withoutTable).toEqual([1, 2]);
    expect(build(false)).toEqual(withoutTable);
  });
});
