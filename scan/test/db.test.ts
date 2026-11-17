import { describe, it, expect, beforeEach } from 'vitest';
import { openDb, checkpointNoWait, type Db } from '../src/lib/db.js';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

let db: Db;
beforeEach(() => { db = openDb(':memory:'); });

describe('openDb', () => {
  it('creates required tables', () => {
    const tables = db.raw
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all()
      .map((r: any) => r.name);
    expect(tables).toContain('runs');
    expect(tables).toContain('ports');
    expect(tables).toContain('http_probes');
    expect(tables).toContain('findings');
    expect(tables).toContain('screenshots');
  });
});

describe('startRun / finishRun', () => {
  it('records run with args and delta', () => {
    const runId = db.startRun('nmap', { top: 1000 }, '2026-08-19T00:00:00Z');
    db.finishRun(runId, { targetsCount: 3, findingsCount: 12, notes: 'ok', at: '2026-08-19T00:05:00Z' });
    const row = db.raw.prepare('SELECT * FROM runs WHERE id = ?').get(runId) as any;
    expect(row.tool).toBe('nmap');
    expect(row.finished_at).toBe('2026-08-19T00:05:00Z');
    expect(row.findings_count).toBe(12);
    expect(JSON.parse(row.args_json)).toEqual({ top: 1000 });
  });
});

describe('insertPort', () => {
  it('inserts open-port rows', () => {
    const runId = db.startRun('nmap', {}, '2026-08-19T00:00:00Z');
    db.insertPort({
      target: 'gitlab.dtr.gov.hu', ip: '84.206.128.147',
      port: 443, protocol: 'tcp', service: 'https', product: 'nginx', version: '1.24.0',
    }, '2026-08-19T00:01:00Z', runId);
    const rows = db.raw.prepare('SELECT * FROM ports').all() as any[];
    expect(rows).toHaveLength(1);
    expect(rows[0].port).toBe(443);
    expect(rows[0].service).toBe('https');
    expect(rows[0].run_id).toBe(runId);
  });
});

describe('insertHttpProbe', () => {
  it('inserts fingerprint rows with JSON tech field', () => {
    db.insertHttpProbe({
      target: 'foo.example.com', url: 'https://foo.example.com/',
      status_code: 200, title: 'Login', web_server: 'nginx',
      tech: ['nginx', 'WordPress'], content_length: 4321,
    }, '2026-08-19T00:00:00Z', null);
    const row = db.raw.prepare('SELECT * FROM http_probes').get() as any;
    expect(row.status_code).toBe(200);
    expect(JSON.parse(row.tech_json)).toEqual(['nginx', 'WordPress']);
  });
});

describe('insertFinding', () => {
  it('logs cross-tool findings', () => {
    db.insertFinding({
      tool: 'nuclei', target: 'https://foo.example.com/', category: 'exposed-panel',
      severity: 'medium', title: 'Jenkins Login Panel', cve: null,
      matched_at: 'https://foo.example.com/login', meta: { info: 'panel' },
    }, '2026-08-19T00:00:00Z', null);
    const row = db.raw.prepare('SELECT * FROM findings').get() as any;
    expect(row.tool).toBe('nuclei');
    expect(row.severity).toBe('medium');
    expect(JSON.parse(row.meta_json).info).toBe('panel');
  });
});

describe('date-range queries', () => {
  beforeEach(() => {
    const runId = db.startRun('nuclei', {}, '2026-08-01T00:00:00Z');
    db.insertFinding({ tool: 'nuclei', target: 'a', category: 'x', severity: 'high', title: 'old', cve: null, matched_at: null, meta: {} }, '2026-08-01T00:00:00Z', runId);
    db.insertFinding({ tool: 'nuclei', target: 'b', category: 'x', severity: 'critical', title: 'mid', cve: null, matched_at: null, meta: {} }, '2026-08-15T00:00:00Z', runId);
    db.insertFinding({ tool: 'nuclei', target: 'c', category: 'x', severity: 'high', title: 'new', cve: null, matched_at: null, meta: {} }, '2026-08-19T00:00:00Z', runId);
  });

  it('findingsSince returns rows first seen at/after a date', () => {
    const rows = db.findingsSince('2026-08-10T00:00:00Z');
    expect(rows.map((r) => r.title).sort()).toEqual(['mid', 'new']);
  });

  it('findingsBetween returns rows within a window', () => {
    const rows = db.findingsBetween('2026-08-01T00:00:00Z', '2026-08-17T00:00:00Z');
    expect(rows.map((r) => r.title).sort()).toEqual(['mid', 'old']);
  });

  it('countBySeverity aggregates', () => {
    const counts = db.countBySeverity();
    expect(counts.find((c) => c.severity === 'high')?.n).toBe(2);
    expect(counts.find((c) => c.severity === 'critical')?.n).toBe(1);
  });
});


describe('certificates subject columns', () => {
  const cert = {
    target: 'x.example', port: 443, certIndex: 1, commonName: 'cn',
    san: [], issuer: 'CN=CA', notBefore: null, notAfter: null,
    keyAlgo: 'EC', keySize: 256, sigAlgo: 'sha256', serial: '1',
    fingerprintSha256: 'A'.repeat(64), selfSigned: false,
    organization: 'Acme Kft', orgUnit: 'IT', locality: 'Budapest', country: 'HU',
  };

  it('round-trips organization/org_unit/locality/country', () => {
    const runId = db.startRun('sslyze', {}, 'T');
    db.insertCertificate(cert, 'T', runId);
    const row = db.raw
      .prepare('SELECT organization, org_unit, locality, country FROM certificates')
      .get();
    expect(row).toEqual({ organization: 'Acme Kft', org_unit: 'IT', locality: 'Budapest', country: 'HU' });
  });

  it('adds the subject columns to a legacy certificates table, preserving old rows', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'db-migrate-'));
    try {
      const f = path.join(dir, 'legacy.db');
      const raw = new Database(f);
      raw.exec(`CREATE TABLE certificates (
        id INTEGER PRIMARY KEY, target TEXT NOT NULL, port INTEGER,
        cert_index INTEGER NOT NULL DEFAULT 1, common_name TEXT, san_json TEXT,
        issuer TEXT, not_before TEXT, not_after TEXT, key_algo TEXT, key_size INTEGER,
        sig_algo TEXT, serial TEXT, fingerprint_sha256 TEXT,
        self_signed INTEGER NOT NULL DEFAULT 0, seen_at TEXT NOT NULL, run_id INTEGER,
        UNIQUE(target, port, fingerprint_sha256))`);
      raw.prepare('INSERT INTO certificates(target, common_name, seen_at) VALUES(?,?,?)')
        .run('legacy.host', 'old.cn', 'T');
      raw.close();

      const legacyDb = openDb(f);
      const cols = new Set(
        (legacyDb.raw.prepare('PRAGMA table_info(certificates)').all() as { name: string }[]).map((r) => r.name)
      );
      for (const c of ['organization', 'org_unit', 'locality', 'country']) expect(cols.has(c)).toBe(true);
      const old = legacyDb.raw
        .prepare("SELECT common_name, organization FROM certificates WHERE target='legacy.host'")
        .get();
      expect(old).toEqual({ common_name: 'old.cn', organization: null });
      legacyDb.close();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});


describe('dns_records.last_seen', () => {
  const T1 = '2026-11-01T00:00:00Z';
  const T2 = '2026-11-02T00:00:00Z';
  const rec = { target: 'example.test', name: 'example.test', type: 'A', value: '192.0.2.1', ttl: 300 };

  it('sets last_seen to seen_at on the first insert', () => {
    db.insertDnsRecord(rec, T1, null);
    const row = db.raw.prepare('SELECT seen_at, last_seen FROM dns_records').get();
    expect(row).toEqual({ seen_at: T1, last_seen: T1 });
  });

  it('keeps seen_at and moves last_seen on a repeat, leaving one row', () => {
    db.insertDnsRecord(rec, T1, null);
    db.insertDnsRecord(rec, T2, null);
    const rows = db.raw.prepare('SELECT seen_at, last_seen FROM dns_records').all();
    expect(rows).toEqual([{ seen_at: T1, last_seen: T2 }]);
  });

  it('adds the column to a legacy table, keeps old rows NULL, and reopens cleanly', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'db-migrate-'));
    try {
      const f = path.join(dir, 'legacy.db');
      const raw = new Database(f);
      raw.exec(`CREATE TABLE dns_records (
        id INTEGER PRIMARY KEY, target TEXT NOT NULL, name TEXT NOT NULL,
        type TEXT NOT NULL, value TEXT NOT NULL, ttl INTEGER, seen_at TEXT NOT NULL,
        run_id INTEGER, UNIQUE(target, name, type, value))`);
      raw.prepare('INSERT INTO dns_records(target, name, type, value, seen_at) VALUES(?,?,?,?,?)')
        .run('old.example', 'old.example', 'A', '198.51.100.1', T1);
      raw.close();

      const first = openDb(f);
      const cols = (first.raw.prepare('PRAGMA table_info(dns_records)').all() as { name: string }[])
        .filter((r) => r.name === 'last_seen');
      expect(cols).toHaveLength(1);
      expect(first.raw.prepare('SELECT last_seen FROM dns_records').get()).toEqual({ last_seen: null });
      first.close();

      let second: Db | undefined;
      expect(() => { second = openDb(f); }).not.toThrow();
      second?.close();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});


describe('host_state', () => {
  const T1 = '2026-11-01T00:00:00Z';
  const T2 = '2026-11-02T00:00:00Z';

  it('creates the host_state table', () => {
    const tables = db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r: any) => r.name);
    expect(tables).toContain('host_state');
  });

  it('archives non-resolvers and keeps resolvers active', () => {
    db.applyHostResolution(['up.example', 'dead.example'], new Set(['up.example']), T1, 1);
    const rows = db.hostStates();
    expect(rows.find((r) => r.target === 'up.example')).toMatchObject({ active: 1, reason: null });
    expect(rows.find((r) => r.target === 'dead.example')).toMatchObject({ active: 0, reason: 'dns', dns_fail_count: 1 });
  });

  it('archivedTargets round-trips', () => {
    expect(db.archivedTargets().size).toBe(0);
    db.applyHostResolution(['up.example', 'dead.example'], new Set(['up.example']), T1, 1);
    expect([...db.archivedTargets()]).toEqual(['dead.example']);
  });

  it('un-archives a host that resolves on a later run', () => {
    db.applyHostResolution(['dead.example'], new Set(), T1, 1);
    expect(db.archivedTargets().has('dead.example')).toBe(true);
    db.applyHostResolution(['dead.example'], new Set(['dead.example']), T2, 1);
    expect(db.archivedTargets().has('dead.example')).toBe(false);
    expect(db.hostStates()[0]).toMatchObject({ active: 1, dns_fail_count: 0, last_resolved: T2 });
  });

  it('accrues dns_fail_count across runs and honours the threshold', () => {
    db.applyHostResolution(['flaky.example'], new Set(), T1, 2);
    expect(db.archivedTargets().size).toBe(0);
    expect(db.hostStates()[0]!.dns_fail_count).toBe(1);
    db.applyHostResolution(['flaky.example'], new Set(), T2, 2);
    expect(db.archivedTargets().has('flaky.example')).toBe(true);
  });

  it('is a no-op for an empty batch', () => {
    db.applyHostResolution([], new Set(['x.example']), T1, 1);
    expect(db.hostStates()).toEqual([]);
  });
});

describe('http_probes.ip', () => {
  const probe = { target: 'a.example', url: 'https://a.example' };

  it('stores the ip given and NULL when none', () => {
    db.insertHttpProbe({ ...probe, ip: '192.0.2.1' }, 'T1', null);
    db.insertHttpProbe(probe, 'T2', null);
    expect(db.raw.prepare('SELECT ip FROM http_probes ORDER BY id').all()).toEqual([{ ip: '192.0.2.1' }, { ip: null }]);
  });

  it('adds the column to a legacy table, keeps old rows NULL, and reopens cleanly', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'db-migrate-'));
    try {
      const f = path.join(dir, 'legacy.db');
      const raw = new Database(f);
      raw.exec(`CREATE TABLE http_probes (
        id INTEGER PRIMARY KEY, target TEXT NOT NULL, url TEXT NOT NULL, status_code INTEGER,
        title TEXT, web_server TEXT, tech_json TEXT, content_length INTEGER, hash_body TEXT,
        seen_at TEXT NOT NULL, run_id INTEGER)`);
      raw.prepare('INSERT INTO http_probes(target, url, seen_at) VALUES(?,?,?)').run('old.example', 'https://old.example', 'T0');
      raw.close();

      const first = openDb(f);
      const count = (d: Db, t: string) =>
        (d.raw.prepare(`PRAGMA table_info(${t})`).all() as { name: string }[]).filter((r) => r.name === (t === 'http_probes' ? 'ip' : 'from_http')).length;
      expect(count(first, 'http_probes')).toBe(1);
      expect(first.raw.prepare('SELECT ip FROM http_probes').get()).toEqual({ ip: null });
      first.close();

      let second: Db | undefined;
      expect(() => { second = openDb(f); }).not.toThrow();
      expect(count(second!, 'http_probes')).toBe(1);
      second?.close();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('target_network.from_http', () => {
  it('adds the column to a legacy table, keeps old rows 0, and reopens cleanly', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'db-migrate-'));
    try {
      const f = path.join(dir, 'legacy.db');
      const raw = new Database(f);
      raw.exec(`CREATE TABLE target_network (
        target TEXT NOT NULL, ip TEXT NOT NULL, ip_version INTEGER NOT NULL, ip_class TEXT NOT NULL,
        asn TEXT, as_name TEXT, as_domain TEXT, country_code TEXT, country TEXT,
        geo_checked_at TEXT, ptr_json TEXT, from_ports INTEGER NOT NULL DEFAULT 0,
        from_dns INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        PRIMARY KEY (target, ip)) WITHOUT ROWID`);
      raw.prepare("INSERT INTO target_network(target, ip, ip_version, ip_class, first_seen, last_seen) VALUES('o.example','192.0.2.1',4,'public','T0','T0')").run();
      raw.close();

      for (let i = 0; i < 2; i++) {
        const d = openDb(f);
        const cols = (d.raw.prepare('PRAGMA table_info(target_network)').all() as { name: string }[]).filter((r) => r.name === 'from_http');
        expect(cols).toHaveLength(1);
        expect(d.raw.prepare('SELECT from_http FROM target_network').get()).toEqual({ from_http: 0 });
        d.close();
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('checkpointNoWait', () => {
  function tempWal(): { dir: string; file: string; open: () => Database.Database } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ckpt-'));
    const file = path.join(dir, 'test.db');
    const open = () => {
      const c = new Database(file);
      c.pragma('journal_mode = WAL');
      return c;
    };
    const init = open();
    init.exec('CREATE TABLE t (x INTEGER)');
    init.close();
    return { dir, file, open };
  }

  it('gives up at once while a reader is open and leaves the write lock free', () => {
    const { dir, open } = tempWal();
    const reader = open();
    const writer = open();
    const checkpointer = open();
    const third = open();
    try {
      reader.exec('BEGIN');
      reader.prepare('SELECT count(*) FROM t').get();
      writer.prepare('INSERT INTO t VALUES (1)').run();

      const t0 = Date.now();
      expect(checkpointNoWait(checkpointer)).toBe(false);
      expect(Date.now() - t0).toBeLessThan(500);

      third.pragma('busy_timeout = 100');
      expect(() => third.exec('BEGIN IMMEDIATE; COMMIT')).not.toThrow();
    } finally {
      for (const c of [reader, writer, checkpointer, third]) c.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('truncates the WAL when no reader is open', () => {
    const { dir, file, open } = tempWal();
    const writer = open();
    try {
      writer.prepare('INSERT INTO t VALUES (1)').run();
      expect(fs.statSync(`${file}-wal`).size).toBeGreaterThan(0);
      expect(checkpointNoWait(writer)).toBe(true);
      expect(fs.statSync(`${file}-wal`).size).toBe(0);
    } finally {
      writer.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('restores busy_timeout after a checkpoint', () => {
    const { dir, open } = tempWal();
    const c = open();
    try {
      c.pragma('busy_timeout = 4321');
      checkpointNoWait(c);
      expect(c.pragma('busy_timeout', { simple: true })).toBe(4321);
    } finally {
      c.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('restores busy_timeout when the checkpoint throws', () => {
    let timeout = 4321;
    const fake = {
      pragma(sql: string, opts?: { simple?: boolean }) {
        const m = /^busy_timeout = (\d+)$/.exec(sql);
        if (m) { timeout = Number(m[1]); return undefined; }
        if (sql === 'busy_timeout') return opts?.simple ? timeout : [{ timeout }];
        throw new Error('checkpoint failed');
      },
    } as unknown as Database.Database;
    expect(() => checkpointNoWait(fake)).toThrow('checkpoint failed');
    expect(timeout).toBe(4321);
  });

  // report-worker.ts runs main() on import, so the call sites are checked by reading them.
  it.each(['worker.ts', 'report-worker.ts'])('%s checkpoints through checkpointNoWait', (file) => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');
    expect(src).toContain('checkpointNoWait(');
    expect(src).not.toContain('wal_checkpoint(TRUNCATE)');
  });
});
