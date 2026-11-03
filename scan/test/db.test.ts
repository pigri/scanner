import { describe, it, expect, beforeEach } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
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
