import { describe, it, expect, beforeEach } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';

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
