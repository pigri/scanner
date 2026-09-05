import { describe, it, expect } from 'vitest';
import { computeScore, matchesRiskKeyword, type TargetSignals } from '../src/lib/risk.js';

const empty = (): TargetSignals => ({
  target: 'foo.example.com',
  findings: [],
  ports: [],
  http: [],
  hostShared: 0,
  hostCountryCode: null,
  firstSeen: null,
  now: '2026-08-19T00:00:00Z',
});

describe('matchesRiskKeyword', () => {
  it('matches common risky substrings', () => {
    expect(matchesRiskKeyword('admin.example.com')).toContain('admin');
    expect(matchesRiskKeyword('dev-api.example.com')).toContain('dev');
    expect(matchesRiskKeyword('staging.foo.tld')).toContain('staging');
    expect(matchesRiskKeyword('backup.foo.tld')).toContain('backup');
    expect(matchesRiskKeyword('legacy.old.foo.tld').length).toBeGreaterThanOrEqual(2);
    expect(matchesRiskKeyword('gitlab.foo.tld')).toContain('gitlab');
    expect(matchesRiskKeyword('phpmyadmin.foo.tld')).toContain('phpmyadmin');
  });
  it('empty on clean host', () => {
    expect(matchesRiskKeyword('www.example.com')).toEqual([]);
  });
});

describe('computeScore', () => {
  it('zero for host with no signals', () => {
    const r = computeScore(empty());
    expect(r.score).toBe(0);
    expect(r.breakdown.critical).toBe(0);
  });

  it('adds 40 for one critical finding', () => {
    const s = empty();
    s.findings = [{ tool: 'nuclei', severity: 'critical', title: 'RCE', cve: null }];
    const r = computeScore(s);
    expect(r.score).toBeGreaterThanOrEqual(40);
    expect(r.breakdown.critical).toBe(1);
  });

  it('scores high findings with diminishing returns (first 3 = 25 pts each, extras = 3 pts each, cap 100)', () => {
    const s = empty();
    s.findings = Array.from({ length: 10 }, () => ({ tool: 'nuclei', severity: 'high', title: 'x', cve: null }));
    const r = computeScore(s);
    // 3 * 25 (linear) + 7 * 3 (tail) = 75 + 21 = 96
    expect(r.breakdown.highPoints).toBe(96);
  });

  it('adds 10 for each CVE (cap 30)', () => {
    const s = empty();
    s.findings = [
      { tool: 'nuclei', severity: 'medium', title: 'a', cve: 'CVE-2024-0001' },
      { tool: 'nuclei', severity: 'medium', title: 'b', cve: 'CVE-2024-0002' },
    ];
    const r = computeScore(s);
    expect(r.breakdown.cvePoints).toBe(20);
  });

  it('adds 30 for takeover', () => {
    const s = empty();
    s.findings = [{ tool: 'takeover', severity: 'high', title: 'takeover', cve: null }];
    const r = computeScore(s);
    expect(r.breakdown.takeover).toBe(30);
  });

  it('adds 12 for weak TLS from testssl', () => {
    const s = empty();
    s.findings = [{ tool: 'testssl', severity: 'medium', title: 'RC4 supported', cve: null }];
    const r = computeScore(s);
    expect(r.breakdown.tlsWeak).toBe(12);
  });

  it('adds 8 per risk keyword (cap 24)', () => {
    const s = empty();
    s.target = 'admin-dev-staging-backup.foo.tld';
    const r = computeScore(s);
    expect(r.breakdown.keywordPoints).toBe(24);
  });

  it('adds 2 per open port (cap 20)', () => {
    const s = empty();
    s.ports = Array.from({ length: 15 }, (_, i) => ({ port: 80 + i, service: 'http' }));
    const r = computeScore(s);
    expect(r.breakdown.portPoints).toBe(20);
  });

  it('adds 4 for shared-IP fanout > 5', () => {
    const s = empty();
    s.hostShared = 12;
    const r = computeScore(s);
    expect(r.breakdown.sharedIp).toBe(4);
  });

  it('adds 15 for foreign country when hostSuffix is gov.hu', () => {
    const s = empty();
    s.hostCountryCode = 'DE';
    s.hostSuffix = 'gov.hu';
    const r = computeScore(s);
    expect(r.breakdown.foreign).toBe(15);
  });

  it('does not add foreign points when country matches expected TLD region', () => {
    const s = empty();
    s.hostCountryCode = 'HU';
    s.hostSuffix = 'gov.hu';
    const r = computeScore(s);
    expect(r.breakdown.foreign).toBe(0);
  });

  it('adds 3 for freshness < 7 days', () => {
    const s = empty();
    s.firstSeen = '2026-08-15T00:00:00Z';
    s.now = '2026-08-19T00:00:00Z';
    const r = computeScore(s);
    expect(r.breakdown.fresh).toBe(3);
  });

  it('caps total at 100', () => {
    const s = empty();
    s.findings = [
      ...Array.from({ length: 5 }, () => ({ tool: 'nuclei', severity: 'critical', title: 'x', cve: 'CVE-x' })),
      { tool: 'takeover', severity: 'high', title: 'takeover', cve: null },
      { tool: 'testssl', severity: 'high', title: 'tls', cve: null },
    ];
    s.ports = Array.from({ length: 30 }, (_, i) => ({ port: i, service: 'x' }));
    s.target = 'admin.dev.staging.backup.foo.tld';
    const r = computeScore(s);
    expect(r.score).toBe(100);
  });

  it('breakdown numbers are all non-negative integers', () => {
    const s = empty();
    s.findings = [{ tool: 'nuclei', severity: 'high', title: 'x', cve: null }];
    const r = computeScore(s);
    for (const [, v] of Object.entries(r.breakdown)) {
      if (typeof v === 'number') expect(v).toBeGreaterThanOrEqual(0);
    }
  });
});
