import { describe, it, expect } from 'vitest';
import { nucleiCoveredTargets, nucleiSkippedHosts, parseMatched, hostOf } from '../src/lib/nuclei-coverage.js';

const T = 'www.example.test';
const ssl = { type: 'ssl', 'matched-at': `${T}:443`, stored: true };
const http = { type: 'http', 'matched-at': `https://${T}/app/login`, stored: true };

describe('nucleiCoveredTargets', () => {
  it('covers nothing on the host pass', () => {
    expect(nucleiCoveredTargets([T], [ssl, http], { fromUrls: false, exitCode: 0 })).toEqual([]);
  });

  it('covers nothing when nuclei did not exit 0 (error or scan-timeout kill)', () => {
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: -1 })).toEqual([]);
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: 1 })).toEqual([]);
  });

  it('does not cover a target that only has dns rows', () => {
    const dns = { type: 'dns', 'matched-at': T, stored: true };
    expect(nucleiCoveredTargets([T], [dns], { fromUrls: true, exitCode: 0 })).toEqual([]);
  });

  it('does not cover a target with no row, nor one matched off-target', () => {
    const other = { type: 'http', 'matched-at': 'https://other.example.test/', stored: true };
    expect(nucleiCoveredTargets([T], [], { fromUrls: true, exitCode: 0 })).toEqual([]);
    expect(nucleiCoveredTargets([T], [other], { fromUrls: true, exitCode: 0 })).toEqual([]);
    expect(nucleiCoveredTargets([T], [{ type: 'http', 'matched-at': `https://evil.example.test/${T}`, stored: true }], { fromUrls: true, exitCode: 0 })).toEqual([]);
  });

  it('covers a target through an ssl row on host:443', () => {
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: 0 })).toEqual([T]);
  });

  it('covers a target through a URL-sample row', () => {
    expect(nucleiCoveredTargets([T], [http], { fromUrls: true, exitCode: 0 })).toEqual([T]);
  });

  it('compares hostnames case-insensitively and ignores the port', () => {
    const r = { type: 'http', 'matched-at': 'https://WWW.Example.test:8443/x', stored: true };
    expect(nucleiCoveredTargets([T], [r], { fromUrls: true, exitCode: 0 })).toEqual([T]);
  });

  it('returns each covered target once, in target order', () => {
    const rows = [http, { type: 'ssl', 'matched-at': 'a.example.test:443', stored: true }];
    expect(nucleiCoveredTargets([T, 'a.example.test', T, 'b.example.test'], rows, { fromUrls: true, exitCode: 0 }))
      .toEqual([T, 'a.example.test']);
  });
});

describe('nucleiCoveredTargets storage and skips', () => {
  const opts = { fromUrls: true, exitCode: 0 };

  it('does not cover a target whose only qualifying row failed to store', () => {
    expect(nucleiCoveredTargets([T], [{ ...ssl, stored: false }], opts)).toEqual([]);
  });

  it('does not cover a target when any of its rows failed to store', () => {
    expect(nucleiCoveredTargets([T], [ssl, { ...http, stored: false }], opts)).toEqual([]);
    expect(nucleiCoveredTargets([T], [ssl, { type: 'dns', 'matched-at': T, stored: false }], opts)).toEqual([]);
  });

  it('does not cover a target nuclei skipped, even with rows', () => {
    expect(nucleiCoveredTargets([T], [ssl], { ...opts, skipped: new Set([T]) })).toEqual([]);
  });
});

describe('nucleiSkippedHosts', () => {
  const skipLine = '[INF] Skipped www.example.test:443 from target list as found unresponsive 30 times';
  const errLine = (addr: string) => JSON.stringify({ template: 't.yaml', type: 'http', input: `https://${addr}/p`, address: addr, error: 'cause="connection reset by peer"', kind: 'unknown-error' });

  it('reads the skip message from stderr, port and case ignored', () => {
    const got = nucleiSkippedHosts(`noise\n${skipLine}\n[INF] Skipped WWW2.Example.test from target list as found unresponsive 2 times\n`, [], 30);
    expect([...got].sort()).toEqual(['www.example.test', 'www2.example.test']);
  });

  it('counts elog errors per host against the limit', () => {
    const lines = [...Array(3).fill(errLine('a.example.test:443')), errLine('b.example.test:443'), 'not json'];
    expect([...nucleiSkippedHosts('', lines, 3)]).toEqual(['a.example.test']);
  });

  it('is empty when nothing was skipped', () => {
    expect(nucleiSkippedHosts('[INF] Scan completed', [], 30).size).toBe(0);
  });
});

describe('parseMatched', () => {
  it('returns host and hostname from one parse', () => {
    expect(parseMatched('https://WWW.Example.test:8443/x')).toEqual({ host: 'www.example.test:8443', hostname: 'www.example.test' });
    expect(parseMatched('www.example.test:443')).toEqual({ host: 'www.example.test', hostname: 'www.example.test' });
    expect(parseMatched(undefined)).toEqual({ host: '', hostname: '' });
  });
});

describe('hostOf', () => {
  it('extracts the host of a URL or host:port', () => {
    expect(hostOf('https://www.example.test/a')).toBe('www.example.test');
    expect(hostOf(undefined)).toBe('');
  });
});
