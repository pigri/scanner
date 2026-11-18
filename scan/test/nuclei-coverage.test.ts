import { describe, it, expect } from 'vitest';
import { nucleiCoveredTargets, hostOf } from '../src/lib/nuclei-coverage.js';

const T = 'www.example.test';
const ssl = { type: 'ssl', 'matched-at': `${T}:443` };
const http = { type: 'http', 'matched-at': `https://${T}/app/login` };

describe('nucleiCoveredTargets', () => {
  it('covers nothing on the host pass', () => {
    expect(nucleiCoveredTargets([T], [ssl, http], { fromUrls: false, exitCode: 0 })).toEqual([]);
  });

  it('covers nothing when nuclei did not exit 0 (error or scan-timeout kill)', () => {
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: -1 })).toEqual([]);
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: 1 })).toEqual([]);
  });

  it('does not cover a target that only has dns rows', () => {
    const dns = { type: 'dns', 'matched-at': T };
    expect(nucleiCoveredTargets([T], [dns], { fromUrls: true, exitCode: 0 })).toEqual([]);
  });

  it('does not cover a target with no row, nor one matched off-target', () => {
    const other = { type: 'http', 'matched-at': 'https://other.example.test/' };
    expect(nucleiCoveredTargets([T], [], { fromUrls: true, exitCode: 0 })).toEqual([]);
    expect(nucleiCoveredTargets([T], [other], { fromUrls: true, exitCode: 0 })).toEqual([]);
    expect(nucleiCoveredTargets([T], [{ type: 'http', 'matched-at': `https://evil.example.test/${T}` }], { fromUrls: true, exitCode: 0 })).toEqual([]);
  });

  it('covers a target through an ssl row on host:443', () => {
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: 0 })).toEqual([T]);
  });

  it('covers a target through a URL-sample row', () => {
    expect(nucleiCoveredTargets([T], [http], { fromUrls: true, exitCode: 0 })).toEqual([T]);
  });

  it('compares hostnames case-insensitively and ignores the port', () => {
    const r = { type: 'http', 'matched-at': 'https://WWW.Example.test:8443/x' };
    expect(nucleiCoveredTargets([T], [r], { fromUrls: true, exitCode: 0 })).toEqual([T]);
  });

  it('returns each covered target once, in target order', () => {
    const rows = [http, { type: 'ssl', 'matched-at': 'a.example.test:443' }];
    expect(nucleiCoveredTargets([T, 'a.example.test', T, 'b.example.test'], rows, { fromUrls: true, exitCode: 0 }))
      .toEqual([T, 'a.example.test']);
  });
});

describe('hostOf', () => {
  it('extracts the host of a URL or host:port', () => {
    expect(hostOf('https://www.example.test/a')).toBe('www.example.test');
    expect(hostOf(undefined)).toBe('');
  });
});
