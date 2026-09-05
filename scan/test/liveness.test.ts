import { describe, it, expect } from 'vitest';
import { parseLiveHosts } from '../src/lib/liveness.js';

describe('parseLiveHosts', () => {
  it('extracts hostnames from httpx -silent URL lines', () => {
    const out = 'https://a.gov.hu\nhttp://b.gov.hu\n';
    expect([...parseLiveHosts(out)].sort()).toEqual(['a.gov.hu', 'b.gov.hu']);
  });

  it('handles a trailing [status] and ports', () => {
    const out = 'https://a.gov.hu:8443 [200]\nhttps://b.gov.hu/login [302]\n';
    const live = parseLiveHosts(out);
    expect(live.has('a.gov.hu')).toBe(true);
    expect(live.has('b.gov.hu')).toBe(true);
  });

  it('strips ANSI colour codes', () => {
    const out = '\x1b[34mhttps://a.gov.hu\x1b[0m [200]\n';
    expect(parseLiveHosts(out).has('a.gov.hu')).toBe(true);
  });

  it('lowercases and dedupes', () => {
    const out = 'https://A.GOV.HU\nhttps://a.gov.hu\n';
    expect([...parseLiveHosts(out)]).toEqual(['a.gov.hu']);
  });

  it('handles bare hosts without a scheme', () => {
    expect(parseLiveHosts('a.gov.hu\n').has('a.gov.hu')).toBe(true);
  });

  it('ignores blank lines and returns empty for empty input', () => {
    expect(parseLiveHosts('\n\n  \n').size).toBe(0);
    expect(parseLiveHosts('').size).toBe(0);
  });

  it('keeps IP targets', () => {
    expect(parseLiveHosts('https://84.206.102.29 [200]\n').has('84.206.102.29')).toBe(true);
  });
});
