import { describe, it, expect } from 'vitest';
import {
  parseRetryAfter,
  fetchWithRetry,
  queryCertspotter,
  queryAll,
  type FetchImpl,
} from '../src/lib/ct-fetch.js';

function resp(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return new Response(text, { status, headers });
}

describe('parseRetryAfter', () => {
  it('reads an integer number of seconds', () => {
    expect(parseRetryAfter('5')).toBe(5000);
    expect(parseRetryAfter('0')).toBe(0);
  });

  it('reads an HTTP date relative to now', () => {
    const now = Date.now();
    const ms = parseRetryAfter(new Date(now + 3000).toUTCString(), now);
    expect(ms).not.toBeNull();
    expect(ms!).toBeGreaterThanOrEqual(2000);
    expect(ms!).toBeLessThanOrEqual(3000);
  });

  it('returns null for a missing or unparseable value', () => {
    expect(parseRetryAfter(null)).toBeNull();
    expect(parseRetryAfter('')).toBeNull();
    expect(parseRetryAfter('soon')).toBeNull();
  });
});

describe('fetchWithRetry', () => {
  it('retries a 429 honouring Retry-After, then returns the 200', async () => {
    const slept: number[] = [];
    let n = 0;
    const fetchImpl: FetchImpl = async () => {
      n++;
      return n === 1 ? resp(429, '', { 'retry-after': '2' }) : resp(200, [{ dns_names: ['a.gov.hu'] }]);
    };
    const res = await fetchWithRetry('http://x', {
      timeoutMs: 1000,
      fetchImpl,
      sleep: async (ms) => { slept.push(ms); },
    });
    expect(res.status).toBe(200);
    expect(n).toBe(2);
    expect(slept).toEqual([2000]);
  });

  it('falls back to exponential backoff when Retry-After is absent', async () => {
    const slept: number[] = [];
    let n = 0;
    const fetchImpl: FetchImpl = async () => { n++; return n < 3 ? resp(429, '') : resp(200, []); };
    const res = await fetchWithRetry('http://x', {
      timeoutMs: 1000,
      backoffBaseMs: 100,
      rng: () => 0.5, // jitter factor fixed -> 0.5 + 0.5 = 1.0
      fetchImpl,
      sleep: async (ms) => { slept.push(ms); },
    });
    expect(res.status).toBe(200);
    expect(slept).toEqual([100, 200]); // 100*2^0*1.0, 100*2^1*1.0
  });

  it('gives the final 429 back once the retry budget is spent', async () => {
    const slept: number[] = [];
    let n = 0;
    const fetchImpl: FetchImpl = async () => { n++; return resp(429, ''); };
    const res = await fetchWithRetry('http://x', {
      timeoutMs: 1000,
      maxRetries: 2,
      backoffBaseMs: 1,
      rng: () => 0,
      fetchImpl,
      sleep: async (ms) => { slept.push(ms); },
    });
    expect(res.status).toBe(429);
    expect(n).toBe(3); // 1 initial + 2 retries
    expect(slept.length).toBe(2);
  });

  it('caps a single wait at maxBackoffMs against a hostile Retry-After', async () => {
    const slept: number[] = [];
    let n = 0;
    const fetchImpl: FetchImpl = async () => { n++; return n === 1 ? resp(429, '', { 'retry-after': '99999' }) : resp(200, []); };
    await fetchWithRetry('http://x', {
      timeoutMs: 1000,
      maxBackoffMs: 30000,
      fetchImpl,
      sleep: async (ms) => { slept.push(ms); },
    });
    expect(slept).toEqual([30000]);
  });
});

describe('queryCertspotter', () => {
  it('sends a bearer token when one is configured', async () => {
    let seenHeaders: Record<string, string> | undefined;
    const fetchImpl: FetchImpl = async (_url, init) => {
      seenHeaders = init?.headers as Record<string, string>;
      return resp(200, [{ dns_names: ['x.gov.hu'] }]);
    };
    const hosts = await queryCertspotter('%.gov.hu', { timeoutMs: 1000, token: 'T0KEN', fetchImpl });
    expect(hosts).toEqual(['x.gov.hu']);
    expect(seenHeaders?.Authorization).toBe('Bearer T0KEN');
  });

  it('omits the Authorization header when no token is set', async () => {
    let seenHeaders: Record<string, string> | undefined;
    const fetchImpl: FetchImpl = async (_url, init) => {
      seenHeaders = init?.headers as Record<string, string>;
      return resp(200, []);
    };
    await queryCertspotter('%.gov.hu', { timeoutMs: 1000, fetchImpl });
    expect(seenHeaders?.Authorization).toBeUndefined();
  });

  it('throws on a persistent 429 after exhausting retries', async () => {
    const fetchImpl: FetchImpl = async () => resp(429, '');
    await expect(
      queryCertspotter('%.gov.hu', {
        timeoutMs: 1000, maxRetries: 1, fetchImpl, sleep: async () => {},
      }),
    ).rejects.toThrow(/429/);
  });
});

describe('queryAll', () => {
  it('unions and de-duplicates crt.sh + certspotter', async () => {
    const hosts = await queryAll('%.gov.hu', 'both', {
      timeoutMs: 1000,
      crtshEnabled: true,
      deps: {
        crtsh: async () => ['a.gov.hu', 'b.gov.hu'],
        certspotter: async () => ['b.gov.hu', 'c.gov.hu'],
      },
    });
    expect([...hosts].sort()).toEqual(['a.gov.hu', 'b.gov.hu', 'c.gov.hu']);
  });

  it('skips crt.sh when disabled but still returns certspotter hosts', async () => {
    let crtshCalled = false;
    const hosts = await queryAll('%.gov.hu', 'both', {
      timeoutMs: 1000,
      crtshEnabled: false,
      deps: {
        crtsh: async () => { crtshCalled = true; return ['a.gov.hu']; },
        certspotter: async () => ['c.gov.hu'],
      },
    });
    expect(crtshCalled).toBe(false);
    expect(hosts).toEqual(['c.gov.hu']);
  });

  it('a failing source is swallowed, not fatal', async () => {
    const hosts = await queryAll('%.gov.hu', 'both', {
      timeoutMs: 1000,
      crtshEnabled: true,
      deps: {
        crtsh: async () => { throw new Error('crt.sh returned HTTP 502'); },
        certspotter: async () => ['c.gov.hu'],
      },
    });
    expect(hosts).toEqual(['c.gov.hu']);
  });
});
