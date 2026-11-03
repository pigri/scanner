import { describe, it, expect } from 'vitest';
import {
  isRetryableDnsError,
  resolveHost,
  ResolverPool,
  DEFAULT_RESOLVERS,
  type ResolverLike,
} from '../src/lib/resolve.js';

const noSleep = async () => {};

/** A resolver stub whose resolve4 behaviour is scripted attempt-by-attempt. */
function stub(
  script: Array<string[] | (Error & { code?: string })>,
): { resolver: ResolverLike; calls: () => number } {
  let i = 0;
  const resolver: ResolverLike = {
    async resolve4(_name: string) {
      const step = script[Math.min(i, script.length - 1)]!;
      i++;
      if (step instanceof Error) throw step;
      return step;
    },
    async resolve6() {
      return [];
    },
    async reverse() {
      return [];
    },
  };
  return { resolver, calls: () => i };
}

function err(code: string, message = code): Error & { code?: string } {
  const e = new Error(message) as Error & { code?: string };
  e.code = code;
  return e;
}

describe('isRetryableDnsError', () => {
  it('treats transient server failures as retryable', () => {
    for (const c of ['ESERVFAIL', 'ETIMEOUT', 'EREFUSED', 'ECONNREFUSED', 'ECONNRESET']) {
      expect(isRetryableDnsError(err(c))).toBe(true);
    }
  });
  it('treats a synthetic (code-less) timeout as retryable', () => {
    expect(isRetryableDnsError(new Error('A timeout'))).toBe(true);
  });
  it('treats authoritative negatives as NOT retryable', () => {
    for (const c of ['ENOTFOUND', 'ENODATA', 'NXDOMAIN', 'NODATA']) {
      expect(isRetryableDnsError(err(c))).toBe(false);
    }
  });
});

describe('resolveHost retry', () => {
  const opts = { ipv6: false, maxTries: 3, timeoutMs: 1000 };

  it('retries a transient failure and succeeds before the cap', async () => {
    const { resolver, calls } = stub([err('ESERVFAIL'), err('ESERVFAIL'), ['1.2.3.4']]);
    const out = await resolveHost('h.gov.hu', { next: () => resolver }, opts, noSleep);
    expect(out.a).toEqual(['1.2.3.4']);
    expect(out.errors).toEqual([]);
    expect(calls()).toBe(3);
  });

  it('does NOT retry an authoritative negative (one attempt only)', async () => {
    const { resolver, calls } = stub([err('ENOTFOUND')]);
    const out = await resolveHost('nope.gov.hu', { next: () => resolver }, opts, noSleep);
    expect(out.a).toEqual([]);
    expect(calls()).toBe(1);
    expect(out.errors[0]).toMatch(/ENOTFOUND/);
  });

  it('gives up after maxTries on a persistent transient failure', async () => {
    const { resolver, calls } = stub([err('ETIMEOUT')]);
    const out = await resolveHost('slow.gov.hu', { next: () => resolver }, opts, noSleep);
    expect(out.a).toEqual([]);
    expect(calls()).toBe(3);
    expect(out.errors[0]).toMatch(/ETIMEOUT/);
  });
});

describe('ResolverPool', () => {
  it('round-robins across the configured servers', () => {
    const pool = new ResolverPool(['1.1.1.1', '8.8.8.8']);
    expect(pool.size).toBe(2);
    const a = pool.next();
    const b = pool.next();
    const c = pool.next();
    expect(a).not.toBe(b);
    expect(c).toBe(a); // wraps around
  });

  it('falls back to a single system resolver when none configured', () => {
    expect(new ResolverPool(null).size).toBe(1);
    expect(DEFAULT_RESOLVERS.length).toBeGreaterThan(0);
  });
});
