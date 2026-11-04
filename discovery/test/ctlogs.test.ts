import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadKey, fetchSubdomains, usage } from '../src/lib/ctlogs.js';
import type { FetchImpl } from '../src/lib/ct-fetch.js';

function resp(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return new Response(text, { status, headers });
}

const KEY = 'sekrit-key-123';
const noSleep = async () => {};

describe('loadKey', () => {
  it('prefers CTLOGS_API_KEY from the environment', () => {
    expect(loadKey({ env: { CTLOGS_API_KEY: ' envkey \n' }, path: '/nonexistent/.ctlogs' })).toBe('envkey');
  });

  it('reads and trims the key file when the env var is unset', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ctlogs-'));
    const path = join(dir, '.ctlogs');
    writeFileSync(path, `  ${KEY}\n`);
    expect(loadKey({ env: {}, path })).toBe(KEY);
  });

  it('throws a clear error when neither env nor file exists', () => {
    const path = join(tmpdir(), 'ctlogs-missing-dir', '.ctlogs');
    expect(() => loadKey({ env: {}, path })).toThrow(/CTLOGS_API_KEY/);
  });

  it('throws when the file is empty', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ctlogs-'));
    const path = join(dir, '.ctlogs');
    writeFileSync(path, '\n');
    expect(() => loadKey({ env: {}, path })).toThrow(/CTLOGS_API_KEY/);
  });
});

describe('fetchSubdomains', () => {
  it('follows the after cursor across pages and concatenates hosts', async () => {
    const urls: string[] = [];
    const seen: Array<RequestInit | undefined> = [];
    const fetchImpl: FetchImpl = async (url, init) => {
      urls.push(url);
      seen.push(init);
      const after = new URL(url).searchParams.get('after');
      if (after === null) return resp(200, { subdomains: ['a.example.com', 'b.example.com'], after: 'c1' });
      if (after === 'c1') return resp(200, { subdomains: ['c.example.com'], after: 'c2' });
      return resp(200, { subdomains: ['d.example.com'], after: null });
    };
    const r = await fetchSubdomains('example.com', { fetchImpl, key: KEY, budget: 10, sleep: noSleep });
    expect(r).toEqual({
      ok: true,
      hosts: ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com'],
      requests: 3,
    });
    expect(urls[0]).toContain('https://api.ctlogs.dev/v1/subdomains/example.com');
    for (const u of urls) expect(u).not.toContain(KEY);
    expect((seen[0]?.headers as Record<string, string>).Authorization).toBe(`Bearer ${KEY}`);
  });

  it('stops at the budget and reports reason budget', async () => {
    let calls = 0;
    const fetchImpl: FetchImpl = async () => {
      calls++;
      return resp(200, { subdomains: [`h${calls}.example.com`], after: `c${calls}` });
    };
    const r = await fetchSubdomains('example.com', { fetchImpl, key: KEY, budget: 2, sleep: noSleep });
    expect(calls).toBe(2);
    expect(r).toEqual({
      ok: false,
      reason: 'budget',
      hosts: ['h1.example.com', 'h2.example.com'],
      requests: 2,
    });
  });

  it('does not exceed the budget through 429 retries', async () => {
    let calls = 0;
    const fetchImpl: FetchImpl = async () => {
      calls++;
      return resp(429, '', { 'retry-after': '1' });
    };
    const r = await fetchSubdomains('example.com', { fetchImpl, key: KEY, budget: 2, sleep: noSleep });
    expect(calls).toBeLessThanOrEqual(2);
    expect(r.ok).toBe(false);
  });

  it('returns a typed quota result when 429 persists, keeping earlier hosts', async () => {
    let n = 0;
    const fetchImpl: FetchImpl = async () => {
      n++;
      if (n === 1) return resp(200, { subdomains: ['a.example.com'], after: 'c1' });
      return resp(429, '', { 'retry-after': '1' });
    };
    const r = await fetchSubdomains('example.com', {
      fetchImpl,
      key: KEY,
      budget: 50,
      sleep: noSleep,
      maxRetries: 2,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('quota');
      expect(r.hosts).toEqual(['a.example.com']);
      expect(r.requests).toBe(4);
    }
  });

  it('throws on a non-429 error status without leaking the key', async () => {
    const fetchImpl: FetchImpl = async () => resp(500, 'boom');
    await expect(
      fetchSubdomains('example.com', { fetchImpl, key: KEY, budget: 5, sleep: noSleep }),
    ).rejects.toThrow(/HTTP 500/);
  });

  it('never puts the key in a thrown error when the fetch itself throws', async () => {
    const fetchImpl: FetchImpl = async (url, init) => {
      throw new Error(`connect failed ${url} ${JSON.stringify(init?.headers)}`);
    };
    let caught: unknown;
    try {
      await fetchSubdomains('example.com', { fetchImpl, key: KEY, budget: 5, sleep: noSleep });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(Error);
    const text = `${(caught as Error).message}\n${(caught as Error).stack ?? ''}\n${String(caught)}`;
    expect(text).not.toContain(KEY);
  });
});

describe('usage', () => {
  it('flattens numeric quota figures from /v1/usage', async () => {
    let seenUrl = '';
    const fetchImpl: FetchImpl = async (url) => {
      seenUrl = url;
      return resp(200, { month: { used: 120, limit: 10000 }, hour: { used: 3, limit: 100 }, plan: 'free' });
    };
    const u = await usage({ fetchImpl, key: KEY });
    expect(seenUrl).toBe('https://api.ctlogs.dev/v1/usage');
    expect(u.figures).toEqual({
      'month.used': 120,
      'month.limit': 10000,
      'hour.used': 3,
      'hour.limit': 100,
    });
  });

  it('survives a pathologically deep response and keeps the shallow figures', async () => {
    const depth = 50000;
    const body = '{"month":{"used":1},"deep":' + '{"a":'.repeat(depth) + '1' + '}'.repeat(depth) + '}';
    const fetchImpl: FetchImpl = async () => resp(200, body);
    const u = await usage({ fetchImpl, key: KEY });
    expect(u.figures['month.used']).toBe(1);
  });

  it('throws on a non-ok status', async () => {
    const fetchImpl: FetchImpl = async () => resp(401, 'no');
    await expect(usage({ fetchImpl, key: KEY })).rejects.toThrow(/HTTP 401/);
  });
});
