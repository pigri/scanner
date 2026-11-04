import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runExpand, type ExpandOpts, type ExpandDeps } from '../src/expand.js';
import type { FetchImpl } from '../src/lib/ct-fetch.js';

const CORPUS = [
  'ex.gov.hu', 'web1.ex.gov.hu', 'web2.ex.gov.hu', 'web3.ex.gov.hu', 'mail.ex.gov.hu',
  'wc.gov.hu', 'api1.wc.gov.hu', 'api2.wc.gov.hu', 'api3.wc.gov.hu',
];
// Permuted: web4/5/6.ex.gov.hu and api4/5/6.wc.gov.hu.
const WILDCARD_IP = '9.9.9.9';
const DNS: Record<string, string[]> = {
  'web4.ex.gov.hu': ['1.1.1.4'], // A (in CT)
  // web5: NXDOMAIN but in CT -> B
  'web6.ex.gov.hu': ['1.1.1.6'], // resolves, no CT -> C
  'zzzrand987nomatch.wc.gov.hu': [WILDCARD_IP],
  'xxx111notreal999.wc.gov.hu': [WILDCARD_IP],
  'api4.wc.gov.hu': [WILDCARD_IP], // wildcard noise, no CT -> D
  'api5.wc.gov.hu': [WILDCARD_IP],
  // api6 no resolve, no CT -> D
};

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

let dir: string;
let domains: string;
let sidecar: string;
const logs: string[] = [];

function opts(over: Partial<ExpandOpts> = {}): ExpandOpts {
  return {
    domains, sidecar, dryRun: false, mergeTierC: false, perZone: 50, maxCandidates: 1000,
    ctBudget: 20, ctFallbackBudget: 100, concurrency: 4, suffix: null, exclude: [], timeoutMs: 1000, ...over,
  };
}

function deps(over: Partial<ExpandDeps> = {}): ExpandDeps {
  const fetchImpl: FetchImpl = async (url) => {
    if (url.includes('/v1/subdomains/ex.gov.hu')) {
      return json(200, { subdomains: ['web4.ex.gov.hu', 'web5.ex.gov.hu'], after: null });
    }
    if (url.includes('/v1/subdomains/')) return json(200, { subdomains: [], after: null });
    return json(200, { used: 1 });
  };
  return {
    resolveIps: async (h) => DNS[h] ?? [],
    loadKey: () => 'k',
    fetchImpl,
    ctFallback: async () => [],
    sleep: async () => {},
    log: (s) => logs.push(s),
    ...over,
  };
}

const lines = (p: string) => readFileSync(p, 'utf8').split('\n').filter(Boolean);

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'expand-'));
  domains = join(dir, 'domains.txt');
  sidecar = join(dir, 'expand-tier-c.txt');
  writeFileSync(domains, CORPUS.join('\n') + '\n');
  logs.length = 0;
});

describe('runExpand', () => {
  it('merges tier A/B into domains, tier C into the sidecar, drops D', async () => {
    const r = await runExpand(opts(), deps());
    const merged = lines(domains);
    expect(merged).toContain('web4.ex.gov.hu');
    expect(merged).toContain('web5.ex.gov.hu');
    expect(merged).not.toContain('web6.ex.gov.hu');
    expect(merged.filter((h) => h.startsWith('api') && /api[456]/.test(h))).toEqual([]);
    expect(merged).toEqual([...merged].sort());
    expect(lines(sidecar)).toEqual(['web6.ex.gov.hu']);
    expect(r.tiers).toEqual({ A: 1, B: 1, C: 1, D: 3 });
    expect(r.ctRequests).toBeGreaterThan(0);
  });

  it('--ct-fallback-budget 0 (the default) never calls the fallback and goes DNS-only', async () => {
    const calls: string[] = [];
    const r = await runExpand(opts({ ctFallbackBudget: 0 }), deps({
      loadKey: () => { throw new Error('no key'); },
      ctFallback: async (zone) => { calls.push(zone); return ['web4.ex.gov.hu']; },
    }));
    expect(calls).toEqual([]);
    expect(r.tiers.A + r.tiers.B).toBe(0);
  });

  it('--ct-fallback-budget 1 calls the fallback for at most one zone', async () => {
    const calls: string[] = [];
    const r = await runExpand(opts({ ctFallbackBudget: 1 }), deps({
      fetchImpl: async () => json(429, {}),
      ctFallback: async (zone) => { calls.push(zone); return zone === 'ex.gov.hu' ? ['web4.ex.gov.hu'] : []; },
    }));
    expect(calls).toHaveLength(1);
    expect(r.tiers.A).toBe(1);
  });

  it('with fallback budget 0 a resolving, non-wildcard, uncorroborated candidate lands in tier C', async () => {
    const r = await runExpand(opts({ ctFallbackBudget: 0 }), deps({
      fetchImpl: async () => json(429, {}),
      ctFallback: async () => ['web6.ex.gov.hu'],
    }));
    expect(lines(sidecar)).toContain('web6.ex.gov.hu');
    expect(r.tiers.C).toBeGreaterThan(0);
  });

  it('a wildcard zone demotes a no-CT resolver to D', async () => {
    await runExpand(opts(), deps());
    expect(existsSync(sidecar) ? lines(sidecar) : []).not.toContain('api4.wc.gov.hu');
    expect(lines(domains)).not.toContain('api4.wc.gov.hu');
  });

  it('--merge-tier-c folds tier C into domains', async () => {
    await runExpand(opts({ mergeTierC: true }), deps());
    expect(lines(domains)).toContain('web6.ex.gov.hu');
  });

  it('--dry-run makes zero network calls, writes nothing, and projects the CT spend', async () => {
    const before = readFileSync(domains, 'utf8');
    let calls = 0;
    const trap = async (): Promise<never> => { calls++; throw new Error('network call in dry-run'); };
    const r = await runExpand(opts({ dryRun: true }), deps({
      fetchImpl: trap,
      ctFallback: trap,
      resolveIps: trap,
    }));
    expect(calls).toBe(0);
    expect(readFileSync(domains, 'utf8')).toBe(before);
    expect(readdirSync(dir)).toEqual(['domains.txt']);
    expect(r.zones).toEqual({ 'ex.gov.hu': 3, 'wc.gov.hu': 3 });
    expect(r.ctRequests).toBe(0);
    const out = logs.join('\n');
    expect(out).toMatch(/ex\.gov\.hu: 3 candidates/);
    expect(out).toMatch(/projected CT requests: 2\b/);
  });

  it('--dry-run caps the projected CT spend at the budget', async () => {
    await runExpand(opts({ dryRun: true, ctBudget: 1 }), deps());
    expect(logs.join('\n')).toMatch(/projected CT requests: 1\b/);
  });

  it('a 429 from ctlogs degrades to the fallback and still resolves', async () => {
    const fetch429: FetchImpl = async () => json(429, {});
    const r = await runExpand(opts(), deps({
      fetchImpl: fetch429,
      ctFallback: async (zone) => (zone === 'ex.gov.hu' ? ['web4.ex.gov.hu', 'web5.ex.gov.hu'] : []),
    }));
    expect(lines(domains)).toEqual(expect.arrayContaining(['web4.ex.gov.hu', 'web5.ex.gov.hu']));
    expect(r.tiers.A).toBe(1);
    expect(r.tiers.B).toBe(1);
  });

  it('degrades to DNS-only when ctlogs 429s and the fallback throws', async () => {
    const r = await runExpand(opts(), deps({
      fetchImpl: async () => json(429, {}),
      ctFallback: async () => { throw new Error('boom'); },
    }));
    expect(r.tiers.A + r.tiers.B).toBe(0);
    expect(lines(sidecar)).toEqual(expect.arrayContaining(['web4.ex.gov.hu', 'web6.ex.gov.hu']));
  });

  it('runs on the fallback path only when no ctlogs key is available', async () => {
    let fetched = 0;
    const r = await runExpand(opts(), deps({
      loadKey: () => { throw new Error('no key'); },
      fetchImpl: async () => { fetched++; return json(200, {}); },
      ctFallback: async (zone) => (zone === 'ex.gov.hu' ? ['web4.ex.gov.hu'] : []),
    }));
    expect(fetched).toBe(0);
    expect(r.ctRequests).toBe(0);
    expect(r.tiers.A).toBe(1);
    expect(logs.join('\n')).toMatch(/no ctlogs key/i);
  });

  it('a network error in the oracle is not fatal', async () => {
    const r = await runExpand(opts(), deps({
      fetchImpl: async () => { throw new Error('ECONNRESET'); },
    }));
    expect(r.tiers.C).toBeGreaterThan(0);
  });

  it('enforces the global CT budget across zones', async () => {
    const urls: string[] = [];
    await runExpand(opts({ ctBudget: 1 }), deps({
      fetchImpl: async (u) => { urls.push(u); return json(200, { subdomains: [], after: null }); },
    }));
    expect(urls.filter((u) => u.includes('/v1/subdomains/')).length).toBe(1);
  });

  it('caps total candidates', async () => {
    const seen: string[] = [];
    await runExpand(opts({ maxCandidates: 2 }), deps({
      resolveIps: async (h) => { seen.push(h); return DNS[h] ?? []; },
    }));
    const cands = seen.filter((h) => /\b(web|api)[456]\./.test(h));
    expect(cands.length).toBe(2);
  });

  it('keeps candidates in scope of --suffix/--exclude', async () => {
    const r = await runExpand(opts({ exclude: ['wc.gov.hu'] }), deps());
    expect(r.tiers.D).toBe(0);
  });
});
