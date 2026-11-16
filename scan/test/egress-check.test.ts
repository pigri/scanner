import { describe, it, expect } from 'vitest';
import { checkNetns, checkDns, makePreflight, exitCodeFor, preflightFromOpts, postBatchFromOpts, EXIT_RESTART } from '../src/lib/egress-check.js';

const netnsDeps = (ino: number, link: string) => ({
  statIno: (p: string) => { if (p !== '/run/netns/vpn') throw new Error(`unexpected path ${p}`); return ino; },
  readlink: (p: string) => { if (p !== '/proc/self/ns/net') throw new Error(`unexpected path ${p}`); return link; },
});

describe('checkNetns', () => {
  it('is ok when the named namespace is the one this process is in', () => {
    expect(checkNetns('vpn', netnsDeps(4026500001, 'net:[4026500001]'))).toEqual({ status: 'ok' });
  });

  it('reports a mismatch with both inodes', () => {
    expect(checkNetns('vpn', netnsDeps(4026500002, 'net:[4026500001]')))
      .toEqual({ status: 'mismatch', expected: 4026500002, actual: 4026500001 });
  });

  it('errors when the namespace file is missing', () => {
    const deps = { statIno: () => { throw new Error('ENOENT: no such file'); }, readlink: () => 'net:[1]' };
    const r = checkNetns('vpn', deps);
    expect(r.status).toBe('error');
    expect(JSON.stringify(r)).toContain('ENOENT');
  });

  it('errors when /proc/self/ns/net cannot be read', () => {
    const deps = { statIno: () => 1, readlink: () => { throw new Error('EACCES'); } };
    expect(checkNetns('vpn', deps).status).toBe('error');
  });

  it('errors on an unparsable link', () => {
    expect(checkNetns('vpn', netnsDeps(1, 'mnt:[1]')).status).toBe('error');
    expect(checkNetns('vpn', netnsDeps(1, 'net:[abc]')).status).toBe('error');
    expect(checkNetns('vpn', netnsDeps(1, '')).status).toBe('error');
  });

  it.each(['', '../etc', 'a/b', '..', 'x/../y'])('rejects the name %j without touching the filesystem', (name) => {
    const deps = { statIno: () => { throw new Error('touched'); }, readlink: () => { throw new Error('touched'); } };
    const r = checkNetns(name, deps);
    expect(r.status).toBe('error');
    expect(JSON.stringify(r)).not.toContain('touched');
  });
});

describe('checkDns', () => {
  it('is ok when the probe resolves', async () => {
    expect(await checkDns('probe.test', 1000, { resolve: async () => undefined })).toEqual({ status: 'ok' });
  });

  it('fails with the reason when the lookup rejects', async () => {
    const r = await checkDns('probe.test', 1000, { resolve: async () => { throw new Error('ENOTFOUND probe.test'); } });
    expect(r).toEqual({ status: 'fail', reason: 'ENOTFOUND probe.test' });
  });

  it('times out when the lookup never settles', async () => {
    const r = await checkDns('probe.test', 20, { resolve: () => new Promise<void>(() => {}) });
    expect(r).toEqual({ status: 'timeout' });
  });

  it('cancels the pending lookup on timeout, and not otherwise', async () => {
    let cancelled = 0;
    await checkDns('probe.test', 20, { resolve: () => new Promise<void>(() => {}), cancel: () => { cancelled++; } });
    expect(cancelled).toBe(1);
    await checkDns('probe.test', 1000, { resolve: async () => undefined, cancel: () => { cancelled++; } });
    expect(cancelled).toBe(1);
  });

  it('passes the host to the resolver', async () => {
    let seen = '';
    await checkDns('probe.test', 1000, { resolve: async (h) => { seen = h; } });
    expect(seen).toBe('probe.test');
  });
});

describe('makePreflight', () => {
  const mk = (ino: number, resolve: () => Promise<unknown>) => makePreflight({
    netns: 'vpn', dnsProbe: 'probe.test', timeoutMs: 20,
    deps: { netns: netnsDeps(ino, 'net:[7]'), dns: { resolve: resolve as () => Promise<void> } },
  });

  it('is ok when netns matches and DNS resolves', async () => {
    expect(await mk(7, async () => undefined)()).toEqual({ action: 'ok' });
  });

  it('asks for a restart on a netns mismatch, without needing DNS', async () => {
    let dnsCalled = false;
    const r = await mk(8, async () => { dnsCalled = true; })();
    expect(r.action).toBe('restart');
    expect(dnsCalled).toBe(false);
  });

  it('asks for a restart when the namespace is missing', async () => {
    const p = makePreflight({
      netns: 'vpn', dnsProbe: 'probe.test', timeoutMs: 20,
      deps: { netns: { statIno: () => { throw new Error('ENOENT'); }, readlink: () => 'net:[7]' }, dns: { resolve: async () => undefined } },
    });
    expect((await p()).action).toBe('restart');
  });

  it('retries on a DNS failure', async () => {
    const r = await mk(7, async () => { throw new Error('SERVFAIL'); })();
    expect(r.action).toBe('retry');
    expect(JSON.stringify(r)).toContain('SERVFAIL');
  });

  it('retries on a DNS timeout', async () => {
    expect((await mk(7, () => new Promise(() => {}))()).action).toBe('retry');
  });
});

describe('exitCodeFor', () => {
  it('is 75 when the loop asked for a restart', () => {
    expect(EXIT_RESTART).toBe(75);
    expect(exitCodeFor({ batches: 0, restart: 'wrong namespace' })).toBe(75);
  });

  it('is 0 on a normal finish', () => {
    expect(exitCodeFor({ batches: 3 })).toBe(0);
  });
});

describe('preflightFromOpts', () => {
  it('is off without --netns', () => {
    expect(preflightFromOpts({ netns: null, dnsProbe: 'probe.test', dnsTimeoutMs: 20 })).toBeUndefined();
  });

  it('checks the given netns and resolves the given probe', async () => {
    let seen = '';
    const pf = preflightFromOpts(
      { netns: 'vpn', dnsProbe: 'probe.test', dnsTimeoutMs: 20 },
      { netns: netnsDeps(7, 'net:[7]'), dns: { resolve: async (h) => { seen = h; } } },
    );
    expect(await pf!()).toEqual({ action: 'ok' });
    expect(seen).toBe('probe.test');
  });

  it('restarts on a mismatch and uses the given DNS timeout', async () => {
    const dns = { resolve: () => new Promise<void>(() => {}) };
    expect((await preflightFromOpts({ netns: 'vpn', dnsProbe: 'p', dnsTimeoutMs: 20 }, { netns: netnsDeps(8, 'net:[7]'), dns })!())!.action).toBe('restart');
    const t0 = Date.now();
    expect((await preflightFromOpts({ netns: 'vpn', dnsProbe: 'p', dnsTimeoutMs: 20 }, { netns: netnsDeps(7, 'net:[7]'), dns })!())!.action).toBe('retry');
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});

describe('postBatchFromOpts', () => {
  it('is off without --netns', () => {
    expect(postBatchFromOpts({ netns: null })).toBeUndefined();
  });

  it('is ok when the namespace still matches', async () => {
    expect(await postBatchFromOpts({ netns: 'vpn' }, { netns: netnsDeps(7, 'net:[7]') })!()).toEqual({ action: 'ok' });
  });

  it('asks for a restart on a mismatch, naming both inodes', async () => {
    const r = await postBatchFromOpts({ netns: 'vpn' }, { netns: netnsDeps(8, 'net:[7]') })!();
    expect(r.action).toBe('restart');
    expect(JSON.stringify(r)).toContain('7');
    expect(JSON.stringify(r)).toContain('8');
  });

  it('asks for a restart when the namespace is gone', async () => {
    const r = await postBatchFromOpts({ netns: 'vpn' }, { netns: { statIno: () => { throw new Error('ENOENT'); }, readlink: () => 'net:[7]' } })!();
    expect(r.action).toBe('restart');
    expect(JSON.stringify(r)).toContain('ENOENT');
  });
});

// ---- egress country check ----
import { checkEgressCountry, makeCountryGate, normalizeCountryCode } from '../src/lib/egress-check.js';
import type { GeoLookup } from '../src/lib/geoip.js';

const IP = '203.0.113.7'; // documentation range
const geoFor = (cc: string | null): GeoLookup => ({ buildAt: null, get: (ip) => (ip === IP && cc ? { country_code: cc } : null) });
const okFetch = (body: string, status = 200) => (async () => new Response(body, { status })) as unknown as typeof fetch;
const cdeps = (o: { fetch?: typeof fetch; geo?: GeoLookup | null; now?: () => number; timeoutMs?: number } = {}) => ({
  fetch: o.fetch ?? okFetch(`${IP}\n`),
  openGeo: async () => (o.geo === undefined ? geoFor('HU') : o.geo),
  ...(o.now ? { now: o.now } : {}),
  ...(o.timeoutMs ? { timeoutMs: o.timeoutMs } : {}),
});
const base = { country: null as string | null, notCountry: null as string | null, echoUrl: 'https://echo.test/', mmdb: 'x.mmdb' };

describe('normalizeCountryCode', () => {
  it('uppercases a two-letter code and rejects the rest', () => {
    expect(normalizeCountryCode('hu')).toBe('HU');
    expect(() => normalizeCountryCode('HUN')).toThrow();
    expect(() => normalizeCountryCode('')).toThrow();
    expect(() => normalizeCountryCode('1a')).toThrow();
  });
});

describe('checkEgressCountry', () => {
  it('passes when the country equals --egress-country', async () => {
    expect(await checkEgressCountry({ ...base, country: 'HU' }, cdeps())).toEqual({ status: 'ok', country: 'HU' });
  });
  it('fails when the country differs from --egress-country', async () => {
    const r = await checkEgressCountry({ ...base, country: 'HU' }, cdeps({ geo: geoFor('DE') }));
    expect(r.status).toBe('fail');
    expect(JSON.stringify(r)).toContain('DE');
  });
  it('passes --egress-not-country when the country differs', async () => {
    expect(await checkEgressCountry({ ...base, notCountry: 'HU' }, cdeps({ geo: geoFor('DE') }))).toEqual({ status: 'ok', country: 'DE' });
  });
  it('fails --egress-not-country when the country matches', async () => {
    expect((await checkEgressCountry({ ...base, notCountry: 'HU' }, cdeps({ geo: geoFor('HU') }))).status).toBe('fail');
  });
  it('fails closed when the country is unknown', async () => {
    expect((await checkEgressCountry({ ...base, notCountry: 'HU' }, cdeps({ geo: geoFor(null) }))).status).toBe('fail');
  });
  it('fails closed on a fetch error, without leaking the IP', async () => {
    const f = (async () => { throw new Error(`connect ECONNREFUSED ${IP}:443`); }) as unknown as typeof fetch;
    const r = await checkEgressCountry({ ...base, country: 'HU' }, cdeps({ fetch: f }));
    expect(r.status).toBe('fail');
    expect(JSON.stringify(r)).not.toContain(IP);
  });
  it('fails closed on a non-200 response', async () => {
    expect((await checkEgressCountry({ ...base, country: 'HU' }, cdeps({ fetch: okFetch(IP, 503) }))).status).toBe('fail');
  });
  it('fails closed on a timeout', async () => {
    const f = ((_u: unknown, init: RequestInit) => new Promise((_res, rej) => {
      init.signal!.addEventListener('abort', () => rej(new DOMException('aborted', 'TimeoutError')));
    })) as unknown as typeof fetch;
    const t0 = Date.now();
    const r = await checkEgressCountry({ ...base, country: 'HU' }, cdeps({ fetch: f, timeoutMs: 20 }));
    expect(r.status).toBe('fail');
    expect(Date.now() - t0).toBeLessThan(2000);
  });
  it.each(['<html>blocked</html>', '', 'not an ip', '999.1.1.1', `${IP} extra`])('fails closed on the junk body %j without echoing it', async (body) => {
    const r = await checkEgressCountry({ ...base, country: 'HU' }, cdeps({ fetch: okFetch(body) }));
    expect(r.status).toBe('fail');
    if (body) expect(JSON.stringify(r)).not.toContain(body);
  });
  it('fails closed when there is no MMDB', async () => {
    expect((await checkEgressCountry({ ...base, country: 'HU' }, cdeps({ geo: null }))).status).toBe('fail');
  });
  it('requests the echo url', async () => {
    let seen = '';
    const f = (async (u: string) => { seen = u; return new Response(IP); }) as unknown as typeof fetch;
    await checkEgressCountry({ ...base, country: 'HU' }, cdeps({ fetch: f }));
    expect(seen).toBe('https://echo.test/');
  });
});

describe('makeCountryGate', () => {
  it('does not refetch within 10 minutes after a pass, and refetches after', async () => {
    let t = 1_000_000; let calls = 0;
    const f = (async () => { calls++; return new Response(IP); }) as unknown as typeof fetch;
    const gate = makeCountryGate({ ...base, country: 'HU' }, cdeps({ fetch: f, now: () => t }));
    expect((await gate()).status).toBe('ok');
    t += 9 * 60_000;
    expect((await gate()).status).toBe('ok');
    expect(calls).toBe(1);
    t += 2 * 60_000;
    expect((await gate()).status).toBe('ok');
    expect(calls).toBe(2);
  });
  it('rechecks on every attempt after a failure', async () => {
    let t = 1_000_000; let calls = 0; let body = 'junk';
    const f = (async () => { calls++; return new Response(body); }) as unknown as typeof fetch;
    const gate = makeCountryGate({ ...base, country: 'HU' }, cdeps({ fetch: f, now: () => t }));
    expect((await gate()).status).toBe('fail');
    expect((await gate()).status).toBe('fail');
    expect(calls).toBe(2);
    body = IP;
    expect((await gate()).status).toBe('ok');
    body = 'junk'; t += 11 * 60_000;
    expect((await gate()).status).toBe('fail');
    expect((await gate()).status).toBe('fail');
    expect(calls).toBe(5);
  });
});

describe('country check wiring', () => {
  const copts = { netns: null, dnsProbe: 'p', dnsTimeoutMs: 20, egressCountry: 'HU' as string | null, egressNotCountry: null as string | null, egressEchoUrl: 'https://echo.test/', mmdb: 'x.mmdb' };
  it('is off without either country flag', () => {
    expect(preflightFromOpts({ ...copts, egressCountry: null })).toBeUndefined();
    expect(postBatchFromOpts({ ...copts, egressCountry: null })).toBeUndefined();
  });
  it('preflight retries on a mismatch and is ok on a match', async () => {
    expect(await preflightFromOpts(copts, { country: cdeps() })!()).toEqual({ action: 'ok' });
    const r = await preflightFromOpts(copts, { country: cdeps({ geo: geoFor('DE') }) })!();
    expect(r.action).toBe('retry');
  });
  it('preflight runs the netns check first and does not fetch on a mismatch', async () => {
    let calls = 0;
    const f = (async () => { calls++; return new Response(IP); }) as unknown as typeof fetch;
    const r = await preflightFromOpts({ ...copts, netns: 'vpn' }, { netns: netnsDeps(8, 'net:[7]'), country: cdeps({ fetch: f }) })!();
    expect(r.action).toBe('restart');
    expect(calls).toBe(0);
  });
  it('post-batch asks for a restart on a mismatch and is ungated', async () => {
    let calls = 0;
    const f = (async () => { calls++; return new Response(IP); }) as unknown as typeof fetch;
    const pb = postBatchFromOpts(copts, { country: cdeps({ fetch: f }) })!;
    expect(await pb()).toEqual({ action: 'ok' });
    expect(await pb()).toEqual({ action: 'ok' });
    expect(calls).toBe(2);
    const bad = postBatchFromOpts(copts, { country: cdeps({ geo: geoFor('DE') }) })!;
    const r = await bad();
    expect(r.action).toBe('restart');
    expect(JSON.stringify(r)).toContain('DE');
  });
  it('post-batch checks the netns before the country', async () => {
    const pb = postBatchFromOpts({ ...copts, netns: 'vpn' }, { netns: netnsDeps(8, 'net:[7]'), country: cdeps() })!;
    expect((await pb()).action).toBe('restart');
  });
});

describe('country check in the queue loop', () => {
  it('a post-batch country failure releases the batch and exits 75; a preflight failure claims nothing', async () => {
    const { runQueueLoop } = await import('../src/lib/queue-loop.js');
    const noop = (): void => {};
    const log = { info: noop, warn: noop, error: noop, step: noop, close: noop } as never;
    const released: number[][] = []; const done: number[] = []; let claims = 0;
    const mkQueue = (rows: { id: number; target: string; priority: number }[]) => ({
      enqueueMany: () => 0, requeueMany: () => 0,
      claimBatch: () => { claims++; return claims === 1 ? rows : []; },
      markDone: (id: number) => { done.push(id); }, markFailed: noop,
      release: (ids: number[]) => { released.push([...ids]); return ids.length; },
      heartbeat: (ids: number[]) => ids.length, reapStale: () => ({ requeued: 0, failed: 0 }),
      stats: () => ({ pending: 0, in_progress: 0, done: 0, failed: 0 }),
    }) as never;
    const copts = { netns: null, dnsProbe: 'p', dnsTimeoutMs: 20, egressCountry: 'HU', egressNotCountry: null, egressEchoUrl: 'https://echo.test/', mmdb: 'x.mmdb' };
    const common = { label: 'scan', batchSize: 5, maxBatches: 0, watch: false, pollSec: 0, log, workerId: 'w', processBatch: async () => ({ ok: true as const }) };

    const r = await runQueueLoop({ ...common, queue: mkQueue([{ id: 1, target: 't', priority: 1 }]),
      postBatchCheck: postBatchFromOpts(copts, { country: cdeps({ geo: geoFor('DE') }) })! });
    expect(released).toEqual([[1]]);
    expect(done).toEqual([]);
    expect(exitCodeFor(r)).toBe(75);

    claims = 0;
    const pf = preflightFromOpts(copts, { country: cdeps({ geo: geoFor('DE') }) })!;
    let sleeps = 0;
    const r2 = await runQueueLoop({ ...common, queue: mkQueue([{ id: 2, target: 't', priority: 1 }]), preflight: pf,
      sleepFn: async () => { if (++sleeps >= 2) throw new Error("stop"); } } as never).catch((e: Error) => e);
    expect(claims).toBe(0);
    expect(r2).toBeInstanceOf(Error);
  });
});
