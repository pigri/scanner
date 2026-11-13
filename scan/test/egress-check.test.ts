import { describe, it, expect } from 'vitest';
import { checkNetns, checkDns, makePreflight, exitCodeFor, preflightFromOpts, EXIT_RESTART } from '../src/lib/egress-check.js';

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
