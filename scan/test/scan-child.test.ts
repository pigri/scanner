import { describe, it, expect } from 'vitest';
import { EventEmitter } from 'node:events';
import { spawn as realSpawn } from 'node:child_process';
import { spawnGrouped, type SpawnedChild } from '../src/lib/scan-child.js';

class FakeChild extends EventEmitter { constructor(public pid: number | undefined) { super(); } }

function harness(...a: [] | [number | undefined]) {
  const pid = a.length ? a[0] : 4242;
  const kills: { pid: number; sig: string }[] = [];
  const spawnCalls: { cmd: string; opts: Record<string, unknown> }[] = [];
  const timers: { ms: number; cb: () => void; live: boolean }[] = [];
  const child = new FakeChild(pid);
  const opts = {
    spawnFn: ((cmd: string, _a: string[], o: Record<string, unknown>) => { spawnCalls.push({ cmd, opts: o }); return child; }) as unknown as typeof realSpawn,
    killFn: (p: number, sig: NodeJS.Signals) => { kills.push({ pid: p, sig }); },
    setTimeoutFn: ((cb: () => void, ms: number) => { const t = { ms, cb, live: true }; timers.push(t); return t; }) as unknown as typeof setTimeout,
    clearTimeoutFn: ((t: { live: boolean }) => { t.live = false; }) as unknown as typeof clearTimeout,
    graceMs: 60_000,
  };
  return { kills, spawnCalls, timers, child, opts };
}

describe('spawnGrouped', () => {
  it('spawns detached so the child leads its own group', () => {
    const h = harness();
    spawnGrouped('npx', ['tsx'], { env: {}, ...h.opts });
    expect(h.spawnCalls[0]!.opts.detached).toBe(true);
  });

  it('forwards the signal to the recorded group only, then resolves on close', async () => {
    const h = harness(4242);
    const c = spawnGrouped('npx', [], { env: {}, ...h.opts });
    const stopped = c.stop('SIGTERM');
    expect(h.kills).toEqual([{ pid: -4242, sig: 'SIGTERM' }]);
    expect(h.timers[0]!.ms).toBe(60_000);
    h.child.emit('close', 143);
    await stopped;
    expect(await c.done).toBe(143);
    expect(h.timers[0]!.live).toBe(false);
    expect(h.kills).toHaveLength(1);
  });

  it('SIGKILLs the recorded group when the child outlives the grace period', async () => {
    const h = harness(4242);
    const c = spawnGrouped('npx', [], { env: {}, ...h.opts });
    const stopped = c.stop('SIGINT');
    h.timers[0]!.cb();
    expect(h.kills).toEqual([{ pid: -4242, sig: 'SIGINT' }, { pid: -4242, sig: 'SIGKILL' }]);
    h.child.emit('close', null);
    await stopped;
    expect(await c.done).toBe(-1);
  });

  it('never signals after the child has closed', async () => {
    const h = harness(4242);
    const c = spawnGrouped('npx', [], { env: {}, ...h.opts });
    h.child.emit('close', 0);
    await c.stop('SIGTERM');
    expect(h.kills).toEqual([]);
  });

  it.each([undefined, 0, 1, -5, 1.5])('never signals when the recorded pid is %s', async (pid) => {
    const h = harness(pid as number | undefined);
    const c = spawnGrouped('npx', [], { env: {}, ...h.opts });
    const stopped = c.stop('SIGTERM');
    h.child.emit('close', 0);
    await stopped;
    expect(h.kills).toEqual([]);
  });

  it('resolves -1 when the spawn fails', async () => {
    const h = harness(undefined);
    const c = spawnGrouped('npx', [], { env: {}, ...h.opts });
    h.child.emit('error', new Error('ENOENT'));
    expect(await c.done).toBe(-1);
  });

  it('a second stop does not start a second timer', async () => {
    const h = harness(4242);
    const c = spawnGrouped('npx', [], { env: {}, ...h.opts });
    const a = c.stop('SIGTERM'); const b = c.stop('SIGINT');
    expect(h.timers).toHaveLength(1);
    h.child.emit('close', 0);
    await Promise.all([a, b]);
  });
});

// Real processes: a tiny node script that we start and stop through the module.
const SCRIPT = (ignore: boolean): string =>
  `${ignore ? "process.on('SIGTERM',()=>{});" : ''}console.log('ready');setInterval(()=>{},1000);`;

describe('spawnGrouped with a real child', () => {
  const run = (ignore: boolean, graceMs: number): SpawnedChild =>
    spawnGrouped(process.execPath, ['-e', SCRIPT(ignore)], { env: process.env, stdio: 'ignore', graceMs });
  const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

  it('stops a child that honours SIGTERM', async () => {
    const c = run(false, 5000);
    await sleep(300);
    await c.stop('SIGTERM');
    await c.done;
    expect(c.pgid).toBeGreaterThan(1);
  }, 15_000);

  it('SIGKILLs a child that ignores SIGTERM after the grace period', async () => {
    const c = run(true, 400);
    await sleep(500);
    const t0 = Date.now();
    await c.stop('SIGTERM');
    expect(Date.now() - t0).toBeGreaterThanOrEqual(350);
    expect(await c.done).toBe(-1);
  }, 15_000);
});
