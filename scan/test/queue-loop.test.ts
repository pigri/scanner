import { describe, it, expect, vi } from 'vitest';
import { runQueueLoop, type QueueLoopOpts } from '../src/lib/queue-loop.js';
import type { QueueOps, ClaimedRow } from '../src/lib/queue.js';
import type { Logger } from '../src/lib/log.js';

const noop = (): void => {};
const log = { info: noop, warn: noop, error: noop, step: noop, close: noop } as unknown as Logger;

interface Fake { released: { ids: number[]; workerId?: string }[]; done: number[]; failed: number[]; queue: QueueOps; reaps: Parameters<QueueOps['reapStale']>[0][]; beats: { ids: number[]; atIso: string }[]; claims: string[]; calls: string[] }

function fakeQueue(batches: ClaimedRow[][]): Fake {
  const f: Fake = { released: [], done: [], failed: [], queue: null as unknown as QueueOps, reaps: [], beats: [], claims: [], calls: [] };
  const pending = [...batches];
  f.queue = {
    enqueueMany: () => 0,
    requeueMany: () => 0,
    claimBatch: (_s, _a, workerId) => { f.claims.push(workerId ?? ''); f.calls.push('claim'); return pending.shift() ?? []; },
    markDone: (id) => { f.done.push(id); },
    markFailed: (id) => { f.failed.push(id); },
    release: (ids, workerId) => { f.released.push({ ids: [...ids], ...(workerId !== undefined ? { workerId } : {}) }); f.calls.push('release'); return ids.length; },
    heartbeat: (ids, atIso) => { f.beats.push({ ids: [...ids], atIso }); return ids.length; },
    reapStale: (o) => { f.reaps.push(o); f.calls.push('reap'); return { requeued: 2, failed: 1 }; },
    stats: () => ({ pending: 0, in_progress: 0, done: 0, failed: 0 }),
  };
  return f;
}

// Manual timers: interval callbacks fire only when the test says so.
function fakeTimers() {
  const live = new Map<number, () => void>();
  let n = 0;
  return {
    live,
    setIntervalFn: ((cb: () => void) => { live.set(++n, cb); return n; }) as unknown as NonNullable<QueueLoopOpts['setIntervalFn']>,
    clearIntervalFn: ((h: number) => { live.delete(h); }) as unknown as NonNullable<QueueLoopOpts['clearIntervalFn']>,
    tick: () => { for (const cb of [...live.values()]) cb(); },
  };
}

const row = (id: number): ClaimedRow => ({ id, target: `t${id}`, priority: 1 });
const NOW = Date.parse('2026-08-19T12:00:00.000Z');
const base = (f: Fake, extra: Partial<QueueLoopOpts> = {}): QueueLoopOpts => ({
  queue: f.queue, label: 'scan', batchSize: 5, maxBatches: 0, watch: false, pollSec: 1, log,
  workerId: 'hu-1', now: () => NOW,
  processBatch: async () => ({ ok: true }),
  ...extra,
});

describe('runQueueLoop reaping and heartbeats', () => {
  it('reaps its own rows by worker id before the first claim', async () => {
    const f = fakeQueue([]);
    await runQueueLoop(base(f));
    expect(f.calls[0]).toBe('reap');
    expect(f.reaps[0]).toMatchObject({ ownerId: 'hu-1', atIso: new Date(NOW).toISOString() });
  });

  it('passes the worker id to claimBatch', async () => {
    const f = fakeQueue([[row(1)]]);
    await runQueueLoop(base(f, { maxBatches: 1 }));
    expect(f.claims).toEqual(['hu-1']);
  });

  it('heartbeats the claimed ids during a long batch and stops after it', async () => {
    const f = fakeQueue([[row(1), row(2)]]);
    const t = fakeTimers();
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const p = runQueueLoop(base(f, {
      maxBatches: 1, heartbeatMs: 60_000, setIntervalFn: t.setIntervalFn, clearIntervalFn: t.clearIntervalFn,
      processBatch: async () => { await gate; return { ok: true }; },
    }));
    await vi.waitFor(() => expect(t.live.size).toBe(1));
    t.tick(); t.tick();
    expect(f.beats).toHaveLength(2);
    expect(f.beats[0]!.ids).toEqual([1, 2]);
    release();
    await p;
    expect(t.live.size).toBe(0);
  });

  it('clears the heartbeat timer when processBatch throws', async () => {
    const f = fakeQueue([[row(1)]]);
    const t = fakeTimers();
    await runQueueLoop(base(f, {
      maxBatches: 1, setIntervalFn: t.setIntervalFn, clearIntervalFn: t.clearIntervalFn,
      processBatch: async () => { throw new Error('boom'); },
    }));
    expect(t.live.size).toBe(0);
  });

  it('a failing heartbeat does not abort the batch', async () => {
    const f = fakeQueue([[row(1)]]);
    f.queue.heartbeat = () => { throw new Error('busy'); };
    const done = vi.fn();
    f.queue.markDone = done;
    const onBatchDone = vi.fn();
    const t = fakeTimers();
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const p = runQueueLoop(base(f, {
      maxBatches: 1, setIntervalFn: t.setIntervalFn, clearIntervalFn: t.clearIntervalFn, onBatchDone,
      processBatch: async () => { await gate; return { ok: true }; },
    }));
    await vi.waitFor(() => expect(t.live.size).toBe(1));
    expect(() => t.tick()).not.toThrow();
    release();
    await p;
    expect(done).toHaveBeenCalledTimes(1);
    expect(onBatchDone).toHaveBeenCalledTimes(1);
  });

  it('warns when a heartbeat updates fewer rows than it was given (lost claim)', async () => {
    const f = fakeQueue([[row(1), row(2)]]);
    f.queue.heartbeat = () => 1;
    const warn = vi.fn();
    const t = fakeTimers();
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const p = runQueueLoop(base(f, {
      maxBatches: 1, setIntervalFn: t.setIntervalFn, clearIntervalFn: t.clearIntervalFn,
      log: { ...log, warn } as unknown as Logger,
      processBatch: async () => { await gate; return { ok: true }; },
    }));
    await vi.waitFor(() => expect(t.live.size).toBe(1));
    t.tick();
    release();
    await p;
    expect(warn.mock.calls.some((c) => /lost|heartbeat/.test(String(c[0])))).toBe(true);
  });

  it('passes the worker id to markDone and markFailed', async () => {
    const f = fakeQueue([[row(1)], [row(2)]]);
    const done = vi.fn(); const failed = vi.fn();
    f.queue.markDone = done; f.queue.markFailed = failed;
    let n = 0;
    await runQueueLoop(base(f, { maxBatches: 2, processBatch: async () => (++n === 1 ? { ok: true } : { ok: false, error: 'x' }) }));
    expect(done.mock.calls[0]![3]).toBe('hu-1');
    expect(failed.mock.calls[0]![3]).toBe('hu-1');
  });

  it('keeps reaping while a backlog means every claim succeeds, but not more than once per gate', async () => {
    let t = NOW;
    const mk = (step: number) => {
      const f = fakeQueue([[row(1)], [row(2)], [row(3)]]);
      return { f, opts: base(f, { maxBatches: 3, now: () => t, reapEveryMs: 60_000, processBatch: async () => { t += step; return { ok: true }; } }) };
    };
    const slow = mk(61_000);
    await runQueueLoop(slow.opts);
    expect(slow.f.reaps.filter((r) => r.ownerId === undefined)).toHaveLength(3);
    t = NOW;
    const fast = mk(1_000);
    await runQueueLoop(fast.opts);
    expect(fast.f.reaps.filter((r) => r.ownerId === undefined)).toHaveLength(1);
  });

  it('reaps stale and legacy rows on idle polls with the 15 min and 3 h cutoffs, gated', async () => {
    const f = fakeQueue([]);
    let t = NOW; let ticks = 0;
    await runQueueLoop(base(f, {
      watch: true, pollSec: 0.01, now: () => t, reapEveryMs: 60_000,
      onIdleTick: () => { t += ticks === 0 ? 1_000 : 61_000; if (++ticks >= 3) process.emit('SIGTERM'); },
    }));
    const idle = f.reaps.filter((r) => r.ownerId === undefined);
    expect(idle).toHaveLength(2);
    expect(idle[0]!.staleBeforeIso).toBe(new Date(NOW - 15 * 60_000).toISOString());
    expect(idle[0]!.legacyBeforeIso).toBe(new Date(NOW - 3 * 3600_000).toISOString());
  });
});

describe('runQueueLoop preflight', () => {
  type PF = NonNullable<QueueLoopOpts['preflight']>;
  const seq = (...rs: Awaited<ReturnType<PF>>[]): PF => { const q = [...rs]; return async () => q.shift() ?? { action: 'ok' }; };

  it('claims as before when there is no preflight', async () => {
    const f = fakeQueue([[row(1)]]);
    const r = await runQueueLoop(base(f, { maxBatches: 1 }));
    expect(f.claims).toEqual(['hu-1']);
    expect(r).toEqual({ batches: 1 });
  });

  it('runs the preflight before each claim and claims on ok', async () => {
    const f = fakeQueue([[row(1)], [row(2)]]);
    const pf = vi.fn(async () => { f.calls.push('preflight'); return { action: 'ok' as const }; });
    await runQueueLoop(base(f, { maxBatches: 2, preflight: pf }));
    expect(f.calls.filter((c) => c !== 'reap')).toEqual(['preflight', 'claim', 'preflight', 'claim']);
  });

  it('claims nothing on retry, sleeps with doubling backoff capped at 300 s, and resets on ok', async () => {
    const f = fakeQueue([[row(1)]]);
    const sleeps: number[] = [];
    const retry = { action: 'retry' as const, reason: 'dns down' };
    const pf = seq(...Array(11).fill(retry), { action: 'ok' }, retry, retry);
    let stop = false;
    await runQueueLoop(base(f, {
      pollSec: 10, preflight: pf, maxBatches: 1,
      sleepFn: async (ms) => { sleeps.push(ms); },
      processBatch: async () => { stop = true; return { ok: true }; },
    }));
    expect(stop).toBe(true);
    // 10 s doubling: 10,20,40,80,160,300,300,... then reset after the ok
    expect(sleeps.slice(0, 8)).toEqual([10_000, 20_000, 40_000, 80_000, 160_000, 300_000, 300_000, 300_000]);
    expect(f.claims).toHaveLength(1);
    // claim happened only after the 11 retries
    expect(sleeps).toHaveLength(11);
  });

  it('resets the backoff after an ok', async () => {
    const f = fakeQueue([[row(1)], [row(2)]]);
    const sleeps: number[] = [];
    const retry = { action: 'retry' as const, reason: 'x' };
    await runQueueLoop(base(f, {
      pollSec: 5, maxBatches: 2,
      preflight: seq(retry, retry, { action: 'ok' }, retry, { action: 'ok' }),
      sleepFn: async (ms) => { sleeps.push(ms); },
    }));
    expect(sleeps).toEqual([5000, 10_000, 5000]);
  });

  it('does not claim while the preflight says retry', async () => {
    const f = fakeQueue([[row(1)]]);
    let n = 0;
    await runQueueLoop(base(f, {
      preflight: async () => ({ action: 'retry', reason: 'dns down' }),
      sleepFn: async () => { if (++n >= 3) process.emit('SIGTERM'); },
    }));
    expect(f.claims).toEqual([]);
  });

  it('treats a throwing preflight as retry', async () => {
    const f = fakeQueue([[row(1)]]);
    const warn = vi.fn();
    let n = 0;
    await runQueueLoop(base(f, {
      log: { ...log, warn } as unknown as Logger,
      preflight: async () => { throw new Error('probe exploded'); },
      sleepFn: async () => { if (++n >= 2) process.emit('SIGTERM'); },
    }));
    expect(f.claims).toEqual([]);
    expect(n).toBe(2);
    expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).toContain('probe exploded');
  });

  it('claims nothing and returns a restart signal on restart', async () => {
    const f = fakeQueue([[row(1)]]);
    const error = vi.fn();
    // Ends a loop that wrongly keeps going instead of hanging the test.
    const sleepFn = vi.fn(async () => { process.emit('SIGTERM'); });
    const r = await runQueueLoop(base(f, {
      watch: true, log: { ...log, error } as unknown as Logger, sleepFn,
      preflight: async () => ({ action: 'restart', reason: 'wrong namespace' }),
    }));
    expect(f.claims).toEqual([]);
    expect(sleepFn).not.toHaveBeenCalled();
    expect(r).toEqual({ batches: 0, restart: 'wrong namespace' });
    expect(error.mock.calls.map((c) => String(c[0])).join('\n')).toContain('wrong namespace');
  });

  it('still reaps its own rows at start when the first preflight says restart', async () => {
    const f = fakeQueue([]);
    await runQueueLoop(base(f, { preflight: async () => ({ action: 'restart', reason: 'x' }) }));
    expect(f.reaps[0]).toMatchObject({ ownerId: 'hu-1' });
  });

  it('does not claim when a signal arrives while the preflight runs', async () => {
    const f = fakeQueue([[row(1)]]);
    await runQueueLoop(base(f, {
      watch: true,
      preflight: async () => { process.emit('SIGTERM'); return { action: 'ok' }; },
    }));
    expect(f.claims).toEqual([]);
  });
});

describe('runQueueLoop post-batch check', () => {
  type PB = NonNullable<QueueLoopOpts['postBatchCheck']>;
  const bad: PB = () => ({ action: 'restart', reason: 'netns replaced' });

  it('releases the batch instead of marking it, returns a restart signal and claims no more', async () => {
    const f = fakeQueue([[row(1), row(2)], [row(3)]]);
    const error = vi.fn();
    const onBatchDone = vi.fn();
    const r = await runQueueLoop(base(f, { log: { ...log, error } as unknown as Logger, postBatchCheck: bad, onBatchDone }));
    expect(f.released).toEqual([{ ids: [1, 2], workerId: 'hu-1' }]);
    expect(f.done).toEqual([]);
    expect(f.failed).toEqual([]);
    expect(onBatchDone).not.toHaveBeenCalled();
    expect(f.claims).toHaveLength(1);
    expect(r).toEqual({ batches: 1, restart: 'netns replaced' });
    const msg = error.mock.calls.map((c) => String(c[0])).join('\n');
    expect(msg).toContain('2 row(s)');
    expect(msg).toContain('netns replaced');
  });

  it('releases rather than fails a batch whose processing failed', async () => {
    const f = fakeQueue([[row(1)]]);
    const r = await runQueueLoop(base(f, { postBatchCheck: bad, processBatch: async () => ({ ok: false, error: 'scan-all exit 1' }) }));
    expect(f.released).toHaveLength(1);
    expect(f.failed).toEqual([]);
    expect(r.restart).toBe('netns replaced');
  });

  it('checks after the batch and before marking, and marks as before on ok', async () => {
    const f = fakeQueue([[row(1)], [row(2)]]);
    const markDone = f.queue.markDone;
    f.queue.markDone = (...a) => { f.calls.push('done'); markDone(...a); };
    const pb: PB = () => { f.calls.push('postcheck'); return { action: 'ok' }; };
    const r = await runQueueLoop(base(f, { maxBatches: 2, postBatchCheck: pb }));
    expect(f.calls.filter((c) => c !== 'reap')).toEqual(['claim', 'postcheck', 'done', 'claim', 'postcheck', 'done']);
    expect(f.released).toEqual([]);
    expect(r).toEqual({ batches: 2 });
  });

  it('marks failed as before on ok when the batch failed', async () => {
    const f = fakeQueue([[row(1)]]);
    await runQueueLoop(base(f, { maxBatches: 1, postBatchCheck: () => ({ action: 'ok' }), processBatch: async () => ({ ok: false, error: 'x' }) }));
    expect(f.failed).toEqual([1]);
    expect(f.released).toEqual([]);
  });

  it('is unchanged without a post-batch check', async () => {
    const f = fakeQueue([[row(1)]]);
    const r = await runQueueLoop(base(f, { maxBatches: 1 }));
    expect(f.done).toEqual([1]);
    expect(f.released).toEqual([]);
    expect(r).toEqual({ batches: 1 });
  });

  it('treats a throwing check as a mismatch (fails closed)', async () => {
    const f = fakeQueue([[row(1)], [row(2)]]);
    const r = await runQueueLoop(base(f, { postBatchCheck: () => { throw new Error('boom'); } }));
    expect(f.released).toHaveLength(1);
    expect(f.done).toEqual([]);
    expect(f.claims).toHaveLength(1);
    expect(r.restart).toContain('boom');
  });

  it('still returns the restart signal when the release itself throws', async () => {
    const f = fakeQueue([[row(1)]]);
    f.queue.release = () => { throw new Error('db locked'); };
    const r = await runQueueLoop(base(f, { postBatchCheck: bad }));
    expect(f.done).toEqual([]);
    expect(f.failed).toEqual([]);
    expect(r.restart).toBe('netns replaced');
  });
});
