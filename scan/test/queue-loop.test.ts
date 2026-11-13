import { describe, it, expect, vi } from 'vitest';
import { runQueueLoop, type QueueLoopOpts } from '../src/lib/queue-loop.js';
import type { QueueOps, ClaimedRow } from '../src/lib/queue.js';
import type { Logger } from '../src/lib/log.js';

const noop = (): void => {};
const log = { info: noop, warn: noop, error: noop, step: noop, close: noop } as unknown as Logger;

interface Fake { queue: QueueOps; reaps: Parameters<QueueOps['reapStale']>[0][]; beats: { ids: number[]; atIso: string }[]; claims: string[]; calls: string[] }

function fakeQueue(batches: ClaimedRow[][]): Fake {
  const f: Fake = { queue: null as unknown as QueueOps, reaps: [], beats: [], claims: [], calls: [] };
  const pending = [...batches];
  f.queue = {
    enqueueMany: () => 0,
    requeueMany: () => 0,
    claimBatch: (_s, _a, workerId) => { f.claims.push(workerId ?? ''); f.calls.push('claim'); return pending.shift() ?? []; },
    markDone: noop,
    markFailed: noop,
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
    const t = fakeTimers();
    const out = await runQueueLoop(base(f, {
      maxBatches: 1, setIntervalFn: t.setIntervalFn, clearIntervalFn: t.clearIntervalFn,
      processBatch: async () => { t.tick(); return { ok: true }; },
    }));
    expect(out.batches).toBe(1);
  });

  it('reaps stale and legacy rows on an idle tick with the 15 min and 3 h cutoffs', async () => {
    const f = fakeQueue([]);
    let ticks = 0;
    await runQueueLoop(base(f, {
      watch: true, pollSec: 0.01,
      onIdleTick: () => { if (++ticks >= 1) process.emit('SIGTERM'); },
    }));
    const idleReap = f.reaps[1]!;
    expect(idleReap.ownerId).toBeUndefined();
    expect(idleReap.staleBeforeIso).toBe(new Date(NOW - 15 * 60_000).toISOString());
    expect(idleReap.legacyBeforeIso).toBe(new Date(NOW - 3 * 3600_000).toISOString());
  });
});
