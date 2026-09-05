import { describe, it, expect, beforeEach } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';

let db: Db;
beforeEach(() => { db = openDb(':memory:'); });

describe('scan_queue schema', () => {
  it('creates the table', () => {
    const row = db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_queue'").get() as { name?: string } | undefined;
    expect(row?.name).toBe('scan_queue');
  });
});

describe('enqueueMany', () => {
  it('inserts new rows, skips duplicates', () => {
    const n1 = db.enqueueMany([{ target: 'a', priority: 10 }, { target: 'b', priority: 5 }], '2026-08-19T12:00:00Z');
    expect(n1).toBe(2);
    const n2 = db.enqueueMany([{ target: 'a', priority: 20 }, { target: 'c', priority: 15 }], '2026-08-19T12:01:00Z');
    expect(n2).toBe(1); // only c inserted; a already present
    const total = (db.raw.prepare('SELECT COUNT(*) c FROM scan_queue').get() as { c: number }).c;
    expect(total).toBe(3);
  });
});

describe('claimBatch', () => {
  beforeEach(() => {
    db.enqueueMany([
      { target: 'high', priority: 100 },
      { target: 'mid1', priority: 50 },
      { target: 'mid2', priority: 50 },
      { target: 'low', priority: 10 },
    ], '2026-08-19T12:00:00Z');
  });

  it('returns highest-priority pending rows, marks in_progress', () => {
    const batch = db.claimBatch(2, '2026-08-19T12:05:00Z');
    expect(batch.map((r) => r.target)).toEqual(['high', 'mid1']);
    const inProg = db.raw.prepare("SELECT COUNT(*) c FROM scan_queue WHERE status='in_progress'").get() as { c: number };
    expect(inProg.c).toBe(2);
  });

  it('subsequent claims skip already-in-progress rows', () => {
    db.claimBatch(2, '2026-08-19T12:05:00Z');
    const next = db.claimBatch(2, '2026-08-19T12:06:00Z');
    expect(next.map((r) => r.target)).toEqual(['mid2', 'low']);
  });

  it('empty when no pending remain', () => {
    db.claimBatch(10, '2026-08-19T12:05:00Z');
    const next = db.claimBatch(10, '2026-08-19T12:06:00Z');
    expect(next).toEqual([]);
  });
});

describe('markDone / markFailed', () => {
  it('sets finished_at + status=done and stores run_id', () => {
    const runId = db.startRun('scan-all', {}, '2026-08-19T12:00:00Z');
    db.enqueueMany([{ target: 'x', priority: 1 }], '2026-08-19T12:00:00Z');
    const [row] = db.claimBatch(1, '2026-08-19T12:01:00Z');
    db.markDone(row!.id, runId, '2026-08-19T12:10:00Z');
    const r = db.raw.prepare('SELECT status, finished_at, run_id FROM scan_queue WHERE id=?').get(row!.id) as { status: string; finished_at: string; run_id: number };
    expect(r.status).toBe('done');
    expect(r.finished_at).toBe('2026-08-19T12:10:00Z');
    expect(r.run_id).toBe(runId);
  });

  it('stores NULL run_id (not 0) when no run was created — avoids FK violation', () => {
    // Regression: worker computes runId=0/null when scan-all creates no runs row
    // (e.g. every stage skipped). run_id is a nullable FK to runs(id); storing 0
    // used to throw "FOREIGN KEY constraint failed".
    db.enqueueMany([{ target: 'x', priority: 1 }, { target: 'y', priority: 1 }], '2026-08-19T12:00:00Z');
    const [rowX] = db.claimBatch(1, '2026-08-19T12:01:00Z');
    expect(() => db.markDone(rowX!.id, 0, '2026-08-19T12:10:00Z')).not.toThrow();
    const [rowY] = db.claimBatch(1, '2026-08-19T12:02:00Z');
    expect(() => db.markDone(rowY!.id, null, '2026-08-19T12:11:00Z')).not.toThrow();
    const rows = db.raw.prepare("SELECT status, run_id FROM scan_queue WHERE target IN ('x','y')").all() as { status: string; run_id: number | null }[];
    expect(rows.every((r) => r.status === 'done')).toBe(true);
    expect(rows.every((r) => r.run_id === null)).toBe(true);
  });

  it('failed increments attempts and stores error', () => {
    db.enqueueMany([{ target: 'x', priority: 1 }], '2026-08-19T12:00:00Z');
    const [row] = db.claimBatch(1, '2026-08-19T12:01:00Z');
    db.markFailed(row!.id, 'timeout', '2026-08-19T12:10:00Z');
    const r = db.raw.prepare('SELECT status, attempts, error FROM scan_queue WHERE id=?').get(row!.id) as { status: string; attempts: number; error: string };
    expect(r.status).toBe('failed');
    expect(r.attempts).toBe(1);
    expect(r.error).toBe('timeout');
  });
});

describe('requeueMany (weekly re-scan)', () => {
  it('resets a done target back to pending and clears run_id/finished_at', () => {
    const runId = db.startRun('scan-all', {}, '2026-08-19T12:00:00Z');
    db.enqueueMany([{ target: 'h', priority: 3 }], '2026-08-19T12:00:00Z');
    const [row] = db.claimBatch(1, '2026-08-19T12:01:00Z');
    db.markDone(row!.id, runId, '2026-08-19T12:02:00Z');
    expect(db.queueStats().done).toBe(1);

    const n = db.scanQueue.requeueMany([{ target: 'h', priority: 9 }], '2026-08-20T12:00:00Z');
    expect(n).toBe(1);
    const r = db.raw.prepare('SELECT status, priority, run_id, finished_at FROM scan_queue WHERE target=?').get('h') as { status: string; priority: number; run_id: number | null; finished_at: string | null };
    expect(r.status).toBe('pending');
    expect(r.priority).toBe(9);          // priority refreshed
    expect(r.run_id).toBeNull();
    expect(r.finished_at).toBeNull();
    // and it's claimable again
    expect(db.claimBatch(1, '2026-08-20T12:01:00Z').map((c) => c.target)).toEqual(['h']);
  });

  it('inserts brand-new targets too', () => {
    const n = db.scanQueue.requeueMany([{ target: 'fresh', priority: 1 }], '2026-08-19T12:00:00Z');
    expect(n).toBe(1);
    expect(db.queueStats().pending).toBe(1);
  });
});

describe('report_queue (second queue, same factory)', () => {
  it('scanQueue and reportQueue are independent tables', () => {
    db.scanQueue.enqueueMany([{ target: 's1', priority: 5 }], '2026-08-19T12:00:00Z');
    db.reportQueue.enqueueMany([{ target: 'r1', priority: 9 }], '2026-08-19T12:00:00Z');
    expect(db.scanQueue.stats().pending).toBe(1);
    expect(db.reportQueue.stats().pending).toBe(1);
    // claiming from one must not touch the other
    const claimed = db.reportQueue.claimBatch(10, '2026-08-19T12:01:00Z');
    expect(claimed.map((c) => c.target)).toEqual(['r1']);
    expect(db.scanQueue.stats().pending).toBe(1);
    expect(db.scanQueue.stats().in_progress).toBe(0);
  });

  it('the scan→report handoff: enqueue done scan targets into report_queue', () => {
    db.scanQueue.enqueueMany([{ target: 'h.gov.hu', priority: 7 }], '2026-08-19T12:00:00Z');
    const [row] = db.scanQueue.claimBatch(1, '2026-08-19T12:01:00Z');
    db.scanQueue.markDone(row!.id, null, '2026-08-19T12:02:00Z');
    // handoff
    db.reportQueue.enqueueMany([{ target: row!.target, priority: row!.priority }], '2026-08-19T12:02:00Z');
    const [rep] = db.reportQueue.claimBatch(1, '2026-08-19T12:03:00Z');
    expect(rep!.target).toBe('h.gov.hu');
    expect(rep!.priority).toBe(7);
  });

  it('report_queue dedupes by target (UNIQUE)', () => {
    const a = db.reportQueue.enqueueMany([{ target: 'dup', priority: 1 }], '2026-08-19T12:00:00Z');
    const b = db.reportQueue.enqueueMany([{ target: 'dup', priority: 2 }], '2026-08-19T12:01:00Z');
    expect(a).toBe(1);
    expect(b).toBe(0);
  });
});

describe('queueStats', () => {
  it('counts by status', () => {
    db.enqueueMany([
      { target: 'a', priority: 1 },
      { target: 'b', priority: 1 },
      { target: 'c', priority: 1 },
    ], '2026-08-19T12:00:00Z');
    const runId = db.startRun('scan-all', {}, '2026-08-19T12:00:00Z');
    const [c1] = db.claimBatch(1, '2026-08-19T12:01:00Z');
    db.markDone(c1!.id, runId, '2026-08-19T12:02:00Z');
    const stats = db.queueStats();
    expect(stats.done).toBe(1);
    expect(stats.pending).toBe(2);
    expect(stats.in_progress).toBe(0);
    expect(stats.failed).toBe(0);
  });
});
