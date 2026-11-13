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

type Row = { status: string; attempts: number; abandoned: number; error: string | null; started_at: string | null; finished_at: string | null; claimed_by: string | null; heartbeat_at: string | null };

describe.each(['scanQueue', 'reportQueue'] as const)('%s claim ownership and reaping', (which) => {
  const T = (m: number): string => `2026-08-19T12:${String(m).padStart(2, '0')}:00.000Z`;
  const table = which === 'scanQueue' ? 'scan_queue' : 'report_queue';
  const row = (target: string): Row => db.raw.prepare(`SELECT status, attempts, abandoned, error, started_at, finished_at, claimed_by, heartbeat_at FROM ${table} WHERE target=?`).get(target) as Row;
  const reap = (o: { atIso: string; staleBeforeIso: string; legacyBeforeIso: string; ownerId?: string; maxAttempts?: number }) => db[which].reapStale(o);

  it('a claim records the owner and the first heartbeat', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    db[which].claimBatch(1, T(1), 'w1');
    expect(row('a')).toMatchObject({ status: 'in_progress', claimed_by: 'w1', heartbeat_at: T(1) });
  });

  it('heartbeat bumps heartbeat_at for the given ids only', () => {
    db[which].enqueueMany([{ target: 'a', priority: 2 }, { target: 'b', priority: 1 }], T(0));
    const [a, b] = db[which].claimBatch(2, T(1), 'w1');
    db[which].heartbeat([a!.id], T(5), 'w1');
    expect(row(a!.target).heartbeat_at).toBe(T(5));
    expect(row(b!.target).heartbeat_at).toBe(T(1));
  });

  it('a stale heartbeat resets the row to pending and counts an attempt', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    db[which].claimBatch(1, T(1), 'w1');
    const r = reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0) });
    expect(r).toEqual({ requeued: 1, failed: 0 });
    expect(row('a')).toMatchObject({ status: 'pending', attempts: 1, started_at: null, claimed_by: null, heartbeat_at: null });
    expect(db[which].claimBatch(1, T(31), 'w2').map((c) => c.target)).toEqual(['a']);
  });

  it('leaves a fresh heartbeat alone', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    db[which].claimBatch(1, T(1), 'w1');
    db[which].heartbeat([1], T(20), 'w1');
    expect(reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0) })).toEqual({ requeued: 0, failed: 0 });
    expect(row('a')).toMatchObject({ status: 'in_progress', attempts: 0, claimed_by: 'w1' });
  });

  it('reaps a legacy row (no heartbeat) only once it is older than the legacy cutoff', () => {
    db[which].enqueueMany([{ target: 'old', priority: 2 }, { target: 'young', priority: 1 }], T(0));
    db[which].claimBatch(2, T(1), 'w1');
    db.raw.prepare(`UPDATE ${table} SET claimed_by=NULL, heartbeat_at=NULL`).run();
    db.raw.prepare(`UPDATE ${table} SET started_at=? WHERE target='young'`).run(T(25));
    const r = reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(20) });
    expect(r).toEqual({ requeued: 1, failed: 0 });
    expect(row('old').status).toBe('pending');
    expect(row('young').status).toBe('in_progress');
  });

  it('an owner reap hits only that owner, even with a fresh heartbeat', () => {
    db[which].enqueueMany([{ target: 'mine', priority: 2 }, { target: 'theirs', priority: 1 }], T(0));
    db[which].claimBatch(1, T(1), 'w1');
    db[which].claimBatch(1, T(1), 'w2');
    const r = reap({ atIso: T(2), staleBeforeIso: T(0), legacyBeforeIso: T(0), ownerId: 'w1' });
    expect(r).toEqual({ requeued: 1, failed: 0 });
    expect(row('mine').status).toBe('pending');
    expect(row('theirs')).toMatchObject({ status: 'in_progress', claimed_by: 'w2' });
  });

  it('an undefined owner does not match rows without an owner', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    db[which].claimBatch(1, T(1));
    db.raw.prepare(`UPDATE ${table} SET heartbeat_at=?`).run(T(2));
    expect(reap({ atIso: T(3), staleBeforeIso: T(0), legacyBeforeIso: T(0) })).toEqual({ requeued: 0, failed: 0 });
    expect(row('a').status).toBe('in_progress');
  });

  it('the third reset marks the row failed with abandoned N times', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    for (let i = 0; i < 2; i++) {
      db[which].claimBatch(1, T(1), 'w1');
      expect(reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0) })).toEqual({ requeued: 1, failed: 0 });
    }
    db[which].claimBatch(1, T(1), 'w1');
    expect(reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0) })).toEqual({ requeued: 0, failed: 1 });
    expect(row('a')).toMatchObject({ status: 'failed', attempts: 3, abandoned: 3, error: 'abandoned 3 times', finished_at: T(30) });
  });

  it('honours maxAttempts', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    db[which].claimBatch(1, T(1), 'w1');
    expect(reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0), maxAttempts: 1 })).toEqual({ requeued: 0, failed: 1 });
  });

  it('never touches pending, done or failed rows', () => {
    db[which].enqueueMany([{ target: 'd', priority: 3 }, { target: 'f', priority: 2 }, { target: 'p', priority: 1 }], T(0));
    db[which].claimBatch(2, T(1), 'w1');
    db[which].markDone(1, null, T(2), 'w1');
    db[which].markFailed(2, 'x', T(2), 'w1');
    expect(reap({ atIso: T(30), staleBeforeIso: T(29), legacyBeforeIso: T(29), ownerId: 'w1' })).toEqual({ requeued: 0, failed: 0 });
    expect([row('p').status, row('d').status, row('f').status]).toEqual(['pending', 'done', 'failed']);
  });

  it('the cap counts abandonments, not lifetime failed attempts', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    for (let i = 0; i < 2; i++) {
      const [c] = db[which].claimBatch(1, T(1), 'w1');
      db[which].markFailed(c!.id, 'scan error', T(2), 'w1');
      db[which].requeueMany([{ target: 'a', priority: 1 }], T(3));
    }
    db[which].claimBatch(1, T(4), 'w1');
    expect(reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0) })).toEqual({ requeued: 1, failed: 0 });
    expect(row('a')).toMatchObject({ status: 'pending', abandoned: 1 });
  });

  it('requeueMany resets the abandoned count', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    db[which].claimBatch(1, T(1), 'w1');
    reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0) });
    expect(row('a').abandoned).toBe(1);
    db[which].requeueMany([{ target: 'a', priority: 1 }], T(31));
    expect(row('a').abandoned).toBe(0);
  });

  it('a worker that lost its claim cannot finish, fail or heartbeat the new owner row', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    const [a] = db[which].claimBatch(1, T(1), 'A');
    reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0) });
    db[which].claimBatch(1, T(31), 'B');
    expect(db[which].heartbeat([a!.id], T(32), 'A')).toBe(0);
    db[which].markDone(a!.id, null, T(33), 'A');
    db[which].markFailed(a!.id, 'late', T(33), 'A');
    expect(row('a')).toMatchObject({ status: 'in_progress', claimed_by: 'B', heartbeat_at: T(31), error: null });
    db[which].markDone(a!.id, null, T(34), 'B');
    expect(row('a').status).toBe('done');
  });

  it('claims made without an owner can still be finished without one', () => {
    db[which].enqueueMany([{ target: 'a', priority: 2 }, { target: 'b', priority: 1 }], T(0));
    const [a, b] = db[which].claimBatch(2, T(1));
    expect(db[which].heartbeat([a!.id], T(2))).toBe(1);
    db[which].markDone(a!.id, null, T(3));
    db[which].markFailed(b!.id, 'x', T(3));
    expect([row('a').status, row('b').status]).toEqual(['done', 'failed']);
  });

  it('release returns only this owner\'s in_progress rows to pending without counting anything', () => {
    db[which].enqueueMany([{ target: 'a', priority: 3 }, { target: 'b', priority: 2 }, { target: 'c', priority: 1 }], T(0));
    const [a, b, c] = db[which].claimBatch(3, T(1), 'w1');
    db.raw.prepare(`UPDATE ${table} SET attempts=1, abandoned=1 WHERE id=?`).run(a!.id);
    db.raw.prepare(`UPDATE ${table} SET claimed_by='w2' WHERE id=?`).run(b!.id);
    db[which].markDone(c!.id, null, T(2), 'w1');
    expect(db[which].release([a!.id, b!.id, c!.id], 'w1')).toBe(1);
    expect(row('a')).toMatchObject({ status: 'pending', attempts: 1, abandoned: 1, started_at: null, claimed_by: null, heartbeat_at: null });
    expect(row('b')).toMatchObject({ status: 'in_progress', claimed_by: 'w2', heartbeat_at: T(1) });
    expect(row('c').status).toBe('done');
    expect(db[which].claimBatch(5, T(3), 'w3').map((x) => x.target)).toEqual(['a']);
  });

  it('release leaves a row that was reset and re-taken by another worker alone', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    const [a] = db[which].claimBatch(1, T(1), 'A');
    reap({ atIso: T(30), staleBeforeIso: T(15), legacyBeforeIso: T(0) });
    db[which].claimBatch(1, T(31), 'B');
    expect(db[which].release([a!.id], 'A')).toBe(0);
    expect(row('a')).toMatchObject({ status: 'in_progress', claimed_by: 'B' });
  });

  it('requeueMany clears the owner and heartbeat', () => {
    db[which].enqueueMany([{ target: 'a', priority: 1 }], T(0));
    db[which].claimBatch(1, T(1), 'w1');
    db[which].requeueMany([{ target: 'a', priority: 1 }], T(2));
    expect(row('a')).toMatchObject({ status: 'pending', claimed_by: null, heartbeat_at: null });
  });
});

describe('claim-ownership migration', () => {
  it('adds claimed_by and heartbeat_at to queue tables created without them', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const BetterSqlite = (await import('better-sqlite3')).default;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-migrate-'));
    const file = path.join(dir, 'old.db');
    try {
      const old = new BetterSqlite(file);
      for (const t of ['scan_queue', 'report_queue']) {
        old.exec(`CREATE TABLE ${t} (id INTEGER PRIMARY KEY, target TEXT NOT NULL UNIQUE, priority INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'pending', queued_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
          run_id INTEGER, attempts INTEGER NOT NULL DEFAULT 0, error TEXT)`);
        old.prepare(`INSERT INTO ${t}(target, queued_at, status, started_at) VALUES('x', '2026-08-19T12:00:00Z', 'in_progress', '2026-08-19T12:01:00Z')`).run();
      }
      old.close();
      for (let i = 0; i < 2; i++) { // second open proves the migration is idempotent
        const migrated = openDb(file);
        for (const t of ['scan_queue', 'report_queue']) {
          const cols = (migrated.raw.prepare(`PRAGMA table_info(${t})`).all() as { name: string }[]).map((c) => c.name);
          expect(cols).toEqual(expect.arrayContaining(['claimed_by', 'heartbeat_at', 'abandoned']));
        }
        migrated.close();
      }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
