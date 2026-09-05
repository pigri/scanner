import type Database from 'better-sqlite3';

// Generic SQLite-backed work queue. Two instances are used: scan_queue (targets
// to scan) and report_queue (scanned targets awaiting a report). Both tables
// share the same shape, so one factory serves both.
//
// Multi-worker safety: claimBatch runs in an IMMEDIATE transaction so it takes
// the write lock BEFORE selecting pending rows. Without that, two scanner
// processes could SELECT the same pending rows and both mark them in_progress
// (double-claim). With WAL + busy_timeout (set in openDb), concurrent writers
// serialize instead of erroring.

export interface QueueEntry { target: string; priority: number }
export interface ClaimedRow { id: number; target: string; priority: number }
export interface QueueStats { pending: number; in_progress: number; done: number; failed: number }

export interface QueueOps {
  enqueueMany(entries: readonly QueueEntry[], atIso: string): number;
  // Like enqueueMany, but resets already-present targets back to pending
  // (clears started/finished/run_id/error). Used by the weekly full re-scan to
  // re-queue hosts that were already marked done.
  requeueMany(entries: readonly QueueEntry[], atIso: string): number;
  claimBatch(size: number, atIso: string): ClaimedRow[];
  markDone(id: number, runId: number | null, atIso: string): void;
  markFailed(id: number, error: string, atIso: string): void;
  stats(): QueueStats;
}

export function makeQueue(raw: Database.Database, table: string): QueueOps {
  // table is an internal constant, never user input — but validate anyway since
  // it is interpolated into SQL.
  if (!/^[a-z_][a-z0-9_]*$/.test(table)) throw new Error(`invalid queue table name: ${table}`);

  const enqueueStmt = raw.prepare(`INSERT OR IGNORE INTO ${table}(target, priority, queued_at) VALUES(?, ?, ?)`);
  const requeueStmt = raw.prepare(`
    INSERT INTO ${table}(target, priority, queued_at) VALUES(?, ?, ?)
    ON CONFLICT(target) DO UPDATE SET
      priority=excluded.priority, status='pending', queued_at=excluded.queued_at,
      started_at=NULL, finished_at=NULL, run_id=NULL, error=NULL
  `);
  const claimSelectStmt = raw.prepare(`SELECT id, target, priority FROM ${table} WHERE status='pending' ORDER BY priority DESC, id LIMIT ?`);
  const claimUpdateStmt = raw.prepare(`UPDATE ${table} SET status='in_progress', started_at=? WHERE id=?`);
  const markDoneStmt = raw.prepare(`UPDATE ${table} SET status='done', finished_at=?, run_id=? WHERE id=?`);
  const markFailedStmt = raw.prepare(`UPDATE ${table} SET status='failed', finished_at=?, error=?, attempts=attempts+1 WHERE id=?`);
  const statsStmt = raw.prepare(`SELECT status, COUNT(*) n FROM ${table} GROUP BY status`);

  const enqueueTx = raw.transaction((rows: readonly QueueEntry[], atIso: string): number => {
    let n = 0;
    for (const e of rows) if (enqueueStmt.run(e.target, e.priority, atIso).changes > 0) n++;
    return n;
  });

  const requeueTx = raw.transaction((rows: readonly QueueEntry[], atIso: string): number => {
    let n = 0;
    for (const e of rows) if (requeueStmt.run(e.target, e.priority, atIso).changes > 0) n++;
    return n;
  });

  // .immediate acquires the write lock up front → no double-claim across workers.
  const claimTx = raw.transaction((size: number, atIso: string): ClaimedRow[] => {
    const rows = claimSelectStmt.all(size) as ClaimedRow[];
    for (const r of rows) claimUpdateStmt.run(atIso, r.id);
    return rows;
  }).immediate;

  return {
    enqueueMany: (entries, atIso) => enqueueTx(entries, atIso),
    requeueMany: (entries, atIso) => requeueTx(entries, atIso),
    claimBatch: (size, atIso) => claimTx(size, atIso),
    markDone: (id, runId, atIso) => {
      // run_id is a nullable FK to runs(id); never store 0 (no such run row).
      markDoneStmt.run(atIso, runId && runId > 0 ? runId : null, id);
    },
    markFailed: (id, error, atIso) => { markFailedStmt.run(atIso, error, id); },
    stats: (): QueueStats => {
      const acc: QueueStats = { pending: 0, in_progress: 0, done: 0, failed: 0 };
      for (const r of statsStmt.all() as { status: string; n: number }[]) {
        if (r.status === 'pending' || r.status === 'in_progress' || r.status === 'done' || r.status === 'failed') acc[r.status] = r.n;
      }
      return acc;
    },
  };
}
