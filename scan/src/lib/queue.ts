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
  // workerId is recorded as the owner of the claim; heartbeat_at starts at atIso.
  claimBatch(size: number, atIso: string, workerId?: string): ClaimedRow[];
  // Bump heartbeat_at for rows this worker still owns; returns how many rows
  // were updated (fewer than ids.length means a claim was lost).
  heartbeat(ids: readonly number[], atIso: string, workerId?: string): number;
  // Return abandoned in_progress rows to pending, counting an attempt; rows that
  // reach maxAttempts abandonments (the `abandoned` counter, reset by
  // requeueMany) become failed instead. See ReapOpts for what counts as
  // abandoned.
  reapStale(o: ReapOpts): ReapResult;
  // workerId must match the row's owner (omit it for rows claimed without one);
  // a worker whose claim was reset and re-taken cannot overwrite the new owner.
  markDone(id: number, runId: number | null, atIso: string, workerId?: string): void;
  markFailed(id: number, error: string, atIso: string, workerId?: string): void;
  stats(): QueueStats;
}

export interface ReapOpts {
  atIso: string;
  // in_progress rows with heartbeat_at before this are abandoned.
  staleBeforeIso: string;
  // Rows claimed by code that predates heartbeats (heartbeat_at NULL) are
  // abandoned once started_at is before this.
  legacyBeforeIso: string;
  // Also reap every row this worker owns, however fresh its heartbeat: a worker
  // that has just started cannot own a live batch.
  ownerId?: string;
  maxAttempts?: number;       // default 3
}
export interface ReapResult { requeued: number; failed: number }

// Suffix-based filter for claimBatch. Used to split the worker fleet by
// geographical egress: HU workers claim only .gov.hu / .hu targets (matched by
// includeSuffixes); the foreign-egress fleet claims everything else via
// excludeSuffixes. Empty arrays disable the corresponding filter.
export interface QueueFilter {
  includeSuffixes?: readonly string[];
  excludeSuffixes?: readonly string[];
}

export function makeQueue(raw: Database.Database, table: string, filter: QueueFilter = {}): QueueOps {
  // table is an internal constant, never user input — but validate anyway since
  // it is interpolated into SQL.
  if (!/^[a-z_][a-z0-9_]*$/.test(table)) throw new Error(`invalid queue table name: ${table}`);

  const enqueueStmt = raw.prepare(`INSERT OR IGNORE INTO ${table}(target, priority, queued_at) VALUES(?, ?, ?)`);
  const requeueStmt = raw.prepare(`
    INSERT INTO ${table}(target, priority, queued_at) VALUES(?, ?, ?)
    ON CONFLICT(target) DO UPDATE SET
      priority=excluded.priority, status='pending', queued_at=excluded.queued_at,
      started_at=NULL, finished_at=NULL, run_id=NULL, error=NULL,
      claimed_by=NULL, heartbeat_at=NULL, abandoned=0
  `);
  // Build the claim SELECT with optional suffix filters baked in. Suffixes are
  // normalized to LIKE patterns: '.gov.hu' → target LIKE '%.gov.hu' OR target='gov.hu'.
  // The apex-match branch (target=X) covers the bare-domain enqueue case.
  const inc = (filter.includeSuffixes ?? []).map((s) => s.replace(/^\.+/, '').toLowerCase());
  const exc = (filter.excludeSuffixes ?? []).map((s) => s.replace(/^\.+/, '').toLowerCase());
  const claimWhere: string[] = [`status='pending'`];
  const claimParams: string[] = [];
  if (inc.length) {
    const ors: string[] = [];
    for (const s of inc) { ors.push(`target LIKE ? OR target = ?`); claimParams.push(`%.${s}`, s); }
    claimWhere.push(`(${ors.join(' OR ')})`);
  }
  if (exc.length) {
    for (const s of exc) { claimWhere.push(`target NOT LIKE ? AND target <> ?`); claimParams.push(`%.${s}`, s); }
  }
  const claimSql = `SELECT id, target, priority FROM ${table} WHERE ${claimWhere.join(' AND ')} ORDER BY priority DESC, id LIMIT ?`;
  const claimSelectStmt = raw.prepare(claimSql);
  const claimUpdateStmt = raw.prepare(`UPDATE ${table} SET status='in_progress', started_at=?, heartbeat_at=?, claimed_by=? WHERE id=?`);
  const markDoneStmt = raw.prepare(`UPDATE ${table} SET status='done', finished_at=?, run_id=? WHERE id=? AND status='in_progress' AND claimed_by IS ?`);
  const markFailedStmt = raw.prepare(`UPDATE ${table} SET status='failed', finished_at=?, error=?, attempts=attempts+1 WHERE id=? AND status='in_progress' AND claimed_by IS ?`);
  const heartbeatStmt = raw.prepare(`UPDATE ${table} SET heartbeat_at=? WHERE id=? AND status='in_progress' AND claimed_by IS ?`);
  // claimed_by = NULL when ownerId is undefined: NULL = NULL is never true, so an
  // ownerless call matches no row on that branch.
  const reapSelectStmt = raw.prepare(`
    SELECT id, attempts, abandoned FROM ${table}
    WHERE status='in_progress' AND (
      heartbeat_at < @stale
      OR (heartbeat_at IS NULL AND started_at < @legacy)
      OR claimed_by = @owner
    )`);
  const reapRequeueStmt = raw.prepare(`UPDATE ${table} SET status='pending', attempts=?, abandoned=?, started_at=NULL, claimed_by=NULL, heartbeat_at=NULL WHERE id=?`);
  const reapFailStmt = raw.prepare(`UPDATE ${table} SET status='failed', attempts=?, abandoned=?, error=?, finished_at=?, claimed_by=NULL, heartbeat_at=NULL WHERE id=?`);
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
  const claimTx = raw.transaction((size: number, atIso: string, workerId: string | null): ClaimedRow[] => {
    const rows = claimSelectStmt.all(...claimParams, size) as ClaimedRow[];
    for (const r of rows) claimUpdateStmt.run(atIso, atIso, workerId, r.id);
    return rows;
  }).immediate;

  const heartbeatTx = raw.transaction((ids: readonly number[], atIso: string, workerId: string | null): number => {
    let n = 0;
    for (const id of ids) n += heartbeatStmt.run(atIso, id, workerId).changes;
    return n;
  }).immediate;

  // IMMEDIATE for the same reason as claimTx: a deferred read-then-write upgrade
  // can fail with SQLITE_BUSY under concurrent workers.
  const reapTx = raw.transaction((o: ReapOpts): ReapResult => {
    const max = o.maxAttempts ?? 3;
    const rows = reapSelectStmt.all({ stale: o.staleBeforeIso, legacy: o.legacyBeforeIso, owner: o.ownerId ?? null }) as { id: number; attempts: number; abandoned: number }[];
    const res: ReapResult = { requeued: 0, failed: 0 };
    for (const r of rows) {
      const attempts = r.attempts + 1;
      const abandoned = r.abandoned + 1;
      if (abandoned >= max) { reapFailStmt.run(attempts, abandoned, `abandoned ${abandoned} times`, o.atIso, r.id); res.failed++; }
      else { reapRequeueStmt.run(attempts, abandoned, r.id); res.requeued++; }
    }
    return res;
  }).immediate;

  return {
    enqueueMany: (entries, atIso) => enqueueTx(entries, atIso),
    requeueMany: (entries, atIso) => requeueTx(entries, atIso),
    claimBatch: (size, atIso, workerId) => claimTx(size, atIso, workerId ?? null),
    heartbeat: (ids, atIso, workerId) => heartbeatTx(ids, atIso, workerId ?? null),
    reapStale: (o) => reapTx(o),
    markDone: (id, runId, atIso, workerId) => {
      // run_id is a nullable FK to runs(id); never store 0 (no such run row).
      markDoneStmt.run(atIso, runId && runId > 0 ? runId : null, id, workerId ?? null);
    },
    markFailed: (id, error, atIso, workerId) => { markFailedStmt.run(atIso, error, id, workerId ?? null); },
    stats: (): QueueStats => {
      const acc: QueueStats = { pending: 0, in_progress: 0, done: 0, failed: 0 };
      for (const r of statsStmt.all() as { status: string; n: number }[]) {
        if (r.status === 'pending' || r.status === 'in_progress' || r.status === 'done' || r.status === 'failed') acc[r.status] = r.n;
      }
      return acc;
    },
  };
}
