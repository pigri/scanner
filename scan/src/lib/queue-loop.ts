import type { QueueOps, ClaimedRow } from './queue.js';
import type { Logger } from './log.js';
import { isSqliteBusy } from './sqlite-busy.js';
import type { PreflightResult, PostBatchResult } from './egress-check.js';

// Shared drain loop for both the scan worker and the report worker: claim a
// batch → process it → mark each row done/failed → (optionally) hand off. In
// --watch mode it idles and polls instead of exiting when the queue drains, and
// shuts down promptly on SIGINT/SIGTERM (systemd stop).
//
// Abandoned claims: a killed worker leaves its rows in_progress. On start the
// loop returns the rows owned by its own worker id to the queue (a fresh process
// cannot own a live batch). While a batch runs it heartbeats the claimed rows,
// and, at most once per reapEveryMs before a claim, it returns rows whose heartbeat
// went stale, whoever owned them. The pre-claim reap also covers a busy queue,
// where the loop never idles.
//
// Preflight: an optional check that runs before every claim, after the reap (the
// reap only touches the queue, so it is safe and useful even on a bad egress).
// 'retry' claims nothing and backs off; 'restart' claims nothing and returns a
// restart reason so the caller can exit non-zero and let the supervisor start
// a fresh process.
//
// Post-batch check: an optional check that runs after a batch and before its
// rows are marked. When it says 'restart' (or throws), the batch ran in a
// namespace that may be gone, so its result is not trusted: the rows go back to
// pending without counting an attempt, and the loop returns a restart reason.
//
// Locked database: another process (the hourly risk run) can hold the write lock
// longer than busy_timeout. A SQLITE_BUSY from the loop's own calls is contention,
// not a fault. A busy claim backs off and retries. A busy mark retries for about
// MARK_BUDGET_MS, because giving up throws away a finished scan; if that runs out
// the rows stay in_progress for the startup reap and the loop returns a restart
// reason. A busy hand-off or stats call is logged and skipped. Other errors throw.

const HEARTBEAT_MS = 60_000;
const STALE_MS = 15 * 60_000;
const LEGACY_MS = 3 * 3600_000;
const REAP_EVERY_MS = 60_000;
const MAX_BACKOFF_MS = 300_000;
const MARK_FIRST_WAIT_MS = 1_000;
const MARK_MAX_WAIT_MS = 30_000;
const MARK_BUDGET_MS = 300_000;

export interface BatchOutcome {
  ok: boolean;
  runId?: number | null;
  error?: string;
}

export interface QueueLoopOpts {
  queue: QueueOps;
  label: string;              // 'scan' | 'report' — prefixes log lines
  batchSize: number;
  maxBatches: number;         // 0 = unlimited
  watch: boolean;
  pollSec: number;
  log: Logger;
  processBatch: (claimed: ClaimedRow[], batchN: number) => Promise<BatchOutcome>;
  onBatchDone?: (claimed: ClaimedRow[], outcome: BatchOutcome) => void;
  // Called on every idle poll tick — used to piggyback low-priority maintenance
  // (e.g. WAL checkpoint) onto the natural quiet moments in the loop. Must be
  // fast and non-throwing; the loop does not await it.
  onIdleTick?: () => void;
  // Stable identity of this worker; recorded on every claim and used for the
  // startup reap, so it must survive a restart of the same unit.
  workerId: string;
  // Injectable for tests; default to the real clock and timers.
  now?: () => number;
  heartbeatMs?: number;       // default 60 s
  staleMs?: number;           // heartbeat age that counts as abandoned, default 15 min
  reapEveryMs?: number;       // minimum gap between stale reaps, default 60 s
  legacyMs?: number;          // age of a heartbeat-less claim that counts as abandoned, default 3 h
  setIntervalFn?: typeof setInterval;
  clearIntervalFn?: typeof clearInterval;
  // Egress check run before every claim. A throw counts as 'retry'.
  preflight?: () => Promise<PreflightResult>;
  // Egress check run after every batch, before its rows are marked. A throw
  // counts as 'restart'.
  postBatchCheck?: () => PostBatchResult | Promise<PostBatchResult>;
  // Called on SIGINT/SIGTERM while a batch is running. It must make processBatch
  // return soon (forward the signal, kill after a grace period). The loop then
  // releases the batch's rows to pending without counting an attempt and stops.
  stopBatch?: (sig: NodeJS.Signals) => Promise<void>;
  // Replaces the interruptible sleep used for idling and backoff (tests).
  sleepFn?: (ms: number) => Promise<void>;
}

export async function runQueueLoop(o: QueueLoopOpts): Promise<{ batches: number; restart?: string }> {
  const { queue, log, label } = o;
  const now = o.now ?? Date.now;
  const heartbeatMs = o.heartbeatMs ?? HEARTBEAT_MS;
  const staleMs = o.staleMs ?? STALE_MS;
  const legacyMs = o.legacyMs ?? LEGACY_MS;
  const reapEveryMs = o.reapEveryMs ?? REAP_EVERY_MS;
  let lastReap = -Infinity;
  const setIntervalFn = o.setIntervalFn ?? setInterval;
  const clearIntervalFn = o.clearIntervalFn ?? clearInterval;
  let batchN = 0;

  const reap = (what: string, ownerId?: string): void => {
    try {
      const t = now();
      const r = queue.reapStale({
        atIso: new Date(t).toISOString(),
        staleBeforeIso: new Date(t - staleMs).toISOString(),
        legacyBeforeIso: new Date(t - legacyMs).toISOString(),
        ...(ownerId !== undefined ? { ownerId } : {}),
      });
      if (r.requeued || r.failed) log.warn(`${label}: ${what}: returned ${r.requeued} abandoned row(s) to pending, failed ${r.failed} after repeated abandonment`);
    } catch (e) {
      log.warn(`${label}: ${what} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  let interrupted = false;
  let inBatch = false;
  let stopSig: NodeJS.Signals | null = null;
  let stopping: Promise<void> | null = null;
  let wake: (() => void) | null = null;
  const onSig = (sig: NodeJS.Signals): void => {
    interrupted = true;
    if (inBatch && o.stopBatch) {
      if (!stopSig) {
        stopSig = sig;
        log.warn(`${label}: received ${sig} during a batch; stopping it and releasing its rows`);
        stopping = o.stopBatch(sig).catch((e: unknown) => { log.warn(`${label}: stopping the batch failed: ${e instanceof Error ? e.message : String(e)}`); });
      }
      return;
    }
    log.warn(`${label}: received ${sig}; finishing current batch then stopping`);
    if (wake) wake();
  };
  const onInt = (): void => onSig('SIGINT');
  const onTerm = (): void => onSig('SIGTERM');
  process.on('SIGINT', onInt);
  process.on('SIGTERM', onTerm);
  const idleSleep = o.sleepFn ?? ((ms: number): Promise<void> => new Promise((res) => {
    const t = setTimeout(() => { wake = null; res(); }, ms);
    wake = () => { clearTimeout(t); wake = null; res(); };
  }));

  // 'exhausted' once the write has stayed locked past the budget; 'interrupted' if a stop arrived while waiting.
  const markWithRetry = async (run: () => void): Promise<'ok' | 'exhausted' | 'interrupted'> => {
    let wait = MARK_FIRST_WAIT_MS;
    let waited = 0;
    while (true) {
      try { run(); return 'ok'; }
      catch (e) {
        if (!isSqliteBusy(e)) throw e;
        if (waited >= MARK_BUDGET_MS) return 'exhausted';
        log.warn(`${label}: database busy while marking; retrying in ${Math.round(wait / 1000)}s`);
        await idleSleep(wait);
        if (interrupted) return 'interrupted';
        waited += wait;
        wait = Math.min(wait * 2, MARK_MAX_WAIT_MS);
      }
    }
  };
  const logStats = (what: string): void => {
    try {
      const st = queue.stats();
      log.info(`${label}: ${what}: pending=${st.pending} in_progress=${st.in_progress} done=${st.done} failed=${st.failed}`);
    } catch (e) {
      if (!isSqliteBusy(e)) throw e;
      log.warn(`${label}: database busy; skipped the stats log (${what})`);
    }
  };

  reap('startup reap', o.workerId);
  logStats('queue at start');
  if (o.watch) log.info(`${label}: watch mode, polling every ${o.pollSec}s when idle`);
  let idle = false;
  let backoffMs = o.pollSec * 1000;
  let restart: string | undefined;

  while (true) {
    if (interrupted) { log.warn(`${label}: stopping due to signal`); break; }
    if (o.maxBatches && batchN >= o.maxBatches) { log.info(`${label}: reached --max-batches=${o.maxBatches}; stopping`); break; }

    if (now() - lastReap >= reapEveryMs) { lastReap = now(); reap('stale reap'); }
    if (o.preflight) {
      let pf: PreflightResult;
      try { pf = await o.preflight(); }
      catch (e) { pf = { action: 'retry', reason: `preflight threw: ${e instanceof Error ? e.message : String(e)}` }; }
      if (interrupted) { log.warn(`${label}: stopping due to signal`); break; }
      if (pf.action === 'restart') {
        log.error(`${label}: egress check failed, exiting so the supervisor restarts the worker: ${pf.reason}`);
        restart = pf.reason;
        break;
      }
      if (pf.action === 'retry') {
        log.warn(`${label}: egress check failed, not claiming; retrying in ${Math.round(backoffMs / 1000)}s: ${pf.reason}`);
        await idleSleep(backoffMs);
        backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
        continue;
      }
      backoffMs = o.pollSec * 1000;
    }
    let claimed: ClaimedRow[];
    try {
      claimed = queue.claimBatch(o.batchSize, new Date(now()).toISOString(), o.workerId);
    } catch (e) {
      if (!isSqliteBusy(e)) throw e;
      log.warn(`${label}: database busy, not claiming; retrying in ${Math.round(backoffMs / 1000)}s`);
      await idleSleep(backoffMs);
      backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
      continue;
    }
    backoffMs = o.pollSec * 1000;
    if (!claimed.length) {
      if (o.watch) {
        if (!idle) { log.info(`${label}: queue empty; idling (poll every ${o.pollSec}s)`); idle = true; }
        try { o.onIdleTick?.(); } catch { /* maintenance is best-effort */ }
        await idleSleep(o.pollSec * 1000);
        continue;
      }
      log.info(`${label}: queue empty; nothing to claim`);
      break;
    }
    if (idle) { log.info(`${label}: new work appeared; resuming`); idle = false; }
    batchN++;

    log.step(`${label}: batch ${batchN}: claimed ${claimed.length} row(s) → in_progress (priority ${claimed[0]!.priority}..${claimed[claimed.length - 1]!.priority})`);
    for (const c of claimed) log.info(`  claim #${c.id} ${c.target} (priority ${c.priority})`);

    const start = Date.now();
    let outcome: BatchOutcome;
    const ids = claimed.map((c) => c.id);
    const beat = setIntervalFn(() => {
      try {
        const n = queue.heartbeat(ids, new Date(now()).toISOString(), o.workerId);
        if (n < ids.length) log.warn(`${label}: heartbeat updated ${n} of ${ids.length} row(s); the rest were reset and are no longer owned by ${o.workerId}`);
      }
      catch (e) { log.warn(`${label}: heartbeat failed: ${e instanceof Error ? e.message : String(e)}`); }
    }, heartbeatMs);
    inBatch = true;
    try {
      outcome = await o.processBatch(claimed, batchN);
    } catch (e) {
      outcome = { ok: false, error: e instanceof Error ? e.message : String(e) };
    } finally {
      clearIntervalFn(beat);
    }
    if (stopSig) {
      await stopping;
      let released = 0;
      try { released = queue.release(ids, o.workerId); }
      catch (e) { log.error(`${label}: release failed: ${e instanceof Error ? e.message : String(e)}`); }
      log.warn(`${label}: batch ${batchN}: stopped by ${stopSig}; released ${released} of ${ids.length} row(s) to pending without counting an attempt`);
      inBatch = false;
      break;
    }
    inBatch = false;
    if (o.postBatchCheck) {
      let pb: PostBatchResult;
      try { pb = await o.postBatchCheck(); }
      catch (e) { pb = { action: 'restart', reason: `post-batch check threw: ${e instanceof Error ? e.message : String(e)}` }; }
      if (pb.action === 'restart') {
        let released = 0;
        try { released = queue.release(ids, o.workerId); }
        catch (e) { log.error(`${label}: release failed: ${e instanceof Error ? e.message : String(e)}`); }
        log.error(`${label}: batch ${batchN}: egress check failed after the batch; released ${released} of ${ids.length} row(s) to pending without counting an attempt, exiting so the supervisor restarts the worker: ${pb.reason}`);
        restart = pb.reason;
        break;
      }
    }
    const dt = ((Date.now() - start) / 1000).toFixed(1);
    const doneIso = new Date().toISOString();

    let marked: 'ok' | 'exhausted' | 'interrupted' = 'ok';
    let nMarked = 0;
    if (outcome.ok) {
      for (const c of claimed) {
        marked = await markWithRetry(() => queue.markDone(c.id, outcome.runId ?? null, doneIso, o.workerId));
        if (marked !== 'ok') break;
        nMarked++;
        log.info(`  done  #${c.id} ${c.target} → run_id=${outcome.runId ?? '(none)'}`);
      }
      if (marked === 'ok') {
        log.step(`${label}: batch ${batchN} DONE in ${dt}s → ${claimed.length} row(s) marked done`);
        try { o.onBatchDone?.(claimed, outcome); }
        catch (e) {
          if (!isSqliteBusy(e)) throw e;
          log.warn(`${label}: database busy; skipped the hand-off for batch ${batchN}`);
        }
      }
    } else {
      for (const c of claimed) {
        marked = await markWithRetry(() => queue.markFailed(c.id, outcome.error ?? 'unknown', doneIso, o.workerId));
        if (marked !== 'ok') break;
        nMarked++;
        log.error(`  fail  #${c.id} ${c.target} → ${outcome.error ?? 'unknown'}`);
      }
      if (marked === 'ok') log.error(`${label}: batch ${batchN} FAILED in ${dt}s → ${claimed.length} row(s) marked failed`);
    }
    if (marked === 'exhausted') {
      restart = 'database is locked; could not record the batch result';
      log.error(`${label}: batch ${batchN}: database stayed locked while marking; ${claimed.length - nMarked} of ${claimed.length} row(s) left in_progress for the startup reap, exiting so the supervisor restarts the worker`);
      break;
    }
    if (marked === 'interrupted') {
      log.warn(`${label}: batch ${batchN}: stop requested while the database was locked; ${claimed.length - nMarked} of ${claimed.length} row(s) left in_progress for the startup reap`);
      break;
    }
    logStats(`queue after batch ${batchN}`);
  }

  process.off('SIGINT', onInt);
  process.off('SIGTERM', onTerm);
  return restart === undefined ? { batches: batchN } : { batches: batchN, restart };
}
