import type { QueueOps, ClaimedRow } from './queue.js';
import type { Logger } from './log.js';

// Shared drain loop for both the scan worker and the report worker: claim a
// batch → process it → mark each row done/failed → (optionally) hand off. In
// --watch mode it idles and polls instead of exiting when the queue drains, and
// shuts down promptly on SIGINT/SIGTERM (systemd stop).

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
}

export async function runQueueLoop(o: QueueLoopOpts): Promise<{ batches: number }> {
  const { queue, log, label } = o;
  let batchN = 0;

  let interrupted = false;
  let wake: (() => void) | null = null;
  const onSig = (sig: string): void => {
    interrupted = true;
    log.warn(`${label}: received ${sig}; finishing current batch then stopping`);
    if (wake) wake();
  };
  process.on('SIGINT', () => onSig('SIGINT'));
  process.on('SIGTERM', () => onSig('SIGTERM'));
  const idleSleep = (ms: number): Promise<void> => new Promise((res) => {
    const t = setTimeout(() => { wake = null; res(); }, ms);
    wake = () => { clearTimeout(t); wake = null; res(); };
  });

  const s0 = queue.stats();
  log.info(`${label}: queue at start: pending=${s0.pending} in_progress=${s0.in_progress} done=${s0.done} failed=${s0.failed}`);
  if (o.watch) log.info(`${label}: watch mode, polling every ${o.pollSec}s when idle`);
  let idle = false;

  while (true) {
    if (interrupted) { log.warn(`${label}: stopping due to signal`); break; }
    if (o.maxBatches && batchN >= o.maxBatches) { log.info(`${label}: reached --max-batches=${o.maxBatches}; stopping`); break; }

    const claimed = queue.claimBatch(o.batchSize, new Date().toISOString());
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
    try {
      outcome = await o.processBatch(claimed, batchN);
    } catch (e) {
      outcome = { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
    const dt = ((Date.now() - start) / 1000).toFixed(1);
    const doneIso = new Date().toISOString();

    if (outcome.ok) {
      for (const c of claimed) { queue.markDone(c.id, outcome.runId ?? null, doneIso); log.info(`  done  #${c.id} ${c.target} → run_id=${outcome.runId ?? '(none)'}`); }
      log.step(`${label}: batch ${batchN} DONE in ${dt}s → ${claimed.length} row(s) marked done`);
      o.onBatchDone?.(claimed, outcome);
    } else {
      for (const c of claimed) { queue.markFailed(c.id, outcome.error ?? 'unknown', doneIso); log.error(`  fail  #${c.id} ${c.target} → ${outcome.error ?? 'unknown'}`); }
      log.error(`${label}: batch ${batchN} FAILED in ${dt}s → ${claimed.length} row(s) marked failed`);
    }
    const s = queue.stats();
    log.info(`${label}: queue after batch ${batchN}: pending=${s.pending} in_progress=${s.in_progress} done=${s.done} failed=${s.failed}`);
  }

  return { batches: batchN };
}
