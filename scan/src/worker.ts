#!/usr/bin/env -S node --loader tsx
// Loop: claim next batch from scan_queue → write temp targets file →
// invoke scan-all with it → mark done. Repeats until queue is empty or
// --max-batches reached. Ctrl-C at any time is safe; unfinished claims stay
// as in_progress and can be requeued manually if you want (UPDATE ... SET
// status='pending'). No automatic reaper here — see README.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { openDb } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';
import { createLogger, type Logger } from './lib/log.js';
import { scanChildEnv, TUNED_SCAN_FLAGS } from './lib/scan-all-runner.js';
import { runQueueLoop, type BatchOutcome } from './lib/queue-loop.js';

interface Opts {
  db: string;
  batchSize: number;
  maxBatches: number;
  scope: string | null;
  strict: boolean;
  logFile: string | null;
  watch: boolean;
  pollSec: number;
  claimSuffixes: string[];
  claimNotSuffixes: string[];
  extraArgs: string[];
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    db: resolveDbArg(argv), batchSize: 25, maxBatches: 0, scope: null, strict: false,
    logFile: null, watch: false, pollSec: 10,
    claimSuffixes: [], claimNotSuffixes: [], extraArgs: [],
  };
  let passthrough = false;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (passthrough) { opts.extraArgs.push(a); continue; }
    const next = () => argv[++i]!;
    if (a === '--') passthrough = true;
    else if (isDbFlag(a)) { i++; } // db path resolved by resolveDbArg
    else if (a === '--batch-size') opts.batchSize = parseInt(next(), 10);
    else if (a === '--max-batches') opts.maxBatches = parseInt(next(), 10);
    else if (a === '--scope') opts.scope = next();
    else if (a === '--strict') opts.strict = true;
    else if (a === '--log') opts.logFile = next();
    else if (a === '--watch') opts.watch = true;
    else if (a === '--poll-interval') opts.pollSec = parseInt(next(), 10);
    else if (a === '--claim-suffix') opts.claimSuffixes.push(next());
    else if (a === '--claim-not-suffix') opts.claimNotSuffixes.push(next());
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: worker [options]

Loops the scan_queue: claim → scan → mark. Stops when the queue is empty
(or --max-batches reached). Ctrl-C exits cleanly between batches.

Options:
  --batch-size <N>       hosts per scan-all invocation (default: 25)
  --max-batches <N>      stop after this many batches (default: 0 = unlimited)
  --sqlite <path>        scan.db (default: scan.db) [alias: --db]
  --scope <file>         scope.txt for scan-all
  --strict               refuse out-of-scope targets
  --log <file>           tee timestamped worker logs to <file> (also stderr).
                         Default: logs/worker-<timestamp>.log (always audited).
  --watch                daemon mode: when the queue drains, poll for new work
                         instead of exiting. Runs until SIGINT/SIGTERM.
  --poll-interval <sec>  seconds to sleep between polls in --watch (default: 10)
  --claim-suffix <s>     only claim targets ending in <s> (repeatable).
                         e.g. --claim-suffix .gov.hu --claim-suffix .hu
  --claim-not-suffix <s> never claim targets ending in <s> (repeatable).
                         Used with a matching HU worker to split the fleet.
  --                     everything after is passed to scan-all verbatim
                         (e.g. -- --sqlite scan.db  is already set)

Daemon: run under systemd for auto-restart + boot persistence — see
deploy/scan-worker.service (systemctl --user enable --now scan-worker).

Examples:
  worker --batch-size 50 --scope scope.txt
  worker --batch-size 20 --max-batches 5 --scope scope.txt

Env vars are inherited by scan-all:
  SKIP=wpscan,testssl        skip stages
  SEQUENTIAL=1               run stage 2 sequentially (legacy)
  TESTSSL_FLAGS="--live-only --concurrency 6"
  ...
`);
}

function runScanAll(targetsFile: string, opts: Opts, log: Logger): Promise<number> {
  const scopeArg = opts.scope ? ['--scope', opts.scope] : [];
  const strictArg = opts.strict ? ['--strict'] : [];
  const args = [
    'tsx', 'src/scan-all.ts',
    '--targets', targetsFile,
    ...scopeArg,
    ...strictArg,
    '--sqlite', opts.db,
    ...opts.extraArgs,
  ];
  // Self-sufficient env: Go tools on PATH + tuned live-only defaults, so the
  // worker needs no external `export PATH=... NUCLEI_FLAGS=...` wrapper. Any of
  // these can still be overridden by exporting the var before launching.
  const env = scanChildEnv({ ...TUNED_SCAN_FLAGS });
  log.step(`spawn: npx ${args.join(' ')}`);
  return new Promise((resolve) => {
    const child = spawn('npx', args, { stdio: 'inherit', env });
    child.on('close', (code) => resolve(code ?? -1));
  });
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  // Always write an audit log. Default to logs/worker-<timestamp>.log so every
  // production run is captured even when --log is omitted.
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const logFile = opts.logFile ?? path.join('logs', `worker-${stamp}.log`);
  fs.mkdirSync(path.dirname(logFile), { recursive: true });
  const batchDir = path.dirname(logFile); // batch target files live by the log

  const log = createLogger({ file: logFile });
  // Filter this worker's claim() to a subset of scan_queue by target suffix.
  // Used by the split HU/foreign-egress fleets so HU-geo-blocked targets only
  // get claimed by workers egressing via scanvpn-hu.
  const db = openDb(opts.db,
    (opts.claimSuffixes.length || opts.claimNotSuffixes.length)
      ? { scanQueueFilter: { includeSuffixes: opts.claimSuffixes, excludeSuffixes: opts.claimNotSuffixes } }
      : {},
  );
  const startAll = Date.now();
  const filterDesc = (opts.claimSuffixes.length || opts.claimNotSuffixes.length)
    ? ` claim-filter={include=[${opts.claimSuffixes.join(',')}] exclude=[${opts.claimNotSuffixes.join(',')}]}`
    : '';
  log.info(`scan worker start: db=${path.resolve(opts.db)} batch-size=${opts.batchSize} max-batches=${opts.maxBatches || '∞'} scope=${opts.scope ?? '(none)'} watch=${opts.watch}${filterDesc}`);
  log.info(`logging to ${path.resolve(logFile)}`);

  // WAL maintenance: without a checkpoint the WAL grows unbounded when a
  // long-lived reader (the UI) keeps snapshots pinned, which made every
  // reader disk-bound scanning ~100 MB of WAL frames per query (UI wedged in
  // folio-wait until the WAL was truncated). Time-gated so 4 workers polling
  // every 10s don't thrash the pragma. Errors on BUSY are fine — next tick.
  let lastCheckpoint = 0;
  const checkpointIfDue = (): void => {
    const now = Date.now();
    if (now - lastCheckpoint < 60_000) return;
    lastCheckpoint = now;
    try { db.raw.pragma('wal_checkpoint(TRUNCATE)'); } catch { /* busy: retry next tick */ }
  };

  const { batches } = await runQueueLoop({
    queue: db.scanQueue,
    label: 'scan',
    batchSize: opts.batchSize,
    maxBatches: opts.maxBatches,
    watch: opts.watch,
    pollSec: opts.pollSec,
    log,
    onIdleTick: checkpointIfDue,
    processBatch: async (claimed): Promise<BatchOutcome> => {
      const preRunId = (db.raw.prepare('SELECT COALESCE(MAX(id), 0) m FROM runs').get() as { m: number }).m;
      const targetsFile = path.resolve(batchDir, `scan-batch-${stamp}-${claimed[0]!.id}.txt`);
      fs.writeFileSync(targetsFile, claimed.map((r) => r.target).join('\n') + '\n');
      const code = await runScanAll(targetsFile, opts, log);
      const postRunId = (db.raw.prepare('SELECT COALESCE(MAX(id), 0) m FROM runs').get() as { m: number }).m;
      // null when scan-all created no run row (every stage skipped) — run_id is a
      // nullable FK, so 0 would violate the constraint.
      const runId = postRunId > preRunId ? postRunId : null;
      return code === 0 ? { ok: true, runId } : { ok: false, error: `scan-all exit ${code}` };
    },
    // Hand successfully-scanned targets to the report queue (second stage).
    onBatchDone: (claimed): void => {
      const n = db.reportQueue.enqueueMany(
        claimed.map((c) => ({ target: c.target, priority: c.priority })),
        new Date().toISOString()
      );
      log.info(`scan: handed ${n} target(s) to report_queue`);
    },
  });

  const totalDt = ((Date.now() - startAll) / 1000).toFixed(0);
  const sq = db.scanQueue.stats();
  const rq = db.reportQueue.stats();
  log.info(`scan worker finished: ${batches} batch(es) in ${totalDt}s`);
  log.info(`scan_queue: pending=${sq.pending} in_progress=${sq.in_progress} done=${sq.done} failed=${sq.failed} | report_queue: pending=${rq.pending} done=${rq.done}`);
  db.close();
  log.close();
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
