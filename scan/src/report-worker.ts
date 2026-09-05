#!/usr/bin/env -S node --loader tsx
// Drains report_queue: for each scanned target, gather its rows from the DB and
// write a per-target markdown report to --out-dir. Runs as a daemon with
// --watch (systemd: deploy/scan-report-worker.service).
import fs from 'node:fs';
import path from 'node:path';
import { openDb } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';
import { createLogger } from './lib/log.js';
import { runQueueLoop, type BatchOutcome } from './lib/queue-loop.js';
import { renderTargetReport, reportFilename, type TargetReportData, type ReportFinding, type ReportPort, type ReportHttp } from './lib/report.js';

interface Opts {
  db: string;
  batchSize: number;
  maxBatches: number;
  watch: boolean;
  pollSec: number;
  logFile: string | null;
  outDir: string;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    db: resolveDbArg(argv), batchSize: 25, maxBatches: 0, watch: false, pollSec: 10,
    logFile: null, outDir: 'reports',
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (isDbFlag(a)) { i++; }
    else if (a === '--batch-size') opts.batchSize = parseInt(next(), 10);
    else if (a === '--max-batches') opts.maxBatches = parseInt(next(), 10);
    else if (a === '--watch') opts.watch = true;
    else if (a === '--poll-interval') opts.pollSec = parseInt(next(), 10);
    else if (a === '--log') opts.logFile = next();
    else if (a === '--out-dir') opts.outDir = next();
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: report-worker [options]

Drains report_queue and writes a markdown report per target to --out-dir.

Options:
  --sqlite <path>        scan.db (default: scan.db) [alias: --db]
  --out-dir <dir>        report output directory (default: reports)
  --batch-size <N>       targets per claim (default: 25)
  --max-batches <N>      stop after N batches (default: 0 = unlimited)
  --watch                daemon mode: poll for new work instead of exiting
  --poll-interval <sec>  poll interval in --watch (default: 10)
  --log <file>           tee logs to <file> (default: logs/report-worker-<ts>.log)`);
}

function gatherTargetData(db: ReturnType<typeof openDb>, target: string, nowIso: string): TargetReportData {
  const ports = db.raw.prepare('SELECT port, protocol, service, product, version FROM ports WHERE target = ? ORDER BY port').all(target) as ReportPort[];
  const http = (db.raw.prepare('SELECT url, status_code, web_server, tech_json FROM http_probes WHERE target = ?').all(target) as { url: string; status_code: number | null; web_server: string | null; tech_json: string | null }[])
    .map((r): ReportHttp => ({ url: r.url, status_code: r.status_code, web_server: r.web_server, tech: r.tech_json ? JSON.parse(r.tech_json) as string[] : null }));
  const findings = db.raw.prepare('SELECT severity, tool, title, cve FROM findings WHERE target = ?').all(target) as ReportFinding[];
  const risk = db.raw.prepare('SELECT score FROM risk_scores WHERE target = ? ORDER BY computed_at DESC LIMIT 1').get(target) as { score: number } | undefined;
  return { target, generatedAt: nowIso, riskScore: risk?.score ?? null, ports, http, findings };
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const logFile = opts.logFile ?? path.join('logs', `report-worker-${stamp}.log`);
  fs.mkdirSync(path.dirname(logFile), { recursive: true });
  fs.mkdirSync(opts.outDir, { recursive: true });

  const log = createLogger({ file: logFile });
  const db = openDb(opts.db);
  const startAll = Date.now();
  log.info(`report worker start: db=${path.resolve(opts.db)} out-dir=${path.resolve(opts.outDir)} batch-size=${opts.batchSize} watch=${opts.watch}`);
  log.info(`logging to ${path.resolve(logFile)}`);

  // Piggyback WAL checkpoint on idle ticks — see comment in worker.ts.
  let lastCheckpoint = 0;
  const checkpointIfDue = (): void => {
    const now = Date.now();
    if (now - lastCheckpoint < 60_000) return;
    lastCheckpoint = now;
    try { db.raw.pragma('wal_checkpoint(TRUNCATE)'); } catch { /* busy: retry next tick */ }
  };

  const { batches } = await runQueueLoop({
    queue: db.reportQueue,
    label: 'report',
    batchSize: opts.batchSize,
    maxBatches: opts.maxBatches,
    watch: opts.watch,
    pollSec: opts.pollSec,
    log,
    onIdleTick: checkpointIfDue,
    processBatch: async (claimed): Promise<BatchOutcome> => {
      const now = new Date().toISOString();
      for (const c of claimed) {
        const data = gatherTargetData(db, c.target, now);
        const out = path.join(opts.outDir, reportFilename(c.target));
        fs.writeFileSync(out, renderTargetReport(data));
        log.info(`  report ${c.target} → ${out} (${data.findings.length} findings, risk ${data.riskScore ?? 'n/a'})`);
      }
      return { ok: true };
    },
  });

  const totalDt = ((Date.now() - startAll) / 1000).toFixed(0);
  const rq = db.reportQueue.stats();
  log.info(`report worker finished: ${batches} batch(es) in ${totalDt}s. report_queue: pending=${rq.pending} in_progress=${rq.in_progress} done=${rq.done} failed=${rq.failed}`);
  db.close();
  log.close();
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
