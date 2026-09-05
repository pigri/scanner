#!/usr/bin/env -S node --loader tsx
// Populate the scan_queue from one of:
//   1. --from-risk               (top-N of the latest risk_scores, skipping already-scanned)
//   2. --from-file <path>        (one target per line, priority = position from top)
//   3. positional args           (`enqueue foo.example.com bar.example.com`, priority 0)
// Deduplication is automatic via UNIQUE(target) — re-running is safe.
import fs from 'node:fs';
import { openDb, type QueueEntry } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';
import { createLogger } from './lib/log.js';
import { probeLive } from './lib/liveness.js';

interface Opts {
  db: string;
  fromRisk: number | null;
  fromFile: string | null;
  args: string[];
  skipScanned: boolean;
  reset: boolean;
  requeue: boolean;
  liveOnly: boolean;
  logFile: string | null;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { db: resolveDbArg(argv), fromRisk: null, fromFile: null, args: [], skipScanned: true, reset: false, requeue: false, liveOnly: false, logFile: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (isDbFlag(a)) { i++; } // db path resolved by resolveDbArg
    else if (a === '--log') opts.logFile = next();
    else if (a === '--live-only') opts.liveOnly = true;
    else if (a === '--requeue') { opts.requeue = true; opts.skipScanned = false; } // re-scan: reset existing rows to pending
    else if (a === '--from-risk') opts.fromRisk = parseInt(next(), 10);
    else if (a === '--from-file') opts.fromFile = next();
    else if (a === '--include-scanned') opts.skipScanned = false;
    else if (a === '--reset') opts.reset = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else opts.args.push(a);
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: enqueue [options] [<target>...]

Populate the scan_queue from risk_scores, a file, or CLI args. Idempotent.

Options:
  --sqlite <path>          scan.db (default: scan.db) [alias: --db]
  --log <file>             tee timestamped logs to <file> (also stderr)
  --from-risk <N>          enqueue top-N targets from risk_scores.
                           Priority = the score itself.
  --from-file <path>       one target per line; priority = line position from top
                           (highest priority for line 1).
  --live-only              probe candidates with httpx first; enqueue only hosts
                           that answer (drops resolvable-but-dead dev hosts).
                           Fails open if httpx is unavailable.
  --include-scanned        include hosts already in http_probes/ports/findings
                           (default: skip them)
  --requeue                re-queue targets even if already present: reset their
                           status to pending (implies --include-scanned). Used by
                           the weekly full re-scan to re-check known hosts.
  --reset                  wipe the queue before enqueuing (dangerous)
  positional args          add these targets with priority 0

Examples:
  enqueue --from-risk 500                        # top-500 unscanned hosts by risk
  enqueue --from-file ../discovery/domains.txt   # every discovered host
  enqueue evil.example.com --db scan.db          # one target, priority 0
`);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  const log = createLogger({ file: opts.logFile });
  const db = openDb(opts.db);
  const now = new Date().toISOString();

  if (opts.reset) {
    const n = db.raw.prepare('DELETE FROM scan_queue').run().changes;
    log.warn(`--reset: cleared ${n} queue rows`);
  }

  // A host counts as "scanned" if it has open ports, real findings, or a
  // MEANINGFUL http_probe. A bodyless 3xx (empty-body redirect with no title) is
  // NOT meaningful: apps behind a session/login redirect — Oracle APEX/ORDS,
  // Oracle Forms, etc. — leave only such a probe, so counting it as scanned
  // permanently hid them from re-scan. Excluding bodyless-3xx-only hosts here
  // means they get re-probed (and picked up by the APEX/ORDS template).
  const scannedSet = opts.skipScanned
    ? new Set(
        (db.raw.prepare(
          `SELECT target FROM ports
           UNION SELECT target FROM findings
           UNION SELECT target FROM http_probes
             WHERE NOT (status_code BETWEEN 300 AND 399
                        AND (content_length = 0 OR content_length IS NULL)
                        AND (title IS NULL OR title = ''))`
        ).all() as { target: string }[]).map((r) => r.target)
      )
    : new Set<string>();

  const entries: QueueEntry[] = [];

  if (opts.fromRisk) {
    const rows = db.raw.prepare(`
      SELECT target, MAX(score) score
      FROM risk_scores
      GROUP BY target
      ORDER BY score DESC, target
      LIMIT ?
    `).all(opts.fromRisk) as { target: string; score: number }[];
    for (const r of rows) {
      if (!opts.skipScanned || !scannedSet.has(r.target)) {
        entries.push({ target: r.target, priority: r.score });
      }
    }
    log.info(`--from-risk ${opts.fromRisk}: ${rows.length} candidates → ${entries.length} to enqueue`);
  }

  if (opts.fromFile) {
    const lines = fs.readFileSync(opts.fromFile, 'utf8').split('\n').map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));
    const N = lines.length;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i]!;
      if (opts.skipScanned && scannedSet.has(t)) continue;
      entries.push({ target: t, priority: N - i });
    }
    log.info(`--from-file ${opts.fromFile}: ${lines.length} lines → ${entries.length} to enqueue`);
  }

  for (const t of opts.args) {
    if (opts.skipScanned && scannedSet.has(t)) continue;
    entries.push({ target: t, priority: 0 });
  }

  // Liveness pre-filter: probe candidates with httpx and drop those that don't
  // answer, so the queue isn't front-loaded with resolvable-but-dead dev hosts.
  // Fails open — if httpx can't run, we keep all candidates rather than drop them.
  if (opts.liveOnly && entries.length) {
    log.info(`--live-only: probing ${entries.length} candidate(s) with httpx...`);
    try {
      const live = await probeLive(entries.map((e) => e.target));
      const before = entries.length;
      const kept = entries.filter((e) => live.has(e.target.toLowerCase()));
      entries.length = 0;
      entries.push(...kept);
      log.info(`--live-only: ${kept.length}/${before} candidate(s) are live`);
    } catch (err) {
      log.warn(`--live-only: httpx probe failed (${err instanceof Error ? err.message : String(err)}); enqueuing all candidates`);
    }
  }

  if (!entries.length) {
    log.info('nothing to enqueue');
    db.close();
    log.close();
    return;
  }
  const n = opts.requeue ? db.scanQueue.requeueMany(entries, now) : db.enqueueMany(entries, now);
  if (opts.requeue) log.info(`requeued ${n} target(s) to pending (of ${entries.length} attempted)`);
  else log.info(`enqueued ${n} new (of ${entries.length} attempted; ${entries.length - n} were duplicates)`);
  const s = db.queueStats();
  log.info(`queue now: pending=${s.pending} in_progress=${s.in_progress} done=${s.done} failed=${s.failed}`);
  db.close();
  log.close();
}

main().catch((err: unknown) => { console.error('FATAL:', err instanceof Error ? err.message : String(err)); process.exit(1); });
