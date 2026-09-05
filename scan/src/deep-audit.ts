#!/usr/bin/env -S node --loader tsx
// deep-audit: force-requeue the hosts that returned zero findings on the
// prior sweep — the "locked down or under-instrumented?" cohort. Sets a
// high priority so the workers hit these first, and drops a marker into
// scan_queue.error indicating deep-scan intent (scan-all itself reads
// $SCAN_DEEP from the env when set).
//
// Optional --dry-run just lists the cohort.
import path from 'node:path';
import Database from 'better-sqlite3';

function usage(): void {
  console.error(`Usage: deep-audit --sqlite <path> [--dry-run] [--priority N] [--limit N]

Requeues hosts in scan_queue.status='done' that have zero findings rows —
the "were they locked down or did we under-scan them?" cohort. Sets
priority (default 100) so the workers hit these first; leaves an
'error' marker of 'deep-audit-<iso>' so you can track which pass drove
the requeue.

Pair with SCAN_DEEP=1 in the worker env to make scan-all widen probes
(katana -depth 3, kiterunner --all-hosts, nuclei drops severity/tag filters).

Options:
  --sqlite <path>   default: scan.db
  --priority N      default: 100
  --limit N         cap requeues per run (default: 0 = unlimited)
  --dry-run         list the cohort without touching scan_queue
`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let dbPath = 'scan.db';
  let priority = 100;
  let limit = 0;
  let dryRun = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h' || a === '--help') { usage(); process.exit(0); }
    if (a === '--sqlite' || a === '--db') dbPath = argv[++i]!;
    else if (a === '--priority') priority = parseInt(argv[++i]!, 10);
    else if (a === '--limit') limit = parseInt(argv[++i]!, 10);
    else if (a === '--dry-run') dryRun = true;
  }

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');

  // Zero-finding cohort: scan_queue done rows whose target has NO findings
  // beyond the ubiquitous testssl-*/nuclei-info floor. We restrict to
  // "no crit/high/med/low findings" — anything at info-only means either
  // the host is a redirect stub or nuclei found nothing worth flagging.
  const cohort = db.prepare(`
    SELECT sq.target
    FROM scan_queue sq
    WHERE sq.status = 'done'
      AND NOT EXISTS (
        SELECT 1 FROM findings f
        WHERE f.target = sq.target
          AND f.severity IN ('critical','high','medium','low')
      )
    ORDER BY sq.target
  `).all() as { target: string }[];
  console.error(`zero-finding cohort: ${cohort.length} target(s)`);
  if (dryRun) {
    for (const c of cohort.slice(0, 20)) console.log(c.target);
    if (cohort.length > 20) console.log(`... +${cohort.length - 20} more`);
    db.close();
    return;
  }
  if (!cohort.length) { db.close(); return; }

  const now = new Date().toISOString();
  const marker = `deep-audit-${now}`;
  const upd = db.prepare(`
    UPDATE scan_queue SET status='pending', priority=?, started_at=NULL, finished_at=NULL, error=?
    WHERE target = ? AND status = 'done'
  `);
  const capped = limit > 0 ? cohort.slice(0, limit) : cohort;
  const tx = db.transaction((ts: { target: string }[]) => {
    let n = 0;
    for (const t of ts) if (upd.run(priority, marker, t.target).changes) n++;
    return n;
  });
  const n = tx(capped);
  console.error(`deep-audit: requeued ${n}/${capped.length} target(s) at priority=${priority}`);
  console.error(`  marker: ${marker}`);
  console.error(`  db: ${path.resolve(dbPath)}`);
  console.error(`\nSet SCAN_DEEP=1 in worker env for the wider scan-all profile.`);
  db.close();
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
