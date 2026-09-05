#!/usr/bin/env -S node --loader tsx
// resolved: per-target finding-regression detector. For each host with a
// completed scan_queue row, compares findings observed BEFORE the most-recent
// scan window against findings observed IN it. A (tool, category, title) key
// that used to fire but didn't come back is "resolved"; anything new is
// "novel"; anything seen in both is "persistent" (still open).
//
// The scan_queue.{started_at,finished_at} interval defines the window — same
// data source deep-audit uses to decide "have we actually scanned this host?".
// Hosts without a completed scan_queue row are skipped as unknown.
//
// A finding "disappearing" from the latest scan can also mean the detection
// template was removed upstream. Treat the output as presumed-resolved, not
// audited-resolved.
import { openDb } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';
import {
  diffAgainstScan, classifyHost, isMeaningful,
  type Observation, type ScanWindow, type Diff, type HostStatus,
} from './lib/resolved.js';

interface Opts {
  db: string;
  mode: 'clean-now' | 'target' | 'all-fixed';
  target: string | null;
  json: boolean;
  limit: number;
  includeInfo: boolean;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    db: resolveDbArg(argv),
    mode: 'clean-now',
    target: null,
    json: false,
    limit: 50,
    includeInfo: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = (): string => argv[++i]!;
    if (isDbFlag(a)) { i++; continue; }
    else if (a === '--target') { opts.mode = 'target'; opts.target = next(); }
    else if (a === '--all-fixed') opts.mode = 'all-fixed';
    else if (a === '--json') opts.json = true;
    else if (a === '--limit') opts.limit = parseInt(next(), 10);
    else if (a === '--include-info') opts.includeInfo = true;
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: resolved [--sqlite scan.db] [mode] [options]

Detect findings that stopped surfacing on the latest scan. Scan window comes
from scan_queue.{started_at,finished_at}; a host with no completed queue row
is skipped (we can't tell what "latest scan" means for it).

Modes:
  (default)          Print the clean-now cohort: hosts that had meaningful
                     (crit/high/med/low) findings before their last scan and
                     have none in it.
  --target <host>    Itemize resolved / persistent / novel findings for one host.
  --all-fixed        List every presumed-resolved finding across all hosts.

Options:
  --sqlite <path>    DB path (default: scan.db) [alias: --db]
  --json             Machine-readable JSONL output
  --limit N          Cap rows (default: 50; ignored for --target)
  --include-info     Count info-severity too (default: only crit/high/med/low)

Caveat: a finding may "disappear" because its detection template was removed
upstream. Treat output as presumed-resolved, not audited-resolved.
`);
}

interface ScanWindowRow {
  target: string;
  started_at: string;
  finished_at: string;
}

interface FindingRow {
  tool: string;
  target: string;
  category: string | null;
  severity: string | null;
  title: string;
  cve: string | null;
  matched_at: string | null;
  seen_at: string;
}

function toObservation(r: FindingRow): Observation {
  return {
    tool: r.tool,
    target: r.target,
    category: r.category ?? '',
    title: r.title,
    severity: r.severity,
    seen_at: r.seen_at,
    cve: r.cve,
    matched_at: r.matched_at,
  };
}

// A finding key counts as "meaningful" iff its pre or during observation is
// meaningful (or info is included via --include-info).
function meaningfulGate(includeInfo: boolean): (o: Pick<Observation, 'severity'>) => boolean {
  return includeInfo ? (): boolean => true : isMeaningful;
}

function scanWindowFor(db: ReturnType<typeof openDb>, target: string): ScanWindow | null {
  const row = db.raw
    .prepare(
      `SELECT target, started_at, finished_at FROM scan_queue
       WHERE target = ? AND status = 'done' AND finished_at IS NOT NULL
       ORDER BY finished_at DESC LIMIT 1`,
    )
    .get(target) as ScanWindowRow | undefined;
  if (!row?.started_at || !row?.finished_at) return null;
  return { target: row.target, startedAt: row.started_at, finishedAt: row.finished_at };
}

function allScanWindows(db: ReturnType<typeof openDb>): ScanWindow[] {
  const rows = db.raw
    .prepare(
      `SELECT target, MAX(finished_at) AS finished_at,
              (SELECT started_at FROM scan_queue s2
                WHERE s2.target = scan_queue.target
                  AND s2.status = 'done'
                  AND s2.finished_at IS NOT NULL
                ORDER BY finished_at DESC LIMIT 1) AS started_at
       FROM scan_queue
       WHERE status = 'done' AND finished_at IS NOT NULL
       GROUP BY target`,
    )
    .all() as ScanWindowRow[];
  return rows
    .filter((r) => r.started_at && r.finished_at)
    .map((r) => ({ target: r.target, startedAt: r.started_at, finishedAt: r.finished_at }));
}

function findingsFor(db: ReturnType<typeof openDb>, target: string): Observation[] {
  const rows = db.raw
    .prepare(
      `SELECT tool, target, category, severity, title, cve, matched_at, seen_at
       FROM findings WHERE target = ? ORDER BY seen_at`,
    )
    .all(target) as FindingRow[];
  return rows.map(toObservation);
}

function fmtObs(o: Observation): string {
  const sev = (o.severity ?? '-').padEnd(8);
  const cve = o.cve ? `  ${o.cve}` : '';
  return `  [${sev}] ${o.tool.padEnd(10)} ${o.category}::${o.title}${cve}  (last seen ${o.seen_at})`;
}

function printTarget(diff: Diff, includeInfo: boolean): void {
  const gate = meaningfulGate(includeInfo);
  const resolved = diff.resolved.filter(gate);
  const persistent = diff.persistent.filter((p) => gate(p.pre) || gate(p.during));
  const novel = diff.novel.filter(gate);
  const status = classifyHost(diff);

  console.log(`${diff.target}   status=${status}`);
  console.log(`  window: ${diff.window.startedAt} → ${diff.window.finishedAt}`);
  console.log(`  resolved=${resolved.length}  persistent=${persistent.length}  novel=${novel.length}`);
  if (resolved.length) {
    console.log('\n  RESOLVED (were open, absent from latest scan):');
    for (const o of resolved) console.log(fmtObs(o));
  }
  if (novel.length) {
    console.log('\n  NEW (first seen in latest scan):');
    for (const o of novel) console.log(fmtObs(o));
  }
  if (persistent.length) {
    console.log('\n  PERSISTENT (still open):');
    for (const p of persistent) console.log(fmtObs(p.during));
  }
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }
  const db = openDb(opts.db);

  if (opts.mode === 'target') {
    if (!opts.target) { console.error('--target requires a hostname'); process.exit(1); }
    const window = scanWindowFor(db, opts.target);
    if (!window) {
      console.error(`no completed scan_queue row for ${opts.target}`);
      db.close();
      process.exit(1);
    }
    const diff = diffAgainstScan(findingsFor(db, opts.target), window);
    if (opts.json) console.log(JSON.stringify({ ...diff, status: classifyHost(diff) }));
    else printTarget(diff, opts.includeInfo);
    db.close();
    return;
  }

  const windows = allScanWindows(db);
  const gate = meaningfulGate(opts.includeInfo);

  if (opts.mode === 'clean-now') {
    const cohort: Array<{ target: string; resolvedCount: number; lastScanAt: string; status: HostStatus }> = [];
    for (const w of windows) {
      const diff = diffAgainstScan(findingsFor(db, w.target), w);
      const status = classifyHost(diff);
      if (status !== 'clean-now') continue;
      const resolvedCount = diff.resolved.filter(gate).length;
      cohort.push({ target: w.target, resolvedCount, lastScanAt: w.finishedAt, status });
    }
    cohort.sort((a, b) => b.resolvedCount - a.resolvedCount || a.target.localeCompare(b.target));
    const capped = cohort.slice(0, opts.limit);

    if (opts.json) {
      for (const r of capped) console.log(JSON.stringify(r));
    } else {
      for (const r of capped) {
        console.log(`${String(r.resolvedCount).padStart(4)} resolved   ${r.target}   last scan ${r.lastScanAt}`);
      }
    }
    console.error(
      `\n${cohort.length} host(s) transitioned to clean-now` +
      (cohort.length > capped.length ? ` (showing top ${capped.length})` : '') +
      ` — scanned targets: ${windows.length}`,
    );
    db.close();
    return;
  }

  // --all-fixed: itemize every presumed-resolved finding across all hosts.
  interface Row { target: string; obs: Observation; lastScanAt: string }
  const rows: Row[] = [];
  for (const w of windows) {
    const diff = diffAgainstScan(findingsFor(db, w.target), w);
    for (const o of diff.resolved.filter(gate)) {
      rows.push({ target: w.target, obs: o, lastScanAt: w.finishedAt });
    }
  }
  rows.sort((a, b) => {
    const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const d = (rank[String(b.obs.severity ?? '').toLowerCase()] ?? -1) - (rank[String(a.obs.severity ?? '').toLowerCase()] ?? -1);
    return d !== 0 ? d : a.target.localeCompare(b.target);
  });
  const capped = rows.slice(0, opts.limit);
  if (opts.json) {
    for (const r of capped) console.log(JSON.stringify(r));
  } else {
    for (const r of capped) {
      const sev = (r.obs.severity ?? '-').padEnd(8);
      const cve = r.obs.cve ? `  ${r.obs.cve}` : '';
      console.log(
        `[${sev}] ${r.obs.tool.padEnd(10)} ${r.target}   ${r.obs.category}::${r.obs.title}${cve}  ` +
        `(last seen ${r.obs.seen_at}, scan ${r.lastScanAt})`,
      );
    }
  }
  console.error(
    `\n${rows.length} presumed-resolved finding(s)` +
    (rows.length > capped.length ? ` (showing top ${capped.length})` : ''),
  );
  db.close();
}

main();
