#!/usr/bin/env -S node --loader tsx
// history: per-finding history for a target. Groups findings by
// (tool, category, title) and cross-references each group against every
// completed scan_queue window. Two modes:
//   - grid (default): one line per key with a ✓/✗ attendance strip
//   - detail: --title <t> filters to matching keys and prints each key's
//     full per-window attendance + every observation with matched_at/run_id
//
// The scan_queue.finished_at row list defines the window sequence, same as
// deep-audit and resolved. Findings that predate the earliest scan_queue
// row still count in first_seen/last_seen but sit outside every presence bit.
import { openDb } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';
import {
  computeAttendance,
  type Observation,
  type ScanWindow,
  type KeyAttendance,
} from './lib/history.js';

interface Opts {
  db: string;
  target: string | null;
  tool: string | null;
  category: string | null;
  title: string | null;
  json: boolean;
  limit: number;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    db: resolveDbArg(argv),
    target: null, tool: null, category: null, title: null,
    json: false, limit: 100,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = (): string => argv[++i]!;
    if (isDbFlag(a)) { i++; continue; }
    else if (a === '--target') opts.target = next();
    else if (a === '--tool') opts.tool = next();
    else if (a === '--category') opts.category = next();
    else if (a === '--title') opts.title = next();
    else if (a === '--json') opts.json = true;
    else if (a === '--limit') opts.limit = parseInt(next(), 10);
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: history --target <host> [--tool <t>] [--title <t>] [--json] [--limit N]

Per-finding history for one target. Groups findings by (tool, category, title)
and marks presence in every completed scan_queue window (chronological).

Modes:
  --target <host>                  Grid: one line per key with a ✓/✗ strip.
  --target <host> --title <t>      Detail: full attendance + observation
                                   timeline for keys whose title matches <t>
                                   exactly. Combine with --tool/--category.

Options:
  --sqlite <path>   DB path (default: scan.db) [alias: --db]
  --json            Machine-readable JSONL output
  --limit N         Cap grid rows (default: 100; ignored for detail mode)

Presence strip:
  ✓   present in that window
  ·   absent (tool ran, finding didn't fire)
  -   n/a (that window was a different tool)

Status column (based on the most recent APPLICABLE window):
  persistent   present in the most recent applicable scan
  resolved     absent from the most recent applicable scan (observed before)
  unknown      no applicable window (finding predates the recorded runs)
  <status>!    ≥ 2 present↔absent transitions — often WAF / rate-limit /
               DNS churn, not an actual fix
`);
}

interface WindowRow { target: string; started_at: string; finished_at: string }

function scanWindowsFor(db: ReturnType<typeof openDb>, target: string): ScanWindow[] {
  // Windows come from the runs table (per-tool, chronological). Each row is
  // tagged with the tool that ran during it; the pure lib treats a window as
  // n/a for keys whose tool doesn't match (scan-all is a wildcard). We
  // include every run whose bounds touch a finding OR intersect a recorded
  // scan_queue window for this target, so the "clean now" case (a fresh scan
  // that wrote zero findings) still contributes a window.
  const runRows = db.raw.prepare(`
    SELECT DISTINCT r.id, r.tool, r.started_at, r.finished_at
    FROM runs r
    WHERE r.finished_at IS NOT NULL
      AND (
        EXISTS (
          SELECT 1 FROM findings f
          WHERE f.target = ? AND f.seen_at >= r.started_at AND f.seen_at <= r.finished_at
        )
        OR EXISTS (
          SELECT 1 FROM scan_queue sq
          WHERE sq.target = ? AND sq.status = 'done' AND sq.finished_at IS NOT NULL
            AND sq.started_at <= r.finished_at AND sq.finished_at >= r.started_at
        )
      )
    ORDER BY r.started_at
  `).all(target, target) as { id: number; tool: string; started_at: string; finished_at: string }[];
  const windows: ScanWindow[] = runRows.map((r) => ({
    target, tool: r.tool, startedAt: r.started_at, finishedAt: r.finished_at,
  }));
  // Ensure the current scan_queue row contributes at least one window (a
  // scan-all umbrella) even when the query above missed it — e.g. all
  // per-tool runs pre-date the current queue entry.
  const sq = db.raw.prepare(`
    SELECT target, started_at, finished_at FROM scan_queue
    WHERE target = ? AND status = 'done' AND finished_at IS NOT NULL
  `).get(target) as WindowRow | undefined;
  if (sq?.started_at && sq?.finished_at) {
    const already = windows.some(
      (w) => w.startedAt === sq.started_at && w.finishedAt === sq.finished_at,
    );
    if (!already) {
      windows.push({ target: sq.target, tool: 'scan-all', startedAt: sq.started_at, finishedAt: sq.finished_at });
      windows.sort((a, b) => a.startedAt.localeCompare(b.startedAt));
    }
  }
  return windows;
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
  run_id: number | null;
}

function findingsFor(db: ReturnType<typeof openDb>, target: string, tool: string | null): Observation[] {
  const rows = tool
    ? db.raw.prepare(`
        SELECT tool, target, category, severity, title, cve, matched_at, seen_at, run_id
        FROM findings WHERE target = ? AND tool = ? ORDER BY seen_at
      `).all(target, tool) as FindingRow[]
    : db.raw.prepare(`
        SELECT tool, target, category, severity, title, cve, matched_at, seen_at, run_id
        FROM findings WHERE target = ? ORDER BY seen_at
      `).all(target) as FindingRow[];
  return rows.map((r) => ({
    tool: r.tool, target: r.target,
    category: r.category ?? '',
    title: r.title,
    severity: r.severity,
    seen_at: r.seen_at,
    cve: r.cve, matched_at: r.matched_at, run_id: r.run_id,
  }));
}

function renderStrip(a: KeyAttendance): string {
  return a.presence.map((p) => (p === 'present' ? '✓' : p === 'absent' ? '·' : '-')).join('');
}

function currentSeverity(r: KeyAttendance): string | null {
  for (let i = r.severityPerWindow.length - 1; i >= 0; i--) {
    const sev = r.severityPerWindow[i];
    if (r.presence[i] === 'present' && sev) return sev;
  }
  return null;
}

function printGrid(rows: KeyAttendance[], windows: ScanWindow[], limit: number): void {
  const capped = rows.slice(0, limit);
  const stripHeader = windows.map((_, i) => String((i + 1) % 10)).join('');
  console.log(`\nscans (chronological): ${windows.length}   legend: ✓ present  · absent  - n/a (tool didn't run)`);
  windows.forEach((w, i) => console.log(`  #${i + 1}  ${w.tool.padEnd(12)}  ${w.startedAt} → ${w.finishedAt}`));
  console.log(`\n${'STATUS'.padEnd(11)} ${stripHeader.padEnd(Math.max(stripHeader.length, 6))}  ${'SEV'.padEnd(8)} ${'TOOL'.padEnd(10)} KEY  (obs)  first→last`);
  console.log('─'.repeat(120));
  for (const r of capped) {
    const status = r.status + (r.flapping ? '!' : '');
    const strip = renderStrip(r);
    const sev = (r.worstSeverity ?? '-').padEnd(8);
    const cur = currentSeverity(r);
    const curTag = r.status === 'persistent' && cur ? ` cur=${cur}` : '';
    console.log(
      `${status.padEnd(11)} ${strip.padEnd(Math.max(stripHeader.length, 6))}  ` +
      `${sev} ${r.tool.padEnd(10)} ${r.category}::${r.title}  ` +
      `(${r.observations} obs)  ${r.firstSeen}→${r.lastSeen}${curTag}`,
    );
  }
  console.error(
    `\n${rows.length} key(s) with history` +
    (rows.length > capped.length ? ` (showing top ${capped.length})` : ''),
  );
}

function printDetail(
  keys: KeyAttendance[],
  windows: ScanWindow[],
  observations: readonly Observation[],
  target: string,
): void {
  if (!keys.length) {
    console.error('no keys matched the given filters');
    return;
  }
  for (const k of keys) {
    console.log('═'.repeat(96));
    const flap = k.flapping ? '  [FLAPPING — presence toggled across windows]' : '';
    console.log(`KEY: ${k.tool}::${k.category}::${k.title}`);
    console.log(`     target=${target}   status=${k.status}${flap}`);
    console.log(`     observations=${k.observations}   windows=${windows.length}   worst_severity=${k.worstSeverity ?? '-'}`);
    console.log(`     first_seen=${k.firstSeen}   last_seen=${k.lastSeen}`);
    console.log('\n  Per-scan attendance (✓ present  · absent  - n/a):');
    windows.forEach((w, i) => {
      const state = k.presence[i]!;
      const mark = state === 'present' ? '✓' : state === 'absent' ? '·' : '-';
      const sev = k.severityPerWindow[i] ? ` severity=${k.severityPerWindow[i]}` : '';
      console.log(`    #${i + 1}  ${w.tool.padEnd(12)}  ${w.startedAt} → ${w.finishedAt}   ${mark}${sev}`);
    });

    const rows = observations.filter(
      (o) => o.tool === k.tool && o.category === k.category && o.title === k.title,
    );
    console.log('\n  Observations (chronological):');
    for (const o of rows) {
      const sev = `[${(o.severity ?? '-').padEnd(8)}]`;
      const m = o.matched_at ? `  matched_at=${o.matched_at}` : '';
      const r = o.run_id != null ? `  run=${o.run_id}` : '';
      const cve = o.cve ? `  ${o.cve}` : '';
      console.log(`    ${o.seen_at}  ${sev}${cve}${m}${r}`);
    }
    console.log('');
  }
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.target) {
    if (!opts.help) console.error('--target <host> is required\n');
    usage();
    process.exit(opts.help ? 0 : 1);
  }
  const db = openDb(opts.db);
  const windows = scanWindowsFor(db, opts.target);
  if (!windows.length) {
    console.error(`no completed scan windows found for ${opts.target}`);
    db.close();
    process.exit(1);
  }
  const observations = findingsFor(db, opts.target, opts.tool);
  let rows = computeAttendance(observations, windows);
  if (opts.category) rows = rows.filter((r) => r.category === opts.category);
  if (opts.tool) rows = rows.filter((r) => r.tool === opts.tool);

  const detail = opts.title != null;
  if (detail) rows = rows.filter((r) => r.title === opts.title);

  if (opts.json) {
    for (const r of rows) console.log(JSON.stringify(r));
    db.close();
    return;
  }

  if (detail) printDetail(rows, windows, observations, opts.target);
  else printGrid(rows, windows, opts.limit);
  db.close();
}

main();
