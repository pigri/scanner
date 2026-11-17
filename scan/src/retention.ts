#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import type Database from 'better-sqlite3';
import { openDb } from './lib/db.js';

/** The only tables retention deletes rows from. */
const PRUNABLE_TABLES = ['findings', 'ports', 'http_probes', 'screenshots'] as const;
type PrunableTable = (typeof PRUNABLE_TABLES)[number];

/** Pruned by its own window rule, only when a risk window is given. */
const RISK_TABLE = 'risk_scores';
const DELETE_TABLES = [...PRUNABLE_TABLES, RISK_TABLE] as const;

const DEFAULT_CHUNK = 1000;
const BUSY_TIMEOUT_MS = 60_000;

export interface RetentionOpts {
  olderThanDays: number;
  /** ISO timestamp the cutoff is measured from. */
  now: string;
  /** false = plan only; nothing is deleted. */
  apply: boolean;
  /** Prune risk_scores rows older than this many days, except each target's latest. Unset = risk_scores untouched. */
  riskOlderThanDays?: number | undefined;
  /** Max rows per delete transaction. */
  chunkSize?: number;
}

export interface RetentionResult {
  rows: Record<PrunableTable, number>;
  /** risk_scores rows pruned (or to prune). */
  riskScores: number;
  /** Runs left with no row in any table that references them (deleted when `apply`). */
  runs: number[];
}

interface Opts {
  db: string;
  runDir: string;
  olderThanDays: number;
  riskOlderThanDays?: number;
  dryRun: boolean;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { db: 'scan.db', runDir: 'runs', olderThanDays: 90, dryRun: true };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--db') opts.db = next();
    else if (a === '--run-dir') opts.runDir = next();
    else if (a === '--older-than') opts.olderThanDays = parseInt(next(), 10);
    else if (a === '--risk-older-than') opts.riskOlderThanDays = parseInt(next(), 10);
    else if (a === '--apply' || a === '--yes') opts.dryRun = false;
    else if (a === '-h' || a === '--help') opts.help = true;
    else throw new Error(`unknown option: ${a}${a === '--keep-min' ? ' (removed: retention is per target now)' : ''}`);
  }
  if (!Number.isFinite(opts.olderThanDays) || opts.olderThanDays < 0) throw new Error('--older-than needs a number of days >= 0');
  if (opts.riskOlderThanDays !== undefined && (!Number.isFinite(opts.riskOlderThanDays) || opts.riskOlderThanDays < 0)) throw new Error('--risk-older-than needs a number of days >= 0');
  return opts;
}

function usage(): void {
  console.error(`Usage: retention [options]

Prune superseded rows of findings, ports, http_probes and screenshots. A row is
pruned only when its run is older than --older-than days AND the same target has
a newer, finished run of the same tool with rows in the same table. A target's latest evidence per tool is never
pruned, however old. With --risk-older-than, risk_scores rows older than N days are
pruned too, except each target's latest row. A run and its output directory are removed only once no
row in any table references the run. Other tables are never touched.

Options:
  --db <path>          scan SQLite DB (default: scan.db)
  --run-dir <path>     base run-output dir (default: runs)
  --older-than <days>  only rows of runs older than N days (default: 90)
  --risk-older-than <days>
                       also prune risk_scores rows older than N days, keeping each
                       target's latest row (default: risk_scores is not touched)
  --apply, --yes       actually delete (default: dry-run only)

Examples:
  retention                               # dry-run, 90 days
  retention --older-than 90 --apply       # delete
  retention --risk-older-than 30          # dry-run, also risk_scores
`);
}

/** Tables with a foreign key to runs, read from the schema rather than a list. */
function runReferencingTables(raw: Database.Database): string[] {
  const names = raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all() as { name: string }[];
  return names.map((n) => n.name).filter((name) =>
    (raw.prepare(`PRAGMA foreign_key_list("${name}")`).all() as { table: string }[]).some((fk) => fk.table === 'runs'));
}

const jd = (col: string): string => `julianday(${col})`;

/** Fills temp.ret_rows with the (table, id, run_id) of every prunable row. */
function planRows(raw: Database.Database, cutoffIso: string, riskCutoffIso: string | null): void {
  raw.exec(`
    DROP TABLE IF EXISTS temp.ret_latest;
    DROP TABLE IF EXISTS temp.ret_rows;
    CREATE TEMP TABLE ret_latest(tbl TEXT NOT NULL, target TEXT NOT NULL, tool TEXT NOT NULL, ts REAL NOT NULL, run_id INTEGER NOT NULL, PRIMARY KEY(tbl, target, tool)) WITHOUT ROWID;
    CREATE TEMP TABLE ret_rows(tbl TEXT NOT NULL, id INTEGER NOT NULL, run_id INTEGER, PRIMARY KEY(tbl, id)) WITHOUT ROWID;
  `);
  // Latest superseding run per (table, target, tool): newer = later started_at, then higher id.
  // Only a finished run with a parseable started_at may supersede, so a worker killed
  // mid-run never displaces the last complete evidence.
  for (const t of PRUNABLE_TABLES) {
    raw.exec(`
      INSERT INTO temp.ret_latest(tbl, target, tool, ts, run_id)
      SELECT '${t}', target, tool, ts, run_id FROM (
        SELECT x.target AS target, r.tool AS tool, ${jd('r.started_at')} AS ts, r.id AS run_id,
               ROW_NUMBER() OVER (PARTITION BY x.target, r.tool ORDER BY ${jd('r.started_at')} DESC, r.id DESC) AS rn
        FROM (SELECT DISTINCT target, run_id FROM ${t} WHERE run_id IS NOT NULL) x
        JOIN runs r ON r.id = x.run_id
        WHERE r.finished_at IS NOT NULL AND ${jd('r.started_at')} IS NOT NULL
      ) WHERE rn = 1
    `);
    raw.prepare(`
      INSERT INTO temp.ret_rows(tbl, id, run_id)
      SELECT '${t}', t.id, t.run_id
      FROM ${t} t
      JOIN runs r ON r.id = t.run_id
      JOIN temp.ret_latest l ON l.tbl = '${t}' AND l.target = t.target AND l.tool = r.tool
      WHERE ${jd('r.started_at')} < ${jd('?')}
        AND (${jd('r.started_at')}, r.id) < (l.ts, l.run_id)
    `).run(cutoffIso);
  }
  // risk_scores: not tied to a run's age. Pruned by its own computed_at, never the
  // target's latest row (the one latestRiskRowSql picks).
  if (riskCutoffIso !== null) {
    raw.prepare(`
      INSERT INTO temp.ret_rows(tbl, id, run_id)
      SELECT '${RISK_TABLE}', id, run_id FROM (
        SELECT id, run_id, computed_at,
               ROW_NUMBER() OVER (PARTITION BY target ORDER BY computed_at DESC, id DESC) AS rn
        FROM ${RISK_TABLE}
      ) WHERE rn > 1 AND ${jd('computed_at')} < ${jd('?')}
    `).run(riskCutoffIso);
  }
}

/** Runs with a prunable row, and no other row in any table that references runs. */
function runsLeftEmpty(raw: Database.Database): number[] {
  raw.exec('DROP TABLE IF EXISTS temp.ret_refd; CREATE TEMP TABLE ret_refd(run_id INTEGER PRIMARY KEY)');
  // run_id has no index on any child table: scan each table once, not once per run.
  for (const t of runReferencingTables(raw)) {
    const survives = (DELETE_TABLES as readonly string[]).includes(t)
      ? ` AND NOT EXISTS (SELECT 1 FROM temp.ret_rows p WHERE p.tbl = '${t}' AND p.id = x.id)`
      : '';
    raw.exec(`INSERT OR IGNORE INTO temp.ret_refd SELECT DISTINCT x.run_id FROM "${t}" x WHERE x.run_id IS NOT NULL${survives}`);
  }
  return (raw.prepare(
    'SELECT DISTINCT run_id FROM temp.ret_rows WHERE run_id IS NOT NULL AND run_id NOT IN (SELECT run_id FROM temp.ret_refd) ORDER BY run_id',
  ).all() as { run_id: number }[]).map((r) => r.run_id);
}

/**
 * Plan (and, with `apply`, perform) per-target retention. Deletes run in
 * `.immediate()` transactions of at most `chunkSize` rows so live workers wait
 * only briefly for the write lock.
 */
export function runRetention(raw: Database.Database, opts: RetentionOpts): RetentionResult {
  const chunk = opts.chunkSize ?? DEFAULT_CHUNK;
  const cutoff = new Date(Date.parse(opts.now) - opts.olderThanDays * 86_400_000).toISOString();
  const riskCutoff = opts.riskOlderThanDays === undefined
    ? null
    : new Date(Date.parse(opts.now) - opts.riskOlderThanDays * 86_400_000).toISOString();
  planRows(raw, cutoff, riskCutoff);
  try {
    const rows = Object.fromEntries(PRUNABLE_TABLES.map((t) => [t, 0])) as Record<PrunableTable, number>;
    let riskScores = 0;
    for (const r of raw.prepare('SELECT tbl, count(*) AS c FROM temp.ret_rows GROUP BY tbl').all() as { tbl: string; c: number }[]) {
      if (r.tbl === RISK_TABLE) riskScores = r.c;
      else rows[r.tbl as PrunableTable] = r.c;
    }
    const runs = runsLeftEmpty(raw);
    if (!opts.apply) return { rows, riskScores, runs };

    for (const t of DELETE_TABLES) {
      const next = raw.prepare('SELECT id FROM temp.ret_rows WHERE tbl = ? AND id > ? ORDER BY id LIMIT ?');
      const del = raw.prepare(`DELETE FROM ${t} WHERE id IN (SELECT value FROM json_each(?))`);
      let cursor = -1;
      for (;;) {
        const ids = (next.all(t, cursor, chunk) as { id: number }[]).map((r) => r.id);
        if (ids.length === 0) break;
        raw.transaction(() => del.run(JSON.stringify(ids))).immediate();
        cursor = ids[ids.length - 1]!;
      }
    }

    // No row references these runs any more. Skip FK enforcement for the delete:
    // with no index on any child run_id, each deleted run would scan every child table.
    const delRun = raw.prepare('DELETE FROM runs WHERE id = ?');
    raw.pragma('foreign_keys = OFF');
    try {
      for (let i = 0; i < runs.length; i += chunk) {
        const part = runs.slice(i, i + chunk);
        raw.transaction(() => { for (const id of part) delRun.run(id); }).immediate();
      }
    } finally {
      raw.pragma('foreign_keys = ON');
    }
    return { rows, riskScores, runs };
  } finally {
    raw.exec('DROP TABLE IF EXISTS temp.ret_rows; DROP TABLE IF EXISTS temp.ret_latest; DROP TABLE IF EXISTS temp.ret_refd');
  }
}

function deleteDirRecursive(dirPath: string): void {
  if (!fs.existsSync(dirPath)) return;
  fs.rmSync(dirPath, { recursive: true, force: true });
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  const db = openDb(opts.db);
  db.raw.pragma(`busy_timeout = ${BUSY_TIMEOUT_MS}`);
  const result = runRetention(db.raw, { olderThanDays: opts.olderThanDays, riskOlderThanDays: opts.riskOlderThanDays, now: new Date().toISOString(), apply: !opts.dryRun });

  console.error(`rows ${opts.dryRun ? 'to prune' : 'pruned'} (run older than ${opts.olderThanDays}d, target has a newer finished run of the same tool and table):`);
  for (const t of PRUNABLE_TABLES) console.error(`  ${t.padEnd(12)} ${result.rows[t]}`);
  if (opts.riskOlderThanDays !== undefined) {
    console.error(`  ${RISK_TABLE.padEnd(12)} ${result.riskScores}  (older than ${opts.riskOlderThanDays}d, not the target's latest)`);
  }
  console.error(`runs left empty: ${result.runs.length}`);
  let removed = 0;
  for (const id of result.runs) {
    const dir = path.resolve(opts.runDir, String(id));
    const exists = fs.existsSync(dir);
    console.error(`  #${id}  ${exists ? 'has dir' : 'no dir'}  ${dir}`);
    if (!opts.dryRun && exists) { deleteDirRecursive(dir); removed++; }
  }

  if (opts.dryRun) console.error('\ndry-run. Re-run with --apply to delete.');
  else console.error(`\ndeleted ${result.runs.length} runs from DB + ${removed} directories from ${opts.runDir}/`);
  db.close();
}

// Only run when invoked directly, so tests can import runRetention.
if (process.argv[1] && process.argv[1].endsWith('retention.ts')) main();
