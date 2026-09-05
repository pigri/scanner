#!/usr/bin/env -S node --loader tsx
// Delete specific runs (and their child rows) from a scan DB. Generalizes the
// old _prune-e2e-pollution.mjs one-off. Backs up the DB first and refuses to
// run unless every targeted run's tool matches an --expect assertion (so you
// can't delete the wrong rows).
import fs from 'node:fs';
import path from 'node:path';
import { openDb } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';

interface Opts {
  db: string;
  runs: number[];
  expect: Map<number, string>; // runId -> expected tool name
  yes: boolean;
  help?: boolean;
}

/** Parse a comma/space separated list of run ids into a deduped sorted number[]. */
export function parseRunIds(spec: string): number[] {
  const ids = new Set<number>();
  for (const tok of spec.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean)) {
    const n = Number(tok);
    if (!Number.isInteger(n) || n <= 0) throw new Error(`invalid run id: ${tok}`);
    ids.add(n);
  }
  return [...ids].sort((a, b) => a - b);
}

/** Parse `id:tool` assertions (repeatable) into a map. */
export function parseExpect(pairs: string[]): Map<number, string> {
  const m = new Map<number, string>();
  for (const p of pairs) {
    const [idStr, tool] = p.split(':');
    const id = Number(idStr);
    if (!Number.isInteger(id) || !tool) throw new Error(`invalid --expect '${p}' (want id:tool)`);
    m.set(id, tool);
  }
  return m;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { db: resolveDbArg(argv), runs: [], expect: new Map(), yes: false };
  const expectPairs: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (isDbFlag(a)) { i++; continue; }
    else if (a === '--runs') opts.runs = parseRunIds(next());
    else if (a === '--expect') expectPairs.push(next());
    else if (a === '--yes') opts.yes = true;
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  opts.expect = parseExpect(expectPairs);
  return opts;
}

function usage(): void {
  console.error(`Usage: prune-runs --runs <ids> [--expect id:tool ...] [--sqlite scan.db] [--yes]

Deletes the given runs and their child rows (findings, risk_scores) from the DB.
Backs up to <db>.bak first. With --expect, aborts unless each run's tool matches.

  --runs <ids>       comma/space separated run ids (e.g. "21,22")
  --expect id:tool   assert run <id> is tool <tool> before deleting (repeatable)
  --sqlite <path>    scan DB (default: scan.db) [alias: --db]
  --yes              actually delete (dry-run prints the plan otherwise)`);
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help || opts.runs.length === 0) { usage(); process.exit(opts.help ? 0 : 1); }

  const db = openDb(opts.db);
  const raw = db.raw;

  // Verify each run exists and matches its --expect assertion.
  const getRun = raw.prepare('SELECT id, tool FROM runs WHERE id = ?');
  for (const id of opts.runs) {
    const row = getRun.get(id) as { id: number; tool: string } | undefined;
    if (!row) { console.error(`ABORT: run ${id} not found in ${opts.db}`); db.close(); process.exit(1); }
    const expected = opts.expect.get(id);
    if (expected && row.tool !== expected) {
      console.error(`ABORT: run ${id} is '${row.tool}', expected '${expected}'. No changes made.`);
      db.close(); process.exit(1);
    }
    console.error(`  run ${id} = ${row.tool}${expected ? ' (matches --expect)' : ''}`);
  }

  const placeholders = opts.runs.map(() => '?').join(',');
  const countChildren = (table: string): number =>
    (raw.prepare(`SELECT count(*) c FROM ${table} WHERE run_id IN (${placeholders})`).get(...opts.runs) as { c: number }).c;
  const plan = {
    findings: countChildren('findings'),
    risk_scores: countChildren('risk_scores'),
    runs: opts.runs.length,
  };

  if (!opts.yes) {
    console.error(`\nDRY RUN — would delete: ${JSON.stringify(plan)}`);
    console.error('Re-run with --yes to apply.');
    db.close();
    return;
  }

  const bak = `${opts.db}.bak`;
  fs.copyFileSync(opts.db, bak);
  console.error(`backup written: ${path.resolve(bak)}`);

  const tx = raw.transaction(() => {
    raw.prepare(`DELETE FROM findings WHERE run_id IN (${placeholders})`).run(...opts.runs);
    raw.prepare(`DELETE FROM risk_scores WHERE run_id IN (${placeholders})`).run(...opts.runs);
    raw.prepare(`DELETE FROM runs WHERE id IN (${placeholders})`).run(...opts.runs);
  });
  tx();
  console.error(`deleted: ${JSON.stringify(plan)}`);
  db.close();
}

// Only run when invoked directly, so tests can import parseRunIds/parseExpect.
if (process.argv[1] && process.argv[1].endsWith('prune-runs.ts')) main();
