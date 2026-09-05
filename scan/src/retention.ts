#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { openDb } from './lib/db.js';
import { runsToPrune, type RunRow } from './lib/retention.js';

interface Opts {
  db: string;
  runDir: string;
  olderThanDays: number;
  keepMin: number;
  dryRun: boolean;
  yes: boolean;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    db: 'scan.db',
    runDir: 'runs',
    olderThanDays: 30,
    keepMin: 3,
    dryRun: true,
    yes: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--db') opts.db = next();
    else if (a === '--run-dir') opts.runDir = next();
    else if (a === '--older-than') opts.olderThanDays = parseInt(next(), 10);
    else if (a === '--keep-min') opts.keepMin = parseInt(next(), 10);
    else if (a === '--apply' || a === '--yes') { opts.dryRun = false; opts.yes = true; }
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: retention [options]

Prune old per-run output directories AND their DB rows (findings/ports/http_probes/
screenshots/risk_scores/runs). Runs younger than --older-than or falling into the
--keep-min newest per tool are kept.

Options:
  --db <path>          scan SQLite DB (default: scan.db)
  --run-dir <path>     base run-output dir (default: runs)
  --older-than <days>  prune runs older than N days (default: 30)
  --keep-min <N>       keep at least N newest runs per tool (default: 3)
  --apply, --yes       actually delete (default: dry-run only)

Examples:
  retention --older-than 60                       # dry-run
  retention --older-than 60 --keep-min 5 --apply  # delete
`);
}

function deleteDirRecursive(dirPath: string): void {
  if (!fs.existsSync(dirPath)) return;
  fs.rmSync(dirPath, { recursive: true, force: true });
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  const db = openDb(opts.db);
  const rows = db.raw
    .prepare('SELECT id, tool, started_at FROM runs ORDER BY id')
    .all() as RunRow[];
  const now = new Date().toISOString();
  const prunable = runsToPrune(rows, {
    olderThanDays: opts.olderThanDays,
    now,
    keepMinPerTool: opts.keepMin,
  });

  console.error(`${rows.length} total runs · ${prunable.length} prunable ` +
    `(older than ${opts.olderThanDays}d, keep ${opts.keepMin} newest per tool)`);
  if (prunable.length === 0) { db.close(); return; }

  for (const r of prunable) {
    const dir = path.resolve(opts.runDir, String(r.id));
    const exists = fs.existsSync(dir);
    console.error(`  #${r.id}  ${r.tool}  ${r.started_at}  ${exists ? 'has dir' : 'no dir'}  ${dir}`);
  }

  if (opts.dryRun) {
    console.error('\ndry-run. Re-run with --apply to delete.');
    db.close();
    return;
  }

  const del = db.raw.prepare('DELETE FROM runs WHERE id = ?');
  const delRisk = db.raw.prepare('DELETE FROM risk_scores WHERE run_id = ?');
  const delFindings = db.raw.prepare('DELETE FROM findings WHERE run_id = ?');
  const delPorts = db.raw.prepare('DELETE FROM ports WHERE run_id = ?');
  const delHttp = db.raw.prepare('DELETE FROM http_probes WHERE run_id = ?');
  const delShots = db.raw.prepare('DELETE FROM screenshots WHERE run_id = ?');

  const tx = db.raw.transaction((ids: number[]) => {
    for (const id of ids) {
      delRisk.run(id);
      delFindings.run(id);
      delPorts.run(id);
      delHttp.run(id);
      delShots.run(id);
      del.run(id);
    }
  });
  tx(prunable.map((r) => r.id));

  let removed = 0;
  for (const r of prunable) {
    const dir = path.resolve(opts.runDir, String(r.id));
    if (fs.existsSync(dir)) { deleteDirRecursive(dir); removed++; }
  }
  console.error(`\ndeleted ${prunable.length} runs from DB + ${removed} directories from ${opts.runDir}/`);
  db.close();
}

main();
