// Cost of the partial-run watermark on a copy of a real scan DB.
//   BENCH_DB=/path/to/bench-scan-copy.db npx vitest bench test/bench/watermark.bench.ts
// Skipped when BENCH_DB is unset. The file must be a COPY: its basename has to start
// with `bench-`, because the setup writes partial_stamps rows into it.
import fs from 'node:fs';
import path from 'node:path';
import { bench, describe } from 'vitest';
import { openDb } from '../../src/lib/db.js';
import { currentFindingRowsSelect, currentFindingsSelect, watermarkSelect } from '../../src/lib/current-findings.js';
import { targetAggSql } from '../../src/lib/target-agg.js';

const file = process.env.BENCH_DB;
// Judge the resolved file, so a bench-named symlink to a live DB is refused.
if (file) {
  let real: string;
  try { real = fs.realpathSync(file); } catch (e) { throw new Error(`BENCH_DB cannot be resolved: ${file}: ${e instanceof Error ? e.message : String(e)}`); }
  if (!path.basename(real).startsWith('bench-')) throw new Error(`BENCH_DB must be a copy named bench-*: ${real}`);
}

type Case = 'before' | 'empty' | 'realistic' | 'stress';
const SEVEN = 7;

describe.skipIf(!file)('watermark', () => {
  const t0 = performance.now();
  const db = openDb(file!);
  console.log(`first open: ${(performance.now() - t0).toFixed(0)} ms`);
  const raw = db.raw;
  let loaded: Case | null = null;

  const mark = (sql: string) => raw.exec(`INSERT OR IGNORE INTO partial_stamps (tool, seen_at, run_id) ${sql}`);
  function load(c: Case): void {
    if (loaded === c) return;
    raw.exec('DELETE FROM partial_stamps');
    if (c === 'realistic') {
      mark(`SELECT DISTINCT f.tool, f.seen_at, f.run_id FROM findings f JOIN runs r ON r.id = f.run_id
            WHERE r.tool = 'nuclei' AND (r.finished_at IS NULL
              OR (julianday(r.finished_at) - julianday(r.started_at)) * 86400 >= 900)`);
    } else if (c === 'stress') {
      mark(`SELECT DISTINCT f.tool, f.seen_at, f.run_id FROM findings f
            WHERE f.run_id IS NOT NULL AND f.tool IN
              (SELECT tool FROM findings GROUP BY tool ORDER BY COUNT(*) DESC LIMIT ${SEVEN})`);
    }
    loaded = c;
    const n = (raw.prepare('SELECT COUNT(*) n FROM partial_stamps').get() as { n: number }).n;
    console.log(`case ${c}: ${n} markers`);
  }

  const drain = (sql: string): number => { let n = 0; for (const _ of raw.prepare(sql).iterate()) n++; return n; };
  const queries: [string, (partial: boolean) => string][] = [
    ['watermarkSelect', (partial) => watermarkSelect({ coverage: true, partial })],
    ['current rows (risk)', (partial) => currentFindingRowsSelect({ coverage: true, partial })],
    ['targetAggSql', (partial) => targetAggSql({ coverage: true, partial })],
    ['currentFindingsSelect', (partial) => currentFindingsSelect({ coverage: true, partial })],
  ];
  const opts = { iterations: 10, warmupIterations: 1, time: 0, warmupTime: 0 };
  for (const [name, sql] of queries) {
    for (const c of ['before', 'empty', 'realistic', 'stress'] as Case[]) {
      bench(`${name} / ${c}`, () => { drain(sql(c !== 'before')); }, { ...opts, setup: () => load(c === 'before' ? 'empty' : c) });
    }
  }
});
