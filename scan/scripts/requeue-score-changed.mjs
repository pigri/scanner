#!/usr/bin/env node
// After a risk recompute, find every target whose latest score differs from
// its previous score and push it into report_queue so scan-report-worker
// re-renders its per-host .md file. Called from scan-risk.service after the
// risk step. Cheap (~ms on a 5k-target corpus) — no scoring or DNS work.
import Database from '../node_modules/better-sqlite3/lib/index.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const scanDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const db = new Database(path.join(scanDir, 'scan.db'));

const rows = db.prepare(`
  WITH ranked AS (
    SELECT target, score, computed_at,
           ROW_NUMBER() OVER (PARTITION BY target ORDER BY computed_at DESC) rn
    FROM risk_scores
  )
  SELECT a.target
  FROM ranked a
  LEFT JOIN ranked b ON b.target = a.target AND b.rn = 2
  WHERE a.rn = 1 AND (b.score IS NULL OR a.score != b.score)
`).all();

const upsert = db.prepare(`
  INSERT INTO report_queue(target, priority, status, queued_at)
  VALUES(?, 0, 'pending', ?)
  ON CONFLICT(target) DO UPDATE SET
    status = 'pending',
    queued_at = excluded.queued_at,
    started_at = NULL, finished_at = NULL, run_id = NULL,
    attempts = 0, error = NULL
`);
const now = new Date().toISOString();
const tx = db.transaction(() => { for (const r of rows) upsert.run(r.target, now); });
tx();
console.log(`score-changed → ${rows.length} target(s) requeued for report re-render`);
db.close();
