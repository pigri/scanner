import type Database from 'better-sqlite3';

// Some tools key risk_scores by scheme-prefixed URL (http://host, https://host)
// in addition to the bare FQDN. Those URL rows carry no findings and always have
// a bare-host twin, so they're duplicates that inflate the target list/counts.
// This fragment filters them out of target-level queries.
export const NO_URL = `target NOT LIKE 'http://%' AND target NOT LIKE 'https://%'`;

const isUrlTarget = (t: string): boolean => t.startsWith('http://') || t.startsWith('https://');

// risk_latest holds one row per non-URL target: the risk_scores row with the
// greatest computed_at, ties broken by the highest id. Queries below walk
// idx_risk_target_ca_score (target, computed_at, score); the id tie-break needs a
// small temp b-tree per target, so they are index-assisted, not index-only.

/**
 * Fill risk_latest from risk_scores when it is empty. Idempotent and safe against
 * concurrent openers: the work runs in one IMMEDIATE transaction that re-checks
 * emptiness once it holds the write lock.
 */
export function backfillRiskLatest(raw: Database.Database): void {
  if (raw.prepare('SELECT 1 FROM risk_latest LIMIT 1').get()) return;
  if (!raw.prepare('SELECT 1 FROM risk_scores LIMIT 1').get()) return;
  raw.transaction(() => {
    if (raw.prepare('SELECT 1 FROM risk_latest LIMIT 1').get()) return;
    raw.exec(`
      INSERT OR IGNORE INTO risk_latest(target, score, created_at, updated_at)
      SELECT t.target, r.score,
             (SELECT MIN(computed_at) FROM risk_scores WHERE target = t.target),
             r.computed_at
      FROM (SELECT DISTINCT target FROM risk_scores WHERE ${NO_URL}) t
      JOIN risk_scores r ON r.id = (
        SELECT id FROM risk_scores WHERE target = t.target
        ORDER BY computed_at DESC, id DESC LIMIT 1
      )
    `);
  }).immediate();
}

/**
 * Prepared upsert: run(target, score, createdAt, updatedAt). ON CONFLICT(target)
 * resolves against the PRIMARY KEY of a fresh table and against the unique index
 * on the hand-made live table.
 *
 * - 'keep-created' (a new run): created_at is set on first insert only.
 * - 'reset-created' (a refresh after deletes): created_at is overwritten, because
 *   the caller re-derived it from the risk_scores that remain.
 */
export function upsertRiskLatest(
  raw: Database.Database,
  mode: 'keep-created' | 'reset-created' = 'keep-created',
): Database.Statement<[string, number, string, string]> {
  const createdAt = mode === 'reset-created' ? ', created_at = excluded.created_at' : '';
  return raw.prepare(
    `INSERT INTO risk_latest(target, score, created_at, updated_at) VALUES(?, ?, ?, ?)
     ON CONFLICT(target) DO UPDATE SET score = excluded.score, updated_at = excluded.updated_at${createdAt}`
  ) as Database.Statement<[string, number, string, string]>;
}

/** Re-derive each target from the risk_scores that remain; drop it if none. */
export function refreshRiskLatest(raw: Database.Database, targets: Iterable<string>): void {
  const newest = raw.prepare(
    'SELECT score, computed_at FROM risk_scores WHERE target = ? ORDER BY computed_at DESC, id DESC LIMIT 1'
  );
  const oldest = raw.prepare('SELECT MIN(computed_at) m FROM risk_scores WHERE target = ?');
  const del = raw.prepare('DELETE FROM risk_latest WHERE target = ?');
  const up = upsertRiskLatest(raw, 'reset-created');
  for (const t of targets) {
    if (isUrlTarget(t)) continue;
    const row = newest.get(t) as { score: number; computed_at: string } | undefined;
    if (!row) { del.run(t); continue; }
    const first = (oldest.get(t) as { m: string }).m;
    up.run(t, row.score, first, row.computed_at);
  }
}

export interface RiskRow { target: string; score: number; breakdownJson: string }

/** Insert a run's scores and upsert risk_latest in one write transaction. */
export function recordRiskScores(raw: Database.Database, rows: RiskRow[], now: string, runId: number): void {
  const insert = raw.prepare(
    'INSERT INTO risk_scores(target, score, breakdown_json, computed_at, run_id) VALUES(?, ?, ?, ?, ?)'
  );
  const upsert = upsertRiskLatest(raw);
  raw.transaction((batch: RiskRow[]) => {
    for (const row of batch) {
      insert.run(row.target, row.score, row.breakdownJson, now, runId);
      if (!isUrlTarget(row.target)) upsert.run(row.target, row.score, now, now);
    }
  }).immediate(rows);
}

/**
 * Delete the risk_scores of these runs and refresh the targets they touched.
 * Call inside an IMMEDIATE (write) transaction: it starts with a DELETE, so the
 * write lock is taken up front and busy_timeout applies.
 */
export function deleteRiskScoresForRuns(raw: Database.Database, runIds: number[]): void {
  const targets = new Set<string>();
  const del = raw.prepare('DELETE FROM risk_scores WHERE run_id = ? RETURNING target');
  for (const id of runIds) {
    for (const r of del.all(id) as { target: string }[]) targets.add(r.target);
  }
  refreshRiskLatest(raw, targets);
}
