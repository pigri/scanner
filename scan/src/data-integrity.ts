#!/usr/bin/env -S node --loader tsx
// data-integrity: check + auto-heal common drift between the pipeline's
// derived tables. Idempotent, safe to re-run.
//
// Checks:
//   1. scan_queue.done rows with no report_queue row → enqueue for reports
//   2. cves rollup drift  — findings with cve NOT NULL not represented in cves
//      → run cve-rollup on the missing chunk
//   3. discovered_urls entries whose target isn't in http_probes (dead-link)
//      → warn (no auto-heal — the URL might be real for a host httpx never saw)
//   4. certificates fingerprint_sha256 IS NULL rows → warn (testssl-parse gap)
//
// --dry-run reports without writing.
import path from 'node:path';
import Database from 'better-sqlite3';
import { spawnSync } from 'node:child_process';

function usage(): void {
  console.error(`Usage: data-integrity --sqlite <path> [--dry-run] [--auto-heal]

Sanity-check derived tables against source tables. --auto-heal fixes:
  * scan_queue done rows missing from report_queue → enqueue
  * findings.cve rows missing from cves table → re-run cve-rollup

--dry-run reports only. Default is report + auto-heal.
`);
}

interface CheckResult {
  name: string;
  count: number;
  detail?: string[];
  healed?: number;
  action?: string;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let dbPath = 'scan.db';
  let dryRun = false;
  let autoHeal = true;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h' || a === '--help') { usage(); process.exit(0); }
    if (a === '--sqlite' || a === '--db') dbPath = argv[++i]!;
    else if (a === '--dry-run') { dryRun = true; autoHeal = false; }
    else if (a === '--no-heal') autoHeal = false;
    else if (a === '--auto-heal') autoHeal = true;
  }

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  const results: CheckResult[] = [];

  // ─── Check 1: scan_queue done → report_queue orphans ────────────────────
  const orphans = db.prepare(
    `SELECT target FROM scan_queue WHERE status='done'
     AND target NOT IN (SELECT target FROM report_queue)
     ORDER BY target`
  ).all() as { target: string }[];
  const r1: CheckResult = { name: 'orphan scan_queue.done without report_queue row', count: orphans.length };
  if (orphans.length && !dryRun && autoHeal) {
    const now = new Date().toISOString();
    const ins = db.prepare(
      `INSERT OR IGNORE INTO report_queue(target, priority, status, queued_at)
       VALUES(?, 0, 'pending', ?)`
    );
    const tx = db.transaction((ts: { target: string }[]) => {
      let n = 0;
      for (const o of ts) if (ins.run(o.target, now).changes) n++;
      return n;
    });
    r1.healed = tx(orphans);
    r1.action = `enqueued ${r1.healed} row(s) into report_queue (pending)`;
  }
  r1.detail = orphans.slice(0, 12).map((o) => o.target);
  results.push(r1);

  // ─── Check 2: findings.cve rows missing from the cves rollup ────────────
  const missingCveFindings = db.prepare(
    `SELECT COUNT(*) c FROM findings f
     WHERE f.cve IS NOT NULL AND f.cve != ''
       AND NOT EXISTS (
         SELECT 1 FROM cves c
         WHERE c.target = f.target AND c.cve_id = f.cve
       )`
  ).get() as { c: number };
  const r2: CheckResult = { name: 'findings.cve rows not represented in cves rollup', count: missingCveFindings.c };
  if (missingCveFindings.c && !dryRun && autoHeal) {
    // Re-run cve-rollup once — it's UPSERT so re-running is safe.
    const wd = path.dirname(path.resolve(dbPath));
    const cvePath = path.join(path.dirname(new URL(import.meta.url).pathname), 'cve-rollup.ts');
    console.error(`  → running cve-rollup to backfill: ${cvePath}`);
    const proc = spawnSync('npx', ['tsx', cvePath, '--sqlite', dbPath], { cwd: wd, stdio: 'inherit' });
    r2.action = `cve-rollup exit ${proc.status}`;
    const after = db.prepare(
      `SELECT COUNT(*) c FROM findings f
       WHERE f.cve IS NOT NULL AND f.cve != ''
         AND NOT EXISTS (SELECT 1 FROM cves c WHERE c.target = f.target AND c.cve_id = f.cve)`
    ).get() as { c: number };
    r2.healed = missingCveFindings.c - after.c;
  }
  results.push(r2);

  // ─── Check 3: discovered_urls with no http_probes match (warn only) ─────
  const deadUrls = db.prepare(
    `SELECT DISTINCT target FROM discovered_urls
     WHERE target NOT IN (SELECT DISTINCT target FROM http_probes)`
  ).all() as { target: string }[];
  results.push({ name: 'discovered_urls targets never seen by httpx', count: deadUrls.length, detail: deadUrls.slice(0, 8).map((r) => r.target) });

  // ─── Check 4: certificates without fingerprint (testssl-parse gap) ──────
  const noFp = db.prepare(`SELECT COUNT(*) c FROM certificates WHERE fingerprint_sha256 IS NULL`).get() as { c: number };
  results.push({ name: 'certificates rows without fingerprint_sha256', count: noFp.c });

  // ─── Check 5: cves.cve_id rows still unenriched from NVD ────────────────
  const unenrichedNvd = db.prepare(
    `SELECT COUNT(*) c FROM cves WHERE cve_id GLOB 'CVE-*' AND enriched_at IS NULL`
  ).get() as { c: number };
  results.push({ name: 'CVEs from NVD ID space not yet enriched (drains via nightly timer)', count: unenrichedNvd.c });

  // ─── Print summary ──────────────────────────────────────────────────────
  console.log(`# data-integrity report (db=${path.resolve(dbPath)}) ${dryRun ? '[dry-run]' : ''}`);
  console.log('');
  for (const r of results) {
    const tag = r.count === 0 ? 'OK' : (r.healed !== undefined ? 'HEALED' : 'DRIFT');
    console.log(`[${tag.padEnd(6)}]  ${r.count.toString().padStart(6)}  ${r.name}`);
    if (r.action) console.log(`              → ${r.action}`);
    if (r.detail && r.detail.length) for (const d of r.detail) console.log(`              · ${d}`);
    if (r.detail && r.detail.length < r.count) console.log(`              · (+${r.count - r.detail.length} more)`);
    console.log('');
  }

  db.close();
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
