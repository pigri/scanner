import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { makeQueue, type QueueEntry, type ClaimedRow, type QueueStats, type QueueOps } from './queue.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface RunArgs { [k: string]: unknown }
export interface RunFinish {
  targetsCount?: number;
  findingsCount?: number;
  notes?: string;
  at?: string;
}

export interface PortRow {
  target: string;
  ip?: string | null;
  port: number;
  protocol: string;
  service?: string | null;
  product?: string | null;
  version?: string | null;
  tunnel?: string | null;
  extrainfo?: string | null;
}

export interface HttpProbeRow {
  target: string;
  url: string;
  status_code?: number | null;
  title?: string | null;
  web_server?: string | null;
  tech?: string[] | null;
  content_length?: number | null;
  hash_body?: string | null;
}

export interface FindingInput {
  tool: string;
  target: string;
  category?: string | null;
  severity?: string | null;
  title: string;
  cve?: string | null;
  matched_at?: string | null;
  meta?: unknown;
  // 1 when the scanner suspects a false positive it couldn't rule out (e.g.
  // catch-all-200 responder). Meta should carry body_preview + body_status
  // so the reviewer can look at what the responder actually served.
  needsReview?: boolean;
}

export interface FindingRow {
  id: number;
  tool: string;
  target: string;
  category: string | null;
  severity: string | null;
  title: string;
  cve: string | null;
  matched_at: string | null;
  meta_json: string | null;
  seen_at: string;
  run_id: number | null;
  needs_review: number;
}

// Queue types + the generic queue factory live in ./queue; re-export the types
// so existing imports (`import { QueueEntry } from './db.js'`) keep working.
export type { QueueEntry, ClaimedRow, QueueStats, QueueOps };

export interface ScreenshotRow {
  target: string;
  url: string;
  path: string;
  status?: number | null;
  title?: string | null;
}

export interface DiscoveredUrlRow {
  target: string;
  url: string;
  method?: string | null;
  source: string;               // katana | gau | waybackurls | manual
  status?: number | null;
  content_type?: string | null;
}

export interface DnsRecordRow {
  target: string;
  name: string;
  type: string;
  value: string;
  ttl?: number | null;
}

export interface CertInput {
  target: string;
  port: number | null;
  certIndex: number;
  commonName: string | null;
  san: string[];
  issuer: string | null;
  notBefore: string | null;
  notAfter: string | null;
  keyAlgo: string | null;
  keySize: number | null;
  sigAlgo: string | null;
  serial: string | null;
  fingerprintSha256: string | null;
  selfSigned: boolean;
}

export interface Db {
  raw: Database.Database;
  close(): void;
  startRun(tool: string, args: RunArgs, at?: string): number;
  finishRun(id: number, finish: RunFinish): void;
  insertPort(row: PortRow, at: string, runId: number | null): void;
  insertHttpProbe(row: HttpProbeRow, at: string, runId: number | null): void;
  insertFinding(row: FindingInput, at: string, runId: number | null): void;
  insertScreenshot(row: ScreenshotRow, at: string, runId: number | null): void;
  insertCertificate(row: CertInput, at: string, runId: number | null): void;
  insertDiscoveredUrl(row: DiscoveredUrlRow, at: string, runId: number | null): void;
  insertDnsRecord(row: DnsRecordRow, at: string, runId: number | null): void;
  findingsSince(startIso: string): FindingRow[];
  findingsBetween(startIso: string, endIso: string): FindingRow[];
  countBySeverity(): { severity: string; n: number }[];
  // Two work queues. `scanQueue`/`reportQueue` are the general interface; the
  // top-level enqueueMany/claimBatch/markDone/markFailed/queueStats delegate to
  // scanQueue for backward compatibility.
  scanQueue: QueueOps;
  reportQueue: QueueOps;
  enqueueMany(entries: readonly QueueEntry[], atIso: string): number;
  claimBatch(size: number, atIso: string): ClaimedRow[];
  markDone(id: number, runId: number | null, atIso: string): void;
  markFailed(id: number, error: string, atIso: string): void;
  queueStats(): QueueStats;
}

function loadSchema(): string {
  return fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
}

export function openDb(dbPath: string): Db {
  const raw = new Database(dbPath);
  raw.pragma('foreign_keys = ON');
  // WAL + busy_timeout let multiple scanner/report workers write concurrently:
  // SQLite serializes writers (one at a time) and busy_timeout makes a blocked
  // writer wait-and-retry instead of erroring with SQLITE_BUSY. WAL is persisted
  // in the file; busy_timeout + synchronous are per-connection so set on open.
  raw.pragma('journal_mode = WAL');
  raw.pragma('busy_timeout = 5000');
  raw.pragma('synchronous = NORMAL');
  raw.exec(loadSchema());
  // Idempotent migrations for databases that predate a column addition.
  // ADD COLUMN in SQLite errors if the column already exists; probe first.
  const findingsCols = new Set(
    (raw.prepare('PRAGMA table_info(findings)').all() as { name: string }[]).map((r) => r.name)
  );
  if (!findingsCols.has('needs_review')) {
    raw.exec("ALTER TABLE findings ADD COLUMN needs_review INTEGER NOT NULL DEFAULT 0");
  }
  // Create the partial index unconditionally (idempotent via IF NOT EXISTS).
  // Runs after the column is guaranteed to exist — either from schema.sql on
  // fresh DBs or the migration above on legacy ones.
  raw.exec("CREATE INDEX IF NOT EXISTS idx_findings_review ON findings(needs_review) WHERE needs_review = 1");

  const startRunStmt = raw.prepare(
    'INSERT INTO runs(tool, started_at, args_json) VALUES(?, ?, ?)'
  );
  const finishRunStmt = raw.prepare(
    'UPDATE runs SET finished_at = ?, targets_count = ?, findings_count = ?, notes = ? WHERE id = ?'
  );
  const insertPortStmt = raw.prepare(`
    INSERT INTO ports(target, ip, port, protocol, service, product, version, tunnel, extrainfo, seen_at, run_id)
    VALUES(@target, @ip, @port, @protocol, @service, @product, @version, @tunnel, @extrainfo, @seen_at, @run_id)
  `);
  const insertHttpStmt = raw.prepare(`
    INSERT INTO http_probes(target, url, status_code, title, web_server, tech_json, content_length, hash_body, seen_at, run_id)
    VALUES(@target, @url, @status_code, @title, @web_server, @tech_json, @content_length, @hash_body, @seen_at, @run_id)
  `);
  const insertFindingStmt = raw.prepare(`
    INSERT INTO findings(tool, target, category, severity, title, cve, matched_at, meta_json, seen_at, run_id, needs_review)
    VALUES(@tool, @target, @category, @severity, @title, @cve, @matched_at, @meta_json, @seen_at, @run_id, @needs_review)
  `);
  const insertShotStmt = raw.prepare(`
    INSERT INTO screenshots(target, url, path, status, title, seen_at, run_id)
    VALUES(@target, @url, @path, @status, @title, @seen_at, @run_id)
  `);
  const insertCertStmt = raw.prepare(`
    INSERT OR IGNORE INTO certificates(target, port, cert_index, common_name, san_json, issuer,
      not_before, not_after, key_algo, key_size, sig_algo, serial, fingerprint_sha256, self_signed, seen_at, run_id)
    VALUES(@target, @port, @cert_index, @common_name, @san_json, @issuer,
      @not_before, @not_after, @key_algo, @key_size, @sig_algo, @serial, @fingerprint_sha256, @self_signed, @seen_at, @run_id)
  `);
  const insertUrlStmt = raw.prepare(`
    INSERT OR IGNORE INTO discovered_urls(target, url, method, source, status, content_type, seen_at, run_id)
    VALUES(@target, @url, @method, @source, @status, @content_type, @seen_at, @run_id)
  `);
  const insertDnsStmt = raw.prepare(`
    INSERT OR IGNORE INTO dns_records(target, name, type, value, ttl, seen_at, run_id)
    VALUES(@target, @name, @type, @value, @ttl, @seen_at, @run_id)
  `);

  const findingsSinceStmt = raw.prepare(
    'SELECT * FROM findings WHERE seen_at >= ? ORDER BY seen_at'
  );
  const findingsBetweenStmt = raw.prepare(
    'SELECT * FROM findings WHERE seen_at >= ? AND seen_at <= ? ORDER BY seen_at'
  );
  const countBySevStmt = raw.prepare(
    "SELECT COALESCE(severity, 'unknown') AS severity, COUNT(*) AS n FROM findings GROUP BY severity ORDER BY n DESC"
  );

  const scanQueue = makeQueue(raw, 'scan_queue');
  const reportQueue = makeQueue(raw, 'report_queue');

  return {
    raw,
    scanQueue,
    reportQueue,
    close(): void { raw.close(); },
    startRun(tool, args, at): number {
      const info = startRunStmt.run(tool, at ?? new Date().toISOString(), JSON.stringify(args));
      return Number(info.lastInsertRowid);
    },
    finishRun(id, f): void {
      finishRunStmt.run(
        f.at ?? new Date().toISOString(),
        f.targetsCount ?? 0,
        f.findingsCount ?? 0,
        f.notes ?? null,
        id
      );
    },
    insertPort(row, at, runId): void {
      insertPortStmt.run({
        target: row.target, ip: row.ip ?? null,
        port: row.port, protocol: row.protocol,
        service: row.service ?? null, product: row.product ?? null,
        version: row.version ?? null, tunnel: row.tunnel ?? null,
        extrainfo: row.extrainfo ?? null,
        seen_at: at, run_id: runId,
      });
    },
    insertHttpProbe(row, at, runId): void {
      insertHttpStmt.run({
        target: row.target, url: row.url,
        status_code: row.status_code ?? null,
        title: row.title ?? null,
        web_server: row.web_server ?? null,
        tech_json: row.tech ? JSON.stringify(row.tech) : null,
        content_length: row.content_length ?? null,
        hash_body: row.hash_body ?? null,
        seen_at: at, run_id: runId,
      });
    },
    insertFinding(row, at, runId): void {
      insertFindingStmt.run({
        tool: row.tool, target: row.target,
        category: row.category ?? null,
        severity: row.severity ?? null,
        title: row.title,
        cve: row.cve ?? null,
        matched_at: row.matched_at ?? null,
        meta_json: row.meta !== undefined ? JSON.stringify(row.meta) : null,
        seen_at: at, run_id: runId,
        needs_review: row.needsReview ? 1 : 0,
      });
    },
    insertScreenshot(row, at, runId): void {
      insertShotStmt.run({
        target: row.target, url: row.url, path: row.path,
        status: row.status ?? null, title: row.title ?? null,
        seen_at: at, run_id: runId,
      });
    },
    insertCertificate(row, at, runId): void {
      insertCertStmt.run({
        target: row.target, port: row.port, cert_index: row.certIndex,
        common_name: row.commonName, san_json: JSON.stringify(row.san),
        issuer: row.issuer, not_before: row.notBefore, not_after: row.notAfter,
        key_algo: row.keyAlgo, key_size: row.keySize, sig_algo: row.sigAlgo,
        serial: row.serial, fingerprint_sha256: row.fingerprintSha256,
        self_signed: row.selfSigned ? 1 : 0, seen_at: at, run_id: runId,
      });
    },
    insertDiscoveredUrl(row, at, runId): void {
      insertUrlStmt.run({
        target: row.target, url: row.url,
        method: row.method ?? null, source: row.source,
        status: row.status ?? null, content_type: row.content_type ?? null,
        seen_at: at, run_id: runId,
      });
    },
    insertDnsRecord(row, at, runId): void {
      insertDnsStmt.run({
        target: row.target, name: row.name, type: row.type, value: row.value,
        ttl: row.ttl ?? null, seen_at: at, run_id: runId,
      });
    },
    findingsSince(startIso): FindingRow[] {
      return findingsSinceStmt.all(startIso) as FindingRow[];
    },
    findingsBetween(startIso, endIso): FindingRow[] {
      return findingsBetweenStmt.all(startIso, endIso) as FindingRow[];
    },
    countBySeverity(): { severity: string; n: number }[] {
      return countBySevStmt.all() as { severity: string; n: number }[];
    },
    // Backward-compat delegations to the scan queue.
    enqueueMany(entries, atIso): number { return scanQueue.enqueueMany(entries, atIso); },
    claimBatch(size, atIso): ClaimedRow[] { return scanQueue.claimBatch(size, atIso); },
    markDone(id, runId, atIso): void { scanQueue.markDone(id, runId, atIso); },
    markFailed(id, error, atIso): void { scanQueue.markFailed(id, error, atIso); },
    queueStats(): QueueStats { return scanQueue.stats(); },
  };
}
