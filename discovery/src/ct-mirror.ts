#!/usr/bin/env -S node --loader tsx
// ct-mirror: local Certificate Transparency mirror driven by scrape-ct-log.
// Forward-only: init records the current tree_size for each configured log
// shard; update pulls entries with entry_number > last_entry_id, parses the
// DER cert, filters SAN/CN against scope suffixes, and enqueues NEW
// scope-matched host names into scan.db's scan_queue.
//
// Subcommands:
//   init <label> <log-url>            Register a shard; baseline = current STH
//   update                            Pull delta for every shard, filter, enqueue
//   shards                            List configured shards + progress
//   query [--suffix s]                Query the local mirror
//   dedupe-scan                       (No-op stub; ct_names UNIQUE handles it)
//
// Env:
//   CT_DB          path to CT mirror sqlite   (default: ct.db in cwd)
//   SCAN_DB        path to scan sqlite         (default: ../scan/scan.db)
//   SCOPE_TXT      path to scope.txt           (default: ../scan/scope.txt)
//   SCRAPE_BIN     scrape-ct-log binary        (default: scrape-ct-log on PATH)
//   CT_MAX_ENTRIES     cap per-shard per-update  (default: 500000; safety net)
//   CT_CHUNK_ENTRIES   scrape-ct-log call size    (default: 20000; keeps the
//                      intermediate JSON file under Node's ~512MB string limit)
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import {
  parseEntry, scopedMatches, normaliseSuffix,
  type ScrapeEnvelope,
} from './lib/ct-mirror.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCHEMA_PATH = path.join(__dirname, 'lib', 'schema-ct.sql');

function resolveEnv(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function openCtDb(): Database.Database {
  const p = resolveEnv('CT_DB', 'ct.db');
  const db = new Database(p);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  db.pragma('foreign_keys = ON');
  db.exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  return db;
}

function openScanDb(): Database.Database | null {
  const p = resolveEnv('SCAN_DB', path.resolve(__dirname, '..', '..', 'scan', 'scan.db'));
  if (!fs.existsSync(p)) {
    console.error(`warn: scan DB not found at ${p} — enqueue step will be skipped`);
    return null;
  }
  const db = new Database(p);
  db.pragma('busy_timeout = 5000');
  return db;
}

function loadScopeSuffixes(): string[] {
  const p = resolveEnv('SCOPE_TXT', path.resolve(__dirname, '..', '..', 'scan', 'scope.txt'));
  if (!fs.existsSync(p)) {
    console.error(`FATAL: scope file not found at ${p}`);
    process.exit(1);
  }
  const suffixes: string[] = [];
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const s = normaliseSuffix(line);
    if (s) suffixes.push(s);
  }
  if (!suffixes.length) {
    console.error(`FATAL: no DNS suffixes found in ${p}`);
    process.exit(1);
  }
  return suffixes;
}

function fetchSth(logUrl: string, timeoutMs = 15000): { tree_size: number; timestamp: number } {
  const url = logUrl.replace(/\/+$/, '') + '/ct/v1/get-sth';
  // spawn curl to keep the wrapper dependency-free (fetch is fine too but this
  // matches how the rest of the discovery/ tools handle timeouts).
  const res = spawnSync('curl', ['-sS', '--max-time', String(Math.ceil(timeoutMs / 1000)), url], {
    encoding: 'utf8',
  });
  if (res.status !== 0) throw new Error(`get-sth failed: ${res.stderr || res.stdout}`);
  const json = JSON.parse(res.stdout);
  if (typeof json.tree_size !== 'number') throw new Error(`bad get-sth response: ${res.stdout.slice(0, 200)}`);
  return { tree_size: json.tree_size, timestamp: json.timestamp };
}

function runScrape(logUrl: string, start: number, count: number): ScrapeEnvelope {
  const bin = resolveEnv('SCRAPE_BIN', 'scrape-ct-log');
  const tmp = path.join(process.env.TMPDIR ?? '/tmp', `ct-scrape-${process.pid}-${Date.now()}.json`);
  // Per-chunk wall-clock cap. scrape-ct-log can hang indefinitely on a stalled
  // upstream (CT log server flaking or rate-limiting mid-stream). Without this,
  // one bad chunk parks the whole systemd unit — the ct-mirror.service ran for
  // a week that way with a single scrape-ct-log child alive but producing nothing.
  const timeoutMs = parseInt(resolveEnv('CT_SCRAPE_TIMEOUT_MS', '600000'), 10);
  try {
    const args = ['-s', String(start), '-n', String(count), '-o', tmp, logUrl];
    const res = spawnSync(bin, args, {
      stdio: ['ignore', 'ignore', 'inherit'],
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
    });
    if (res.error && (res.error as NodeJS.ErrnoException).code === 'ETIMEDOUT') {
      throw new Error(`${bin} timed out after ${timeoutMs}ms fetching ${count} entries from ${start}`);
    }
    if (res.signal) throw new Error(`${bin} killed by signal ${res.signal} (likely CT_SCRAPE_TIMEOUT_MS=${timeoutMs} exceeded)`);
    if (res.status !== 0) throw new Error(`${bin} exited ${res.status}`);
    const raw = fs.readFileSync(tmp, 'utf8');
    return JSON.parse(raw) as ScrapeEnvelope;
  } finally {
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
  }
}

interface ShardRow {
  label: string;
  log_url: string;
  baseline_tree_size: number;
  last_entry_id: number;
  updated_at: string;
}

function initCmd(label: string, logUrl: string): void {
  const db = openCtDb();
  const sth = fetchSth(logUrl);
  const now = new Date().toISOString();
  const stmt = db.prepare(`
    INSERT INTO ct_shards(label, log_url, baseline_tree_size, last_entry_id, updated_at)
    VALUES(@label, @log_url, @baseline, @last, @at)
    ON CONFLICT(label) DO NOTHING
  `);
  const info = stmt.run({
    label, log_url: logUrl,
    baseline: sth.tree_size,
    // last = tree_size - 1 so the first update() pulls only new entries (>= tree_size),
    // not everything in the log.
    last: sth.tree_size - 1,
    at: now,
  });
  if (info.changes === 0) {
    console.error(`shard '${label}' already registered — no change`);
    const existing = db.prepare('SELECT * FROM ct_shards WHERE label = ?').get(label) as ShardRow;
    console.error(`  log_url=${existing.log_url}`);
    console.error(`  baseline=${existing.baseline_tree_size} last=${existing.last_entry_id}`);
  } else {
    console.error(`registered '${label}' at baseline tree_size=${sth.tree_size}`);
  }
  db.close();
}

function shardsCmd(): void {
  const db = openCtDb();
  const rows = db.prepare('SELECT * FROM ct_shards ORDER BY label').all() as ShardRow[];
  if (!rows.length) { console.error('no shards registered'); db.close(); return; }
  console.log('LABEL                LAST_ENTRY   BASELINE     DELTA        UPDATED_AT');
  for (const r of rows) {
    const delta = r.last_entry_id - r.baseline_tree_size + 1;
    console.log(
      `${r.label.padEnd(20)} ${String(r.last_entry_id).padStart(11)} ${String(r.baseline_tree_size).padStart(11)} ${String(delta).padStart(11)}  ${r.updated_at}`,
    );
    console.log(`  ${r.log_url}`);
  }
  db.close();
}

interface UpdateStats {
  shard: string;
  fetched: number;
  parsed: number;
  parseFailures: number;
  scopeMatched: number;
  newHostsForScan: number;
  newDomainsAdded: number;
  newLastEntryId: number;
}

// Atomically union `hosts` into the newline-separated file at `filePath`,
// skipping anything already present in `filePath` or in `phantomsPath`
// (phantoms.txt is the graveyard maintained by refresh.ts). Returns how many
// hosts were actually added. tmp-file + rename keeps concurrent readers safe.
function mergeIntoDomainsTxt(
  filePath: string,
  phantomsPath: string,
  hosts: Iterable<string>,
): number {
  const phantoms = fs.existsSync(phantomsPath)
    ? new Set(fs.readFileSync(phantomsPath, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean))
    : new Set<string>();
  const existing = fs.existsSync(filePath)
    ? new Set(fs.readFileSync(filePath, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean))
    : new Set<string>();
  let added = 0;
  for (const raw of hosts) {
    const h = raw.trim().toLowerCase();
    if (!h || phantoms.has(h) || existing.has(h)) continue;
    existing.add(h);
    added++;
  }
  if (added > 0) {
    const sorted = [...existing].sort();
    const tmp = filePath + '.tmp';
    fs.writeFileSync(tmp, sorted.join('\n') + '\n');
    fs.renameSync(tmp, filePath);
  }
  return added;
}

function updateShardOnce(
  db: Database.Database,
  scanDb: Database.Database | null,
  shard: ShardRow,
  suffixes: readonly string[],
  maxEntries: number,
  chunkSize: number,
): UpdateStats {
  const stats: UpdateStats = {
    shard: shard.label, fetched: 0, parsed: 0, parseFailures: 0,
    scopeMatched: 0, newHostsForScan: 0, newDomainsAdded: 0,
    newLastEntryId: shard.last_entry_id,
  };
  const sth = fetchSth(shard.log_url);
  const startCursor = shard.last_entry_id + 1;
  const totalAvailable = sth.tree_size - startCursor;
  if (totalAvailable <= 0) return stats;
  const totalToFetch = Math.min(totalAvailable, maxEntries);
  console.error(`  ${shard.label}: fetching ${totalToFetch} entries starting at ${startCursor} (log head=${sth.tree_size}, chunk=${chunkSize})`);

  const insertEntry = db.prepare(`
    INSERT OR IGNORE INTO ct_entries(log_shard, entry_id, seen_at, sct_at, issuer_o, cn, cert_der_sha256)
    VALUES(@shard, @id, @seen, @sct, @issuer, @cn, @sha)
  `);
  const insertName = db.prepare(`
    INSERT OR IGNORE INTO ct_names(log_shard, entry_id, dns_name, is_wildcard, matched_suffix, first_seen_at)
    VALUES(@shard, @id, @name, @wild, @suf, @seen)
  `);
  const upsertHistory = db.prepare(`
    INSERT INTO ct_name_history(dns_name, first_seen_at, first_log_shard, first_entry_id, sighting_count)
    VALUES(@name, @seen, @shard, @id, 1)
    ON CONFLICT(dns_name) DO UPDATE SET
      sighting_count = sighting_count + 1,
      first_seen_at = CASE WHEN @seen < first_seen_at THEN @seen ELSE first_seen_at END,
      first_log_shard = CASE WHEN @seen < first_seen_at THEN @shard ELSE first_log_shard END,
      first_entry_id  = CASE WHEN @seen < first_seen_at THEN @id    ELSE first_entry_id  END
  `);
  const updateShard = db.prepare('UPDATE ct_shards SET last_entry_id = ?, updated_at = ? WHERE label = ?');

  const seenAt = new Date().toISOString();
  const enqueueSet = new Set<string>();
  let cursor = startCursor;
  const endExclusive = startCursor + totalToFetch;

  // Chunked pull: each scrape-ct-log invocation writes a temp JSON file we
  // slurp with fs.readFileSync. Node's V8 caps a single string at ~512 MB
  // (0x1fffffe8 chars), which a 500K-entry Argon/Nimbus batch easily exceeds.
  // Iterating in windows of `chunkSize` keeps every intermediate file well
  // under that limit and also lets us update last_entry_id after each chunk
  // — so a crash mid-run resumes from the last completed chunk, not from
  // the shard's original baseline.
  while (cursor < endExclusive) {
    const want = Math.min(chunkSize, endExclusive - cursor);
    const env = runScrape(shard.log_url, cursor, want);
    stats.fetched += env.entries.length;

    let highest = cursor - 1;
    const tx = db.transaction(() => {
      for (const raw of env.entries) {
        try {
          const parsed = parseEntry(raw);
          stats.parsed++;
          if (parsed.entryId > highest) highest = parsed.entryId;
          const matches = scopedMatches(parsed, suffixes);
          if (!matches.length) continue;
          insertEntry.run({
            shard: shard.label, id: parsed.entryId, seen: seenAt, sct: parsed.sctAt,
            issuer: parsed.issuerO, cn: parsed.cn, sha: parsed.certDerSha256,
          });
          for (const m of matches) {
            insertName.run({
              shard: shard.label, id: parsed.entryId, name: m.dnsName,
              wild: m.isWildcard ? 1 : 0, suf: m.matchedSuffix, seen: parsed.sctAt,
            });
            upsertHistory.run({
              name: m.dnsName, seen: parsed.sctAt, shard: shard.label, id: parsed.entryId,
            });
            stats.scopeMatched++;
            // Only enqueue non-wildcard scan targets — '*.foo.example' isn't a
            // resolvable host on its own; the scan pipeline discovers real hosts
            // under it via CT + dns-brute in subsequent runs.
            if (!m.isWildcard) enqueueSet.add(m.dnsName);
          }
        } catch (err) {
          stats.parseFailures++;
          if (stats.parseFailures <= 3) {
            console.error(`  parse-fail entry ${raw.entry_number}: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
      }
      updateShard.run(highest, seenAt, shard.label);
    });
    tx();
    stats.newLastEntryId = highest;
    // Advance cursor by what the log actually returned, not what we asked for
    // — a shorter tail is possible near the STH edge.
    if (env.entries.length === 0) break;
    cursor = highest + 1;
    if (env.entries.length < want) {
      // Log gave us fewer than we asked for — likely at head. Stop this shard;
      // next timer run will pick up from `cursor` naturally.
      break;
    }
  }

  if (scanDb && enqueueSet.size) {
    const now = new Date().toISOString();
    const enqueue = scanDb.prepare(`
      INSERT OR IGNORE INTO scan_queue(target, priority, status, queued_at, attempts)
      VALUES(?, 10, 'pending', ?, 0)
    `);
    const etx = scanDb.transaction((hosts: string[]) => {
      let n = 0;
      for (const h of hosts) if (enqueue.run(h, now).changes) n++;
      return n;
    });
    stats.newHostsForScan = etx([...enqueueSet]);
  }

  if (enqueueSet.size) {
    const domainsPath = resolveEnv('DOMAINS_TXT', path.resolve(__dirname, '..', 'domains.txt'));
    const phantomsPath = resolveEnv('PHANTOMS_TXT', path.resolve(__dirname, '..', 'phantoms.txt'));
    try {
      stats.newDomainsAdded = mergeIntoDomainsTxt(domainsPath, phantomsPath, enqueueSet);
    } catch (err) {
      console.error(`  domains.txt merge failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return stats;
}

function updateCmd(): void {
  const db = openCtDb();
  const scanDb = openScanDb();
  const suffixes = loadScopeSuffixes();
  const maxPerShard = parseInt(resolveEnv('CT_MAX_ENTRIES', '500000'), 10);
  const chunkSize = parseInt(resolveEnv('CT_CHUNK_ENTRIES', '20000'), 10);
  const shards = db.prepare('SELECT * FROM ct_shards ORDER BY label').all() as ShardRow[];
  if (!shards.length) {
    console.error('no shards registered; run `ct-mirror init <label> <log-url>` first');
    db.close();
    scanDb?.close();
    process.exit(1);
  }
  console.error(`scope: ${suffixes.length} suffix(es); shards: ${shards.length}; max per shard: ${maxPerShard}; chunk: ${chunkSize}`);
  for (const s of shards) {
    try {
      const stats = updateShardOnce(db, scanDb, s, suffixes, maxPerShard, chunkSize);
      console.error(
        `  ${s.label}: fetched=${stats.fetched} parsed=${stats.parsed} parse-fail=${stats.parseFailures} ` +
        `scope-matched=${stats.scopeMatched} enqueued=${stats.newHostsForScan} ` +
        `domains+=${stats.newDomainsAdded} → last_entry=${stats.newLastEntryId}`,
      );
    } catch (err) {
      console.error(`  ${s.label}: FAILED — ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  db.close();
  scanDb?.close();
}

function queryCmd(argv: string[]): void {
  const db = openCtDb();
  let suffix: string | null = null;
  let since: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--suffix') suffix = argv[++i]!;
    else if (argv[i] === '--since') since = argv[++i]!;
  }
  let sql = 'SELECT dns_name, first_seen_at, first_log_shard, first_entry_id, sighting_count FROM ct_name_history WHERE 1=1';
  const params: unknown[] = [];
  if (suffix) {
    const clean = suffix.replace(/^\./, '').toLowerCase();
    sql += ' AND (dns_name = ? OR dns_name LIKE ?)';
    params.push(clean, `%.${clean}`);
  }
  if (since) { sql += ' AND first_seen_at >= ?'; params.push(since); }
  sql += ' ORDER BY first_seen_at DESC LIMIT 200';
  const rows = db.prepare(sql).all(...params) as {
    dns_name: string; first_seen_at: string; first_log_shard: string;
    first_entry_id: number; sighting_count: number;
  }[];
  for (const r of rows) {
    console.log(`${r.first_seen_at}  ${r.dns_name}  (log=${r.first_log_shard} #${r.first_entry_id}, sightings=${r.sighting_count})`);
  }
  console.error(`\n${rows.length} name(s)`);
  db.close();
}

function usage(): void {
  console.error(`Usage: ct-mirror <command> [args...]

Local Certificate Transparency mirror. Uses scrape-ct-log to poll one or
more CT log shards, extracts DNS names from SAN/CN, filters against
scope.txt, and enqueues newly-observed scope-matched hosts into scan.db.

Commands:
  init <label> <log-url>   Register a shard; baseline = current tree_size
  update                   Pull delta for every shard; parse, filter, enqueue
  shards                   List configured shards + progress
  query [--suffix s] [--since iso]
                           Query the local name history

Environment:
  CT_DB           CT mirror sqlite (default: ct.db)
  SCAN_DB         scan sqlite (default: ../scan/scan.db)
  SCOPE_TXT       scope.txt path (default: ../scan/scope.txt)
  SCRAPE_BIN      scrape-ct-log binary (default: on PATH)
  CT_MAX_ENTRIES  per-shard per-update cap (default: 500000)

Examples:
  # Seed one Google Argon 2026h1 shard, then run a first update:
  ct-mirror init argon2026h1 https://ct.googleapis.com/logs/us1/argon2026h1/
  ct-mirror update

  # Every fresh cert issued for '.nisz.hu' since baseline:
  ct-mirror query --suffix nisz.hu

  # New arrivals in the last hour:
  ct-mirror query --since "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"
`);
}

function main(): void {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === '-h' || cmd === '--help') { usage(); process.exit(cmd ? 0 : 1); }
  const rest = argv.slice(1);
  if (cmd === 'init') {
    if (rest.length < 2) { console.error('usage: ct-mirror init <label> <log-url>'); process.exit(1); }
    initCmd(rest[0]!, rest[1]!);
  } else if (cmd === 'update') {
    updateCmd();
  } else if (cmd === 'shards') {
    shardsCmd();
  } else if (cmd === 'query') {
    queryCmd(rest);
  } else {
    console.error(`unknown command: ${cmd}\n`);
    usage();
    process.exit(1);
  }
}

main();
