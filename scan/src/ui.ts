#!/usr/bin/env -S node --loader tsx
// Read-only web UI for the scan + recon databases.
//
// Serves a small single-page dashboard backed by JSON endpoints. Every DB is
// opened `readonly` and only SELECT statements are issued — nothing here can
// mutate scan.db / recon.db. Safe to point at a live, actively-written WAL DB.
//
//   npm run ui                              # defaults: scan.db + ../discovery/recon.db, :8787
//   npm run ui -- --sqlite scan.db --recon-db ../discovery/recon.db --port 8787
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { resolveDbArg } from './lib/db-arg.js';
import { NEWS_FIRSTS_SQL } from './lib/news-sql.js';

interface Opts {
  scanDb: string;
  reconDb: string | null;
  port: number;
  host: string;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    scanDb: resolveDbArg(argv),
    reconDb: null,
    port: Number(process.env.UI_PORT) || 8787,
    host: process.env.UI_HOST || '127.0.0.1',
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--recon-db') opts.reconDb = next();
    else if (a === '--port' || a === '-p') opts.port = Number(next());
    else if (a === '--host') opts.host = next();
  }
  if (opts.reconDb === null) {
    const guess = path.resolve(process.cwd(), '../discovery/recon.db');
    if (fs.existsSync(guess)) opts.reconDb = guess;
  }
  return opts;
}

const opts = parseArgs(process.argv);

if (!fs.existsSync(opts.scanDb)) {
  console.error(`scan DB not found: ${opts.scanDb}`);
  process.exit(1);
}

// Open a DB for reading only.
//
// Reading a *live* WAL database requires SQLite to build/maintain the WAL
// shared-memory index (-shm). A `readonly: true` handle can't do that, and
// `PRAGMA query_only = ON` also blocks it — both fail with "attempt to write a
// readonly database" whenever no writer is currently holding the -shm. So we
// open read-write (the -shm/-wal maintenance is read-machinery, not a data
// mutation) and instead enforce read-only at the application layer: every
// statement must be a SELECT/WITH/PRAGMA/EXPLAIN, and `exec` is disabled. That
// gives a hard "no content mutation" guarantee that is still WAL-correct.
//
// If the file is on a read-only mount, the rw open throws at construction and we
// fall back to a strict readonly handle (fine for a static, checkpointed DB).
const READ_STMT = /^\s*(select|with|pragma|explain)\b/i;

function openReadonly(file: string): Database.Database {
  let db: Database.Database;
  try {
    db = new Database(file, { fileMustExist: true });
  } catch {
    db = new Database(file, { readonly: true, fileMustExist: true });
  }
  db.pragma('busy_timeout = 3000');
  const nativePrepare = db.prepare.bind(db);
  db.prepare = ((sql: string) => {
    if (!READ_STMT.test(sql)) throw new Error(`read-only: refused non-SELECT statement`);
    return nativePrepare(sql);
  }) as typeof db.prepare;
  db.exec = (() => {
    throw new Error('read-only: exec() disabled');
  }) as typeof db.exec;
  return db;
}

const scan = openReadonly(opts.scanDb);
const recon =
  opts.reconDb && fs.existsSync(opts.reconDb) ? openReadonly(opts.reconDb) : null;

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// Some tools key risk_scores by scheme-prefixed URL (http://host, https://host)
// in addition to the bare FQDN. Those URL rows carry no findings and always have
// a bare-host twin, so they're duplicates that inflate the target list/counts.
// This fragment filters them out of target-level queries.
const NO_URL = `target NOT LIKE 'http://%' AND target NOT LIKE 'https://%'`;

function tableExists(db: Database.Database, name: string): boolean {
  return !!db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
    .get(name);
}

// A "logical finding" collapses every historical sighting of the same issue
// (target · tool · severity · category · title) into one row, tracking when it
// was first and last seen and how many times it was observed. A finding is
// RESOLVED when a later run of the same tool on the same host stopped reporting
// it — i.e. its last_seen predates that tool's most recent scan of the host;
// otherwise it's OPEN (still present in the latest scan).
interface LogicalFinding {
  target: string;
  tool: string;
  severity: string | null;
  category: string | null;
  title: string;
  cve: string | null;
  first_seen: string;
  last_seen: string;
  occ: number;
  resolved: number; // 1 = resolved, 0 = open
}
let logicalCache: { rows: LogicalFinding[]; at: number } | null = null;
function logicalFindings(): LogicalFinding[] {
  const now = Date.now();
  if (logicalCache && now - logicalCache.at < 60000) return logicalCache.rows;
  const rows = scan
    .prepare(
      `WITH logical AS MATERIALIZED (
         SELECT target, tool, severity, category, title, MAX(cve) cve,
                MIN(seen_at) first_seen, MAX(seen_at) last_seen, COUNT(*) occ
         FROM findings GROUP BY target, tool, severity, category, title),
       toollast AS MATERIALIZED (
         SELECT target, tool, MAX(seen_at) tmax FROM findings GROUP BY target, tool)
       SELECT l.target, l.tool, l.severity, l.category, l.title, l.cve,
              l.first_seen, l.last_seen, l.occ,
              CASE WHEN l.last_seen < tl.tmax THEN 1 ELSE 0 END resolved
       FROM logical l JOIN toollast tl ON tl.target = l.target AND tl.tool = l.tool`,
    )
    .all() as LogicalFinding[];
  logicalCache = { rows, at: now };
  return rows;
}

// Per-target aggregate: latest risk score, first/last assessment, finding
// severity tallies and CVE count. Computed once with GROUP-BY passes and cached
// briefly — risk_scores can be very large (hourly snapshots), so recomputing it
// on every pagination/filter request was the source of slow paging.
interface TargetRow {
  target: string; score: number; created_at: string | null; updated_at: string | null;
  critical: number; high: number; medium: number; low: number; info: number;
  findings: number; cves: number;
}
let targetsCache: { rows: TargetRow[]; at: number } | null = null;
function targetRows(): TargetRow[] {
  const now = Date.now();
  if (targetsCache && now - targetsCache.at < 60000) return targetsCache.rows;
  const rows = scan
    .prepare(
      `WITH latest AS MATERIALIZED (
         SELECT target, score FROM (SELECT target, score, MAX(computed_at) FROM risk_scores WHERE ${NO_URL} GROUP BY target)),
       rstime AS MATERIALIZED (
         SELECT target, MIN(computed_at) created_at, MAX(computed_at) updated_at
         FROM risk_scores WHERE ${NO_URL} GROUP BY target),
       agg AS MATERIALIZED (
         SELECT target,
           SUM(severity='critical') critical, SUM(severity='high') high,
           SUM(severity='medium') medium, SUM(severity='low') low, SUM(severity='info') info,
           COUNT(*) findings,
           SUM(CASE WHEN cve IS NOT NULL AND cve!='' THEN 1 ELSE 0 END) cves
         FROM findings GROUP BY target)
       SELECT latest.target target, latest.score score, rstime.created_at, rstime.updated_at,
         COALESCE(agg.critical,0) critical, COALESCE(agg.high,0) high, COALESCE(agg.medium,0) medium,
         COALESCE(agg.low,0) low, COALESCE(agg.info,0) info,
         COALESCE(agg.findings,0) findings, COALESCE(agg.cves,0) cves
       FROM latest JOIN rstime ON rstime.target = latest.target
       LEFT JOIN agg ON agg.target = latest.target`,
    )
    .all() as TargetRow[];
  targetsCache = { rows, at: now };
  return rows;
}

// Parse a CVSS v2 or v3 vector into a flat map (v3's `CVSS:3.1/` prefix stripped).
function parseVec(v: string): Record<string, string> {
  const o: Record<string, string> = {};
  for (const p of v.replace(/^CVSS:3\.\d+\//, '').split('/')) {
    const [k, val] = p.split(':');
    if (k && val) o[k] = val;
  }
  return o;
}
// Heuristic kill-chain roles for a CVE from its CVSS vector:
//   foothold = network + unauthenticated + real confidentiality/integrity impact
//   privesc  = needs some privilege OR is local, and gains integrity / changes scope
//   impact   = high availability impact (DoS) or high confidentiality (data)
function cveRoles(vec: string): string[] {
  const o = parseVec(vec);
  const unauth = o.PR === 'N' || o.Au === 'N';
  const hiC = o.C === 'H' || o.C === 'C';
  const hiI = o.I === 'H' || o.I === 'C';
  const hiA = o.A === 'H' || o.A === 'C';
  const roles: string[] = [];
  if (o.AV === 'N' && unauth && (hiC || hiI)) roles.push('foothold');
  if ((o.PR === 'L' || o.PR === 'H' || o.AV === 'L') && (hiI || o.S === 'C')) roles.push('privesc');
  if (hiA || hiC) roles.push('impact');
  return roles;
}

// Is a finding a genuine leaked secret / credential exposure? Category-curated
// (categories are cleaner than title keywords, which false-match e.g. TLS
// "extended master secret" / CSRF tokens). Covers verified exposed API keys,
// cloud keys, and config files that carry credentials.
const SECRET_CATS = new Set([
  'google-api-key', 'aws-detect', 'firebase-config-exposure',
  'wordpress-accessible-wpconfig', 'wordpress:wp-config-leak',
]);
const SECRET_EXPOSURE = /^exposure-(\.env|\.git|\.svn|\.htaccess|\.htpasswd|wp-config|id_rsa|docker-compose|secrets|credentials)/;
function isSecretFinding(f: { tool: string; category: string | null }): boolean {
  if (f.tool === 'gapi-key-check' || f.tool === 'vendor-key-enrich') return true;
  const cat = (f.category ?? '').toLowerCase();
  if (!cat) return false;
  if (cat.startsWith('gapi:')) return true;
  if (SECRET_CATS.has(cat)) return true;
  if (SECRET_EXPOSURE.test(cat)) return true;
  return false;
}
// Mask a secret value: keep a recognisable head/tail, hide the middle.
function maskSecret(s: string): string {
  const v = String(s).trim();
  return v.length > 12 ? `${v.slice(0, 6)}…${v.slice(-4)}` : v;
}
// A short, MASKED evidence string for a secret finding, from its meta_json.
function secretEvidence(meta: Record<string, unknown> | null, title: string): string {
  if (meta) {
    if (typeof meta['key_prefix'] === 'string') {
      const d = typeof meta['detail'] === 'string' ? ` · ${meta['detail']}` : '';
      return `${meta['key_prefix']}…${d}`;
    }
    const ext = meta['extracted-results'];
    if (Array.isArray(ext) && ext.length) return ext.slice(0, 2).map((x) => maskSecret(String(x))).join(', ');
    if (Array.isArray(meta['exposed_defines'])) {
      const d = meta['exposed_defines'] as string[];
      const impact = typeof meta['impact'] === 'string' ? ` · ${meta['impact']}` : '';
      return d.slice(0, 5).join(', ') + (d.length > 5 ? ` +${d.length - 5}` : '') + impact;
    }
    if (typeof meta['snippet'] === 'string') return maskSecret(String(meta['snippet']).replace(/\s+/g, ' ')).slice(0, 70);
    if (typeof meta['detail'] === 'string') return meta['detail'] as string;
  }
  // fallback: the redacted hint many titles already carry, e.g. "(AIzaSy…Xxsw)"
  const m = title.match(/\(([^()]*…[^()]*)\)\s*$/);
  return m ? m[1]! : '';
}

// ---- API handlers -----------------------------------------------------------

type Json = unknown;

const api: Record<string, (q: URLSearchParams) => Json> = {
  overview() {
    const count = (t: string) =>
      tableExists(scan, t)
        ? (scan.prepare(`SELECT COUNT(*) c FROM ${t}`).get() as { c: number }).c
        : 0;
    const severity = scan
      .prepare(
        `SELECT severity, COUNT(*) c FROM findings GROUP BY severity`,
      )
      .all() as { severity: string | null; c: number }[];
    const sevMap: Record<string, number> = {};
    for (const s of SEVERITY_ORDER) sevMap[s] = 0;
    for (const r of severity) sevMap[r.severity ?? 'info'] = r.c;
    const ports = scan
      .prepare(
        `SELECT port, service, COUNT(DISTINCT target) c FROM ports GROUP BY port ORDER BY c DESC LIMIT 12`,
      )
      .all();
    const topRisk = scan
      .prepare(
        `SELECT target, score FROM (SELECT target, score, MAX(computed_at) FROM risk_scores WHERE ${NO_URL} GROUP BY target)
         ORDER BY score DESC, target LIMIT 10`,
      )
      .all();
    // Recently scanned hosts: last time each target produced any finding
    // (varies per host, unlike risk_scores.computed_at which is stamped in one
    // batch). Correlated subqueries run only for the 12 output rows.
    const recentTargets = scan
      .prepare(
        `SELECT t.target, t.last_scan,
           (SELECT score FROM risk_scores r WHERE r.target=t.target ORDER BY computed_at DESC LIMIT 1) score,
           (SELECT COUNT(*) FROM findings f WHERE f.target=t.target AND f.severity='critical') critical,
           (SELECT COUNT(*) FROM findings f WHERE f.target=t.target AND f.severity='high') high,
           (SELECT COUNT(*) FROM findings f WHERE f.target=t.target) findings
         FROM (SELECT target, MAX(seen_at) last_scan FROM findings GROUP BY target
               ORDER BY last_scan DESC LIMIT 12) t`,
      )
      .all();
    const queue = tableExists(scan, 'scan_queue')
      ? scan
          .prepare(`SELECT status, COUNT(*) c FROM scan_queue GROUP BY status`)
          .all()
      : [];
    // Scanner attribution: rows in `ports` per originating tool, and total
    // runs per tool. Port rows with no run_id are bucketed as '(unattributed)'.
    const portsByTool = scan
      .prepare(
        `SELECT COALESCE(r.tool, '(unattributed)') tool, COUNT(*) c
         FROM ports p LEFT JOIN runs r ON p.run_id = r.id
         GROUP BY r.tool ORDER BY c DESC`,
      )
      .all();
    const runsByTool = scan
      .prepare(`SELECT tool, COUNT(*) c FROM runs GROUP BY tool ORDER BY c DESC`)
      .all();
    // Exploitable: CVEs flagged with a known exploit available (cves.exploit=1).
    const exploitable = tableExists(scan, 'cves')
      ? (() => {
          const bySeverity: Record<string, number> = {};
          for (const s of SEVERITY_ORDER) bySeverity[s] = 0;
          for (const r of scan
            .prepare(`SELECT severity, COUNT(*) c FROM cves WHERE exploit=1 GROUP BY severity`)
            .all() as { severity: string | null; c: number }[]) {
            const k = r.severity ?? 'info';
            bySeverity[k] = (bySeverity[k] ?? 0) + r.c;
          }
          const tot = scan
            .prepare(
              `SELECT COUNT(*) issues, COUNT(DISTINCT cve_id) cves, COUNT(DISTINCT target) targets
               FROM cves WHERE exploit=1`,
            )
            .get() as { issues: number; cves: number; targets: number };
          return { issues: tot.issues, cves: tot.cves, targets: tot.targets, bySeverity };
        })()
      : null;
    return {
      counts: {
        runs: count('runs'),
        ports: count('ports'),
        http_probes: count('http_probes'),
        findings: count('findings'),
        cves: count('cves'),
        certificates: count('certificates'),
        dns_records: count('dns_records'),
        discovered_urls: count('discovered_urls'),
        screenshots: count('screenshots'),
        // Distinct hosts observed anywhere in the inventory (not just those
        // that already have a risk_score). Excludes URL-shaped rows.
        targets: (
          scan
            .prepare(
              `SELECT COUNT(*) c FROM (
                 SELECT target FROM ports        WHERE ${NO_URL}
                 UNION SELECT target FROM http_probes  WHERE ${NO_URL}
                 UNION SELECT target FROM findings     WHERE ${NO_URL}
                 UNION SELECT target FROM dns_records  WHERE ${NO_URL}
                 UNION SELECT target FROM cves         WHERE ${NO_URL}
                 UNION SELECT target FROM risk_scores  WHERE ${NO_URL}
               )`,
            )
            .get() as { c: number }
        ).c,
      },
      severity: sevMap,
      exploitable,
      topPorts: ports,
      topRisk,
      recentTargets,
      queue,
      portsByTool,
      runsByTool,
      recon: recon
        ? {
            hosts: (recon.prepare(`SELECT COUNT(*) c FROM hosts`).get() as { c: number }).c,
            ips: (recon.prepare(`SELECT COUNT(*) c FROM ips`).get() as { c: number }).c,
          }
        : null,
    };
  },

  targets(q) {
    const limit = clampInt(q.get('limit'), 100, 1, 1000);
    const offset = clampInt(q.get('offset'), 0, 0, 1e9);
    const search = (q.get('q') || '').trim().toLowerCase();
    const sevList = (q.get('severity') || '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => SEVERITY_ORDER.includes(s));
    const cve = q.get('cve'); // '1' = has ≥1 CVE, '0' = none
    const minScore = Number(q.get('minScore'));
    const maxScore = Number(q.get('maxScore'));
    const hasMin = q.get('minScore') != null && q.get('minScore') !== '' && Number.isFinite(minScore);
    const hasMax = q.get('maxScore') != null && q.get('maxScore') !== '' && Number.isFinite(maxScore);
    const sort = q.get('sort') || 'score';

    // The heavy per-target aggregate (over a now-large risk_scores) is computed
    // once and cached; all filtering/sorting/paging/faceting happens in JS so
    // pagination and filter changes are instant instead of re-scanning the DB.
    const all = targetRows();
    const base = all.filter((r) => {
      if (search && !r.target.toLowerCase().includes(search)) return false;
      if (cve === '1' && !(r.cves > 0)) return false;
      if (cve === '0' && r.cves > 0) return false;
      if (hasMin && r.score < minScore) return false;
      if (hasMax && r.score > maxScore) return false;
      return true;
    });
    const sevOf = (r: TargetRow, s: string): number =>
      s === 'critical' ? r.critical : s === 'high' ? r.high : s === 'medium' ? r.medium : s === 'low' ? r.low : r.info;
    // Severity facet: # of targets with ≥1 finding of each severity, over the
    // non-severity filters (independent of the severity selection).
    const sevCounts: Record<string, number> = {};
    for (const s of SEVERITY_ORDER) sevCounts[s] = 0;
    for (const r of base) for (const s of SEVERITY_ORDER) if (sevOf(r, s) > 0) sevCounts[s] = (sevCounts[s] ?? 0) + 1;

    const filtered = sevList.length
      ? base.filter((r) => sevList.some((s) => sevOf(r, s) > 0))
      : base;

    const cmp = (a: TargetRow, b: TargetRow): number => {
      const byNum = (k: keyof TargetRow) => (b[k] as number) - (a[k] as number) || b.score - a.score || a.target.localeCompare(b.target);
      switch (sort) {
        case 'critical': return byNum('critical');
        case 'high': return byNum('high');
        case 'findings': return byNum('findings');
        case 'cves': return byNum('cves');
        case 'updated': return (b.updated_at || '').localeCompare(a.updated_at || '') || a.target.localeCompare(b.target);
        case 'created': return (b.created_at || '').localeCompare(a.created_at || '') || a.target.localeCompare(b.target);
        case 'target': return a.target.localeCompare(b.target);
        default: return b.score - a.score || a.target.localeCompare(b.target);
      }
    };
    filtered.sort(cmp);
    return { rows: filtered.slice(offset, offset + limit), total: filtered.length, limit, offset, sevCounts };
  },

  target(q) {
    const t = (q.get('t') || '').trim();
    if (!t) return { error: 'missing target' };
    const risk = scan
      .prepare(
        `SELECT score, breakdown_json, computed_at FROM risk_scores
         WHERE target=? ORDER BY computed_at DESC LIMIT 1`,
      )
      .get(t) as { score: number; breakdown_json: string; computed_at: string } | undefined;
    const span = scan
      .prepare(
        `SELECT MIN(computed_at) created_at, MAX(computed_at) updated_at FROM risk_scores WHERE target=?`,
      )
      .get(t) as { created_at: string | null; updated_at: string | null };
    // `tools` = comma-separated list of scanners (from runs.tool) that ever
    // observed this (port, protocol) on this target — so rustscan-only /
    // naabu-only findings are visible in the detail view.
    const ports = scan
      .prepare(
        `SELECT p.port, p.protocol,
                MAX(p.service)  service,
                MAX(p.product)  product,
                MAX(p.version)  version,
                MAX(p.tunnel)   tunnel,
                (SELECT GROUP_CONCAT(t, ',') FROM (
                   SELECT DISTINCT COALESCE(r2.tool, '?') t
                   FROM ports p2 LEFT JOIN runs r2 ON p2.run_id = r2.id
                   WHERE p2.target = p.target AND p2.port = p.port AND p2.protocol = p.protocol
                   ORDER BY t
                )) tools
         FROM ports p
         WHERE p.target=? GROUP BY p.port, p.protocol ORDER BY p.port`,
      )
      .all(t);
    const http = scan
      .prepare(
        `SELECT url, status_code, title, web_server, tech_json FROM http_probes
         WHERE target=? GROUP BY url ORDER BY url`,
      )
      .all(t);
    // Logical findings for this host, with open/resolved status.
    const findings = scan
      .prepare(
        `WITH logical AS (
           SELECT tool, severity, category, title, MAX(cve) cve,
                  MIN(seen_at) first_seen, MAX(seen_at) last_seen, COUNT(*) occ
           FROM findings WHERE target=@t GROUP BY tool, severity, category, title),
         toollast AS (
           SELECT tool, MAX(seen_at) tmax FROM findings WHERE target=@t GROUP BY tool)
         SELECT l.tool, l.severity, l.category, l.title, l.cve, l.first_seen, l.last_seen, l.occ,
                CASE WHEN l.last_seen < tl.tmax THEN 1 ELSE 0 END resolved
         FROM logical l JOIN toollast tl ON tl.tool = l.tool
         ORDER BY resolved ASC, CASE l.severity
           WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
           WHEN 'low' THEN 3 ELSE 4 END, l.tool LIMIT 800`,
      )
      .all({ t }) as { resolved: number }[];
    const findingsSummary = {
      open: findings.filter((f) => !f.resolved).length,
      resolved: findings.filter((f) => f.resolved).length,
    };
    const cves = tableExists(scan, 'cves')
      ? scan
          .prepare(
            `SELECT cve_id, severity, cvss, tools, exploit, description FROM cves
             WHERE target=? ORDER BY cvss DESC, cve_id LIMIT 300`,
          )
          .all(t)
      : [];
    const certs = tableExists(scan, 'certificates')
      ? scan
          .prepare(
            `SELECT common_name, san_json, issuer, not_after, key_algo, key_size, self_signed
             FROM certificates WHERE target=? ORDER BY not_after`,
          )
          .all(t)
      : [];
    const dns = tableExists(scan, 'dns_records')
      ? scan
          .prepare(`SELECT type, value, ttl FROM dns_records WHERE target=? ORDER BY type`)
          .all(t)
      : [];
    return {
      target: t,
      created_at: span?.created_at ?? null,
      updated_at: span?.updated_at ?? null,
      risk: risk
        ? { score: risk.score, computed_at: risk.computed_at, breakdown: safeParse(risk.breakdown_json) }
        : null,
      ports,
      http,
      findings,
      findingsSummary,
      cves,
      certs,
      dns,
    };
  },

  findings(q) {
    const limit = clampInt(q.get('limit'), 100, 1, 1000);
    const offset = clampInt(q.get('offset'), 0, 0, 1e9);
    const sevList = (q.get('severity') || '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => SEVERITY_ORDER.includes(s));
    const tool = (q.get('tool') || '').trim();
    const category = (q.get('category') || '').trim();
    const search = (q.get('q') || '').trim().toLowerCase();
    const cve = q.get('cve'); // '1' = has CVE, '0' = no CVE, else any
    const since = (q.get('since') || '').trim();
    const until = (q.get('until') || '').trim();
    const status = q.get('status'); // 'open' | 'resolved' | else any
    const sort = q.get('sort') || 'severity';
    const sinceTs = /^\d{4}-\d{2}-\d{2}$/.test(since) ? `${since}T00:00:00.000Z` : '';
    const untilTs = /^\d{4}-\d{2}-\d{2}$/.test(until) ? `${until}T23:59:59.999Z` : '';

    // Everything below operates on de-duplicated LOGICAL findings (with status),
    // filtered/sorted/paged in JS so status + facets stay consistent.
    const all = logicalFindings();
    // Base predicate: everything EXCEPT the severity and status filters (those
    // two are applied on top, so their facet counts can exclude themselves).
    const base = all.filter((r) => {
      if (tool && r.tool !== tool) return false;
      if (category && r.category !== category) return false;
      if (search) {
        const hay = `${r.target}\n${r.title}\n${r.cve ?? ''}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      if (cve === '1' && !r.cve) return false;
      if (cve === '0' && r.cve) return false;
      if (sinceTs && r.last_seen < sinceTs) return false;
      if (untilTs && r.last_seen > untilTs) return false;
      return true;
    });
    const sevPred = (r: LogicalFinding) => !sevList.length || sevList.includes(r.severity ?? 'info');
    const statusPred = (r: LogicalFinding) =>
      status === 'open' ? r.resolved === 0 : status === 'resolved' ? r.resolved === 1 : true;

    // Facets: severity counts exclude the severity filter; status counts exclude
    // the status filter.
    const sevCounts: Record<string, number> = {};
    for (const s of SEVERITY_ORDER) sevCounts[s] = 0;
    for (const r of base.filter(statusPred)) { const k = r.severity ?? 'info'; sevCounts[k] = (sevCounts[k] ?? 0) + 1; }
    const statusCounts = { open: 0, resolved: 0 };
    for (const r of base.filter(sevPred)) statusCounts[r.resolved ? 'resolved' : 'open']++;

    const filtered = base.filter((r) => sevPred(r) && statusPred(r));
    const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    filtered.sort((a, b) => {
      if (sort === 'newest') return b.last_seen < a.last_seen ? -1 : b.last_seen > a.last_seen ? 1 : 0;
      if (sort === 'oldest') return a.first_seen < b.first_seen ? -1 : a.first_seen > b.first_seen ? 1 : 0;
      if (sort === 'target') return a.target < b.target ? -1 : a.target > b.target ? 1 : (b.last_seen.localeCompare(a.last_seen));
      const sr = (sevRank[a.severity ?? 'info'] ?? 4) - (sevRank[b.severity ?? 'info'] ?? 4);
      return sr !== 0 ? sr : b.last_seen.localeCompare(a.last_seen);
    });
    const rows = filtered.slice(offset, offset + limit);

    // Tool / category option lists with counts (over the whole logical set).
    const toolMap = new Map<string, number>();
    const catMap = new Map<string, number>();
    for (const r of all) {
      toolMap.set(r.tool, (toolMap.get(r.tool) || 0) + 1);
      if (r.category) catMap.set(r.category, (catMap.get(r.category) || 0) + 1);
    }
    const tools = [...toolMap].sort((a, b) => a[0].localeCompare(b[0])).map(([tool, c]) => ({ tool, c }));
    const categories = [...catMap].sort((a, b) => b[1] - a[1]).map(([category, c]) => ({ category, c }));

    return { rows, total: filtered.length, limit, offset, tools, categories, sevCounts, statusCounts };
  },

  cves(q) {
    if (!tableExists(scan, 'cves')) return { rows: [], total: 0, exploitCounts: { yes: 0, no: 0 } };
    const limit = clampInt(q.get('limit'), 100, 1, 1000);
    const offset = clampInt(q.get('offset'), 0, 0, 1e9);
    const search = (q.get('q') || '').trim();
    const exploit = q.get('exploit'); // '1' = has exploit, '0' = none
    // `base` = non-exploit clauses (reused for the exploit facet counts).
    const base: string[] = [];
    const baseArgs: unknown[] = [];
    if (search) { base.push('(cve_id LIKE ? OR target LIKE ?)'); baseArgs.push(`%${search}%`, `%${search}%`); }
    const clauses = [...base];
    const args = [...baseArgs];
    if (exploit === '1') clauses.push('exploit=1');
    else if (exploit === '0') clauses.push('(exploit=0 OR exploit IS NULL)');
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = scan
      .prepare(
        `SELECT cve_id, target, severity, cvss, tools, exploit, hit_count, last_seen
         FROM cves ${where} ORDER BY exploit DESC, cvss DESC, cve_id LIMIT ? OFFSET ?`,
      )
      .all(...args, limit, offset);
    const total = (
      scan.prepare(`SELECT COUNT(*) c FROM cves ${where}`).get(...args) as { c: number }
    ).c;
    // exploit facet counts under the search filter (independent of the exploit selection)
    const baseWhere = base.length ? `WHERE ${base.join(' AND ')}` : '';
    const ec = scan
      .prepare(
        `SELECT SUM(CASE WHEN exploit=1 THEN 1 ELSE 0 END) yes,
                SUM(CASE WHEN exploit=1 THEN 0 ELSE 1 END) no FROM cves ${baseWhere}`,
      )
      .get(...baseArgs) as { yes: number | null; no: number | null };
    return { rows, total, limit, offset, exploitCounts: { yes: Number(ec.yes || 0), no: Number(ec.no || 0) } };
  },

  // Leaked secrets: credential / API-key / secret-config exposures (curated
  // from findings, deduped to logical findings with open/resolved status).
  secrets(q) {
    const all = logicalFindings().filter(isSecretFinding);
    const type = (q.get('type') || '').trim();
    const sev = q.get('severity');
    const status = q.get('status'); // open | resolved
    const search = (q.get('q') || '').trim().toLowerCase();
    const limit = clampInt(q.get('limit'), 100, 1, 1000);
    const offset = clampInt(q.get('offset'), 0, 0, 1e9);
    const base = all.filter((f) => {
      if (type && (f.category ?? '') !== type) return false;
      if (search) {
        const hay = `${f.target}\n${f.title}\n${f.category ?? ''}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });
    const sevPred = (f: LogicalFinding) => !sev || !SEVERITY_ORDER.includes(sev) || (f.severity ?? 'info') === sev;
    const statusPred = (f: LogicalFinding) =>
      status === 'open' ? f.resolved === 0 : status === 'resolved' ? f.resolved === 1 : true;
    // facets
    const sevCounts: Record<string, number> = {};
    for (const s of SEVERITY_ORDER) sevCounts[s] = 0;
    for (const f of base.filter(statusPred)) { const k = f.severity ?? 'info'; sevCounts[k] = (sevCounts[k] ?? 0) + 1; }
    const statusCounts = { open: 0, resolved: 0 };
    for (const f of base.filter(sevPred)) statusCounts[f.resolved ? 'resolved' : 'open']++;
    // type list (over all secrets)
    const typeMap = new Map<string, number>();
    for (const f of all) { const c = f.category ?? '(none)'; typeMap.set(c, (typeMap.get(c) || 0) + 1); }
    const types = [...typeMap].sort((a, b) => b[1] - a[1]).map(([type, c]) => ({ type, c }));
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const filtered = base.filter((f) => sevPred(f) && statusPred(f)).sort((a, b) => {
      const r = (rank[a.severity ?? 'info'] ?? 4) - (rank[b.severity ?? 'info'] ?? 4);
      return r !== 0 ? r : b.last_seen.localeCompare(a.last_seen);
    });
    // Enrich the page's rows with the exposure URL + a masked evidence preview,
    // pulled from the most recent matching finding's meta_json (few rows, cheap).
    const evStmt = scan.prepare(
      `SELECT matched_at, meta_json FROM findings
       WHERE target=@target AND tool=@tool AND COALESCE(category,'')=@category AND title=@title
       ORDER BY seen_at DESC LIMIT 1`,
    );
    const rows = filtered.slice(offset, offset + limit).map((f) => {
      const row = evStmt.get({ target: f.target, tool: f.tool, category: f.category ?? '', title: f.title }) as
        | { matched_at: string | null; meta_json: string | null }
        | undefined;
      const meta = row ? (safeParse(row.meta_json ?? null) as Record<string, unknown> | null) : null;
      return { ...f, matched_at: row?.matched_at ?? null, evidence: secretEvidence(meta, f.title) };
    });
    return {
      rows,
      total: filtered.length,
      limit, offset,
      totalSecrets: all.length,
      affectedTargets: new Set(all.map((f) => f.target)).size,
      types, sevCounts, statusCounts,
    };
  },

  // Single-host attack-path analysis: hosts whose CVEs form a multi-stage chain
  // (a remote-unauth foothold CVE PLUS a privilege-escalation CVE), inferred
  // from CVSS vectors. Heuristic — see the coverage caveats returned alongside.
  attackPaths() {
    if (!tableExists(scan, 'cves')) return { chains: [], partial: 0, coverage: { vectoredCves: 0, totalCves: 0, hostsAnalyzed: 0 } };
    const totalCves = (scan.prepare(`SELECT COUNT(*) c FROM cves`).get() as { c: number }).c;
    const rows = scan
      .prepare(
        `SELECT target, cve_id, severity, cvss, nvd_cvss, exploit, nvd_vector
         FROM cves WHERE nvd_vector IS NOT NULL AND nvd_vector != '' AND ${NO_URL}`,
      )
      .all() as { target: string; cve_id: string; severity: string | null; cvss: number | null; nvd_cvss: number | null; exploit: number; nvd_vector: string }[];
    type Item = { cve: string; severity: string | null; cvss: number | null; exploit: number };
    type Host = { target: string; foothold: Item[]; privesc: Item[]; impact: Item[] };
    const hosts = new Map<string, Host>();
    for (const r of rows) {
      const roles = cveRoles(r.nvd_vector);
      if (!roles.length) continue;
      const h = hosts.get(r.target) ?? { target: r.target, foothold: [], privesc: [], impact: [] };
      const item: Item = { cve: r.cve_id, severity: r.severity, cvss: r.nvd_cvss ?? r.cvss, exploit: r.exploit };
      if (roles.includes('foothold')) h.foothold.push(item);
      if (roles.includes('privesc')) h.privesc.push(item);
      if (roles.includes('impact')) h.impact.push(item);
      hosts.set(r.target, h);
    }
    const scoreMap = new Map<string, number>();
    for (const s of scan
      .prepare(`SELECT target, score FROM (SELECT target, score, MAX(computed_at) FROM risk_scores WHERE ${NO_URL} GROUP BY target)`)
      .all() as { target: string; score: number }[]) scoreMap.set(s.target, s.score);
    const byCvss = (a: Item, b: Item) => (b.cvss ?? 0) - (a.cvss ?? 0);
    const cap = (xs: Item[]) => xs.sort(byCvss).slice(0, 12);
    const all = [...hosts.values()].map((h) => ({
      target: h.target,
      score: scoreMap.get(h.target) ?? null,
      foothold: cap(h.foothold),
      privesc: cap(h.privesc),
      impact: cap(h.impact),
      footholdN: h.foothold.length,
      privescN: h.privesc.length,
      chain: h.foothold.length > 0 && h.privesc.length > 0,
    }));
    const chains = all
      .filter((h) => h.chain)
      .sort((a, b) => (b.score ?? 0) - (a.score ?? 0) || (b.footholdN + b.privescN) - (a.footholdN + a.privescN));
    const partial = all.filter((h) => !h.chain && (h.footholdN || h.privescN)).length;
    return { chains, partial, coverage: { vectoredCves: rows.length, totalCves, hostsAnalyzed: hosts.size } };
  },

  ports(q) {
    const port = q.get('port');
    if (port) {
      const rows = scan
        .prepare(
          `SELECT p.target,
                  MAX(p.ip)      ip,
                  p.port,
                  p.protocol,
                  MAX(p.service) service,
                  MAX(p.product) product,
                  MAX(p.version) version,
                  (SELECT GROUP_CONCAT(t, ',') FROM (
                     SELECT DISTINCT COALESCE(r2.tool, '?') t
                     FROM ports p2 LEFT JOIN runs r2 ON p2.run_id = r2.id
                     WHERE p2.target = p.target AND p2.port = p.port AND p2.protocol = p.protocol
                     ORDER BY t
                  )) tools
           FROM ports p
           WHERE p.port=? GROUP BY p.target, p.port, p.protocol ORDER BY p.target LIMIT 1000`,
        )
        .all(Number(port));
      return { rows };
    }
    // Per (port, protocol): host count + scanner set that ever produced a
    // row for that (port, protocol) across ALL targets.
    const rows = scan
      .prepare(
        `SELECT p.port,
                p.protocol,
                MAX(p.service) service,
                COUNT(DISTINCT p.target) targets,
                (SELECT GROUP_CONCAT(t, ',') FROM (
                   SELECT DISTINCT COALESCE(r2.tool, '?') t
                   FROM ports p2 LEFT JOIN runs r2 ON p2.run_id = r2.id
                   WHERE p2.port = p.port AND p2.protocol = p.protocol
                   ORDER BY t
                )) tools
         FROM ports p
         GROUP BY p.port, p.protocol ORDER BY targets DESC, p.port LIMIT 200`,
      )
      .all();
    return { rows };
  },

  recon() {
    if (!recon) return { enabled: false };
    return {
      enabled: true,
      hosts: (recon.prepare(`SELECT COUNT(*) c FROM hosts`).get() as { c: number }).c,
      ips: (recon.prepare(`SELECT COUNT(*) c FROM ips`).get() as { c: number }).c,
      byCountry: recon
        .prepare(
          `SELECT country_code, country, COUNT(*) c FROM ips GROUP BY country_code ORDER BY c DESC LIMIT 15`,
        )
        .all(),
      byAsn: recon
        .prepare(
          `SELECT asn, as_name, COUNT(*) c FROM ips GROUP BY asn ORDER BY c DESC LIMIT 15`,
        )
        .all(),
      bySource: tableExists(recon, 'sources')
        ? recon
            .prepare(`SELECT source, COUNT(*) c FROM sources GROUP BY source ORDER BY c DESC`)
            .all()
        : [],
    };
  },

  // Estate subgraph for one target: host → ports / tech / CVEs / DNS peers.
  // Cytoscape element format ({ nodes:[{data}], edges:[{data}] }), mirroring
  // src/graph-export.ts but scoped to a single host so it stays small.
  graph(q) {
    if (q.get('scope') === 'global') return buildGlobalGraph(q);
    const raw = (q.get('t') || q.get('target') || '').trim();
    // Accept a bare host, or a suffix/wildcard the user might type (`*.gov.hu`,
    // `.gov.hu`) — strip a leading wildcard/dot for matching.
    const t = raw.replace(/^\*?\.?/, '');
    // The graph is a single-host subgraph, so `t` must be an EXACT known host.
    const isHost =
      !!t &&
      (
        scan
          .prepare(
            `SELECT EXISTS(
               SELECT 1 FROM ports        WHERE target=@t
               UNION ALL SELECT 1 FROM http_probes WHERE target=@t
               UNION ALL SELECT 1 FROM dns_records WHERE target=@t
               UNION ALL SELECT 1 FROM cves        WHERE target=@t
               UNION ALL SELECT 1 FROM risk_scores WHERE target=@t
             ) e`,
          )
          .get({ t }) as { e: number }
      ).e === 1;
    if (!isHost) {
      // Not an exact host → treat the input as a search and offer matches to
      // pick from (filtered by what was typed, else the highest-risk hosts).
      const latest =
        `SELECT target, score FROM (SELECT target, score, MAX(computed_at) FROM risk_scores WHERE ${NO_URL} GROUP BY target)`;
      const suggest = t
        ? scan
            .prepare(`${latest} WHERE target LIKE ? ORDER BY score DESC, target LIMIT 50`)
            .all(`%${t}%`)
        : scan.prepare(`${latest} ORDER BY score DESC, target LIMIT 25`).all();
      return { target: null, query: raw, suggest, nodes: [], edges: [] };
    }
    const nodes = new Map<string, { data: Record<string, unknown> }>();
    const edges: { data: Record<string, unknown> }[] = [];
    const addNode = (id: string, label: string, type: string, extra: Record<string, unknown> = {}) => {
      if (!nodes.has(id)) nodes.set(id, { data: { id, label, type, ...extra } });
    };
    const addEdge = (source: string, target: string, kind: string) => {
      edges.push({ data: { id: `${source}__${kind}__${target}`, source, target, kind } });
    };
    const hostId = `host:${t}`;
    addNode(hostId, t, 'host');

    for (const p of scan
      .prepare(`SELECT DISTINCT port, protocol, service FROM ports WHERE target=? ORDER BY port`)
      .all(t) as { port: number; protocol: string; service: string | null }[]) {
      const id = `port:${p.port}/${p.protocol}`;
      addNode(id, `${p.port}${p.service ? '/' + p.service : ''}`, 'port');
      addEdge(hostId, id, 'port');
    }
    for (const h of scan
      .prepare(`SELECT tech_json FROM http_probes WHERE target=? AND tech_json IS NOT NULL AND tech_json!=''`)
      .all(t) as { tech_json: string }[]) {
      for (const tech of (safeParse(h.tech_json) as string[] | null) ?? []) {
        if (!tech) continue;
        const id = `tech:${tech}`;
        addNode(id, tech, 'tech');
        addEdge(hostId, id, 'tech');
      }
    }
    if (tableExists(scan, 'cves')) {
      for (const c of scan
        .prepare(`SELECT DISTINCT cve_id, severity FROM cves WHERE target=? ORDER BY cve_id LIMIT 100`)
        .all(t) as { cve_id: string; severity: string | null }[]) {
        const id = `cve:${c.cve_id}`;
        addNode(id, c.cve_id, 'cve', { severity: c.severity ?? 'info' });
        addEdge(hostId, id, 'cve');
      }
    }
    if (tableExists(scan, 'dns_records')) {
      for (const d of scan
        .prepare(
          `SELECT DISTINCT type, value FROM dns_records WHERE target=? AND type IN ('MX','NS','CNAME') ORDER BY type`,
        )
        .all(t) as { type: string; value: string }[]) {
        const id = `dns:${d.value}`;
        addNode(id, d.value, 'dns', { rtype: d.type });
        addEdge(hostId, id, d.type.toLowerCase());
      }
    }
    return { target: t, nodes: [...nodes.values()], edges };
  },

  // News = newly-discovered findings, grouped by the day each finding was
  // FIRST seen (MIN(seen_at) per logical finding), read-only. Filterable by day
  // (YYYY-MM-DD), severity, and a free-text search over target/title/CVE.
  // A "logical finding" is keyed by (target, tool, severity, category, title)
  // so re-scans that re-observe the same issue don't re-report it as new.
  news(q) {
    const day = (q.get('day') || '').trim();
    const sev = q.get('severity');
    const search = (q.get('q') || '').trim();
    const clauses: string[] = [];
    const args: unknown[] = [];
    if (/^\d{4}-\d{2}-\d{2}$/.test(day)) {
      clauses.push(`substr(first_seen,1,10) = ?`);
      args.push(day);
    }
    if (sev && SEVERITY_ORDER.includes(sev)) {
      clauses.push('severity = ?');
      args.push(sev);
    }
    if (search) {
      clauses.push('(target LIKE ? OR title LIKE ? OR cve LIKE ?)');
      args.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const firsts = NEWS_FIRSTS_SQL;
    const rows = scan
      .prepare(
        `SELECT * FROM (${firsts}) ${where}
         ORDER BY first_seen DESC,
           CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 ELSE 4 END
         LIMIT 800`,
      )
      .all(...args);
    // New-findings count per day, for the day picker.
    const days = scan
      .prepare(
        `SELECT substr(first_seen,1,10) day, COUNT(*) c FROM (${firsts}) GROUP BY day ORDER BY day DESC`,
      )
      .all();
    return { rows, days };
  },
};

// Global infrastructure overview: ASN → shared-IP clusters (→ hosts, optional).
// Aggregated so the whole estate stays renderable. Prefers recon.db (has ASN);
// falls back to scan.db ports (host↔ip only, no ASN) when recon is absent.
function buildGlobalGraph(q: URLSearchParams): Json {
  const minShared = clampInt(q.get('min') || '2', 2, 1, 9999); // min hosts per IP to show it
  const withHosts = q.get('hosts') === '1';
  const HOST_CAP = 1500;
  let truncated = false;
  const nodes = new Map<string, { data: Record<string, unknown> }>();
  const edges: { data: Record<string, unknown> }[] = [];
  const addNode = (id: string, label: string, type: string, extra: Record<string, unknown> = {}) => {
    if (!nodes.has(id)) nodes.set(id, { data: { id, label, type, ...extra } });
  };
  const addEdge = (source: string, target: string, kind: string) => {
    const id = `${source}__${kind}__${target}`;
    if (source !== target) edges.push({ data: { id, source, target, kind } });
  };

  if (recon) {
    // ASN hubs sized by total hosts (across all their IPs, not just shared).
    const asnRows = recon
      .prepare(
        `SELECT i.asn asn, MAX(i.as_name) as_name, COUNT(DISTINCT r.host_id) hosts
         FROM resolutions r JOIN ips i ON i.ip = r.ip
         WHERE i.asn IS NOT NULL AND i.asn != ''
         GROUP BY i.asn ORDER BY hosts DESC`,
      )
      .all() as { asn: string; as_name: string | null; hosts: number }[];
    for (const a of asnRows) {
      addNode(`asn:${a.asn}`, `${a.as_name || a.asn}`, 'asn', { weight: a.hosts, asn: a.asn });
    }
    // Shared IPs (co-hosting ≥ minShared hosts) → the interesting clusters.
    const ipRows = recon
      .prepare(
        `SELECT r.ip ip, COUNT(DISTINCT r.host_id) hosts, MAX(i.asn) asn
         FROM resolutions r LEFT JOIN ips i ON i.ip = r.ip
         GROUP BY r.ip HAVING hosts >= @min ORDER BY hosts DESC LIMIT 500`,
      )
      .all({ min: minShared }) as { ip: string; hosts: number; asn: string | null }[];
    for (const ip of ipRows) {
      addNode(`ip:${ip.ip}`, `${ip.ip} (${ip.hosts})`, 'ip', { weight: ip.hosts });
      if (ip.asn) addEdge(`ip:${ip.ip}`, `asn:${ip.asn}`, 'asn');
    }
    if (withHosts && ipRows.length) {
      const rows = recon
        .prepare(
          `SELECT h.name name, r.ip ip FROM resolutions r
           JOIN hosts h ON h.id = r.host_id
           JOIN (SELECT ip FROM resolutions GROUP BY ip HAVING COUNT(DISTINCT host_id) >= @min) s
             ON s.ip = r.ip
           LIMIT ${HOST_CAP}`,
        )
        .all({ min: minShared }) as { name: string; ip: string }[];
      truncated = rows.length >= HOST_CAP;
      for (const r of rows) {
        addNode(`host:${r.name}`, r.name, 'host');
        addEdge(`host:${r.name}`, `ip:${r.ip}`, 'resolves');
      }
    }
    return {
      scope: 'global',
      source: 'recon',
      minShared,
      withHosts,
      asnCount: asnRows.length,
      sharedIpCount: ipRows.length,
      truncated,
      nodes: [...nodes.values()],
      edges,
    };
  }

  // Fallback: scan.db ports has (target, ip) but no ASN.
  const ipRows = scan
    .prepare(
      `SELECT ip, COUNT(DISTINCT target) hosts FROM ports
       WHERE ip IS NOT NULL AND ip != ''
       GROUP BY ip HAVING hosts >= @min ORDER BY hosts DESC LIMIT 500`,
    )
    .all({ min: minShared }) as { ip: string; hosts: number }[];
  for (const ip of ipRows) addNode(`ip:${ip.ip}`, `${ip.ip} (${ip.hosts})`, 'ip', { weight: ip.hosts });
  if (withHosts && ipRows.length) {
    const rows = scan
      .prepare(
        `SELECT DISTINCT p.target name, p.ip ip FROM ports p
         JOIN (SELECT ip FROM ports WHERE ip IS NOT NULL AND ip != '' GROUP BY ip HAVING COUNT(DISTINCT target) >= @min) s
           ON s.ip = p.ip
         LIMIT ${HOST_CAP}`,
      )
      .all({ min: minShared }) as { name: string; ip: string }[];
    truncated = rows.length >= HOST_CAP;
    for (const r of rows) {
      addNode(`host:${r.name}`, r.name, 'host');
      addEdge(`host:${r.name}`, `ip:${r.ip}`, 'resolves');
    }
  }
  return {
    scope: 'global',
    source: 'scan',
    minShared,
    withHosts,
    asnCount: 0,
    sharedIpCount: ipRows.length,
    truncated,
    nodes: [...nodes.values()],
    edges,
  };
}

function clampInt(v: string | null, def: number, min: number, max: number): number {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function safeParse(s: string | null): unknown {
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

// ---- HTTP server ------------------------------------------------------------

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  // Read-only: only GET is served.
  if (req.method !== 'GET') {
    res.writeHead(405, { 'content-type': 'text/plain' });
    res.end('read-only');
    return;
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(PAGE);
    return;
  }
  if (url.pathname === '/favicon.svg' || url.pathname === '/favicon.ico') {
    res.writeHead(200, { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'max-age=86400' });
    res.end(FAVICON_SVG);
    return;
  }
  if (url.pathname.startsWith('/api/')) {
    const name = url.pathname.slice(5);
    const handler = api[name];
    if (!handler) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    try {
      const body = JSON.stringify(handler(url.searchParams));
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(body);
    } catch (e) {
      console.error('[api]', name, (e as Error).stack);
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String((e as Error).message) }));
    }
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
});

server.listen(opts.port, opts.host, () => {
  console.log(`Operation Hussar UI  →  http://${opts.host}:${opts.port}`);
  console.log(`  scan db :  ${path.resolve(opts.scanDb)}  (read-only)`);
  console.log(`  recon db:  ${opts.reconDb ? path.resolve(opts.reconDb) + '  (read-only)' : '(none)'}`);
});

// ---- Brand: Operation Hussar emblem (crossed cavalry sabres + star) ----------
// Steel-blue blades, brass-gold hilts — matches the dark UI theme. Used both as
// the inline header logo and (with a dark tile) the served favicon.
// Emblem tuned for a WHITE badge: richer steel-blue blades + brass gold with a
// thin dark outline so everything stays crisp on white.
const HUSSAR_EMBLEM = `
 <defs>
  <linearGradient id="hb" x1="0" y1="1" x2="1" y2="0">
   <stop offset="0" stop-color="#2f6fce"/><stop offset="1" stop-color="#79aef0"/>
  </linearGradient>
  <linearGradient id="hg" x1="0" y1="0" x2="0" y2="1">
   <stop offset="0" stop-color="#e8ac3c"/><stop offset="1" stop-color="#b0791f"/>
  </linearGradient>
 </defs>
 <g stroke="#1d2c46" stroke-width="0.7" stroke-linejoin="round">
  <path d="M18,50 Q42,26 57,9 Q30,38 12,55 Z" fill="url(#hb)"/>
  <path d="M46,50 Q22,26 7,9 Q34,38 52,55 Z" fill="url(#hb)"/>
  <path d="M15,52.5 L9,59.5" stroke="url(#hg)" stroke-width="3.8" stroke-linecap="round"/>
  <path d="M49,52.5 L55,59.5" stroke="url(#hg)" stroke-width="3.8" stroke-linecap="round"/>
  <circle cx="15" cy="52.5" r="3.7" fill="url(#hg)"/>
  <circle cx="49" cy="52.5" r="3.7" fill="url(#hg)"/>
  <circle cx="8.8" cy="59.5" r="2.4" fill="url(#hg)"/>
  <circle cx="55.2" cy="59.5" r="2.4" fill="url(#hg)"/>
 </g>
 <path d="M32,4 l1.8,3.8 4.1,.55 -3,2.85 .85,4.1 -3.75,-2 -3.75,2 .85,-4.1 -3,-2.85 4.1,-.55 Z" fill="url(#hg)" stroke="#6b4e12" stroke-width="0.5"/>`;
const HUSSAR_TILE = `<rect x="2" y="2" width="60" height="60" rx="15" fill="#ffffff" stroke="#c9d2de" stroke-width="1.5"/>`;
const LOGO_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="Operation Hussar">${HUSSAR_TILE}<g transform="translate(32,34) scale(0.84) translate(-32,-34)">${HUSSAR_EMBLEM}</g></svg>`;
const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">${HUSSAR_TILE}<g transform="translate(32,34) scale(0.84) translate(-32,-34)">${HUSSAR_EMBLEM}</g></svg>`;

// ---- Frontend (self-contained single page) ----------------------------------

const PAGE = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Operation Hussar</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">

<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c2330; --border:#2a3140;
    --fg:#e6edf3; --dim:#8b949e; --accent:#58a6ff;
    --crit:#f85149; --high:#ff7b39; --med:#e3b341; --low:#3fb950; --info:#6e7681;
  }
  *{box-sizing:border-box}
  body{margin:0;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg)}
  a{color:var(--accent);text-decoration:none;cursor:pointer}
  a:hover{text-decoration:underline}
  header{display:flex;align-items:center;gap:16px;padding:12px 20px;border-bottom:1px solid var(--border);background:var(--panel);position:sticky;top:0;z-index:10}
  header h1{font-size:15px;margin:0;font-weight:600;letter-spacing:.3px}
  .brand{display:flex;align-items:center}
  .brand svg{height:30px;width:30px;display:block}
  header .badge{font-size:11px;color:var(--dim);border:1px solid var(--border);border-radius:10px;padding:2px 8px}
  nav{display:flex;gap:4px;margin-left:auto;flex-wrap:wrap}
  nav button{background:transparent;color:var(--dim);border:1px solid transparent;border-radius:6px;padding:6px 12px;font-size:13px;cursor:pointer}
  nav button.active{color:var(--fg);background:var(--panel2);border-color:var(--border)}
  nav button:hover{color:var(--fg)}
  main{padding:20px;max-width:1400px;margin:0 auto}
  .grid{display:grid;gap:14px}
  .cards{grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}
  .card .n{font-size:26px;font-weight:600}
  .card .l{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
  .panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px}
  .panel h2{font-size:13px;margin:0 0 12px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;font-weight:600}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
  th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.4px;position:sticky;top:53px;background:var(--panel)}
  tr:hover td{background:var(--panel2)}
  td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
  .pill{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
  .sev-critical{background:rgba(248,81,73,.18);color:var(--crit)}
  .sev-high{background:rgba(255,123,57,.18);color:var(--high)}
  .sev-medium{background:rgba(227,179,65,.18);color:var(--med)}
  .sev-low{background:rgba(63,185,80,.18);color:var(--low)}
  .sev-info{background:rgba(110,118,129,.18);color:var(--info)}
  .sevbar{display:flex;height:10px;border-radius:5px;overflow:hidden;margin-top:6px}
  .sevbar>span{display:block}
  .score{font-variant-numeric:tabular-nums;font-weight:600}
  .toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center}
  input[type=search],select{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:13px}
  input[type=search]{min-width:240px}
  .muted{color:var(--dim)}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  .pager{display:flex;gap:8px;align-items:center;margin-top:12px;color:var(--dim);font-size:13px}
  .pager button{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:5px 12px;cursor:pointer}
  .pager button:disabled{opacity:.4;cursor:default}
  .kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:13px}
  .kv .k{color:var(--dim)}
  .cols2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:820px){.cols2{grid-template-columns:1fr}}
  .loading{color:var(--dim);padding:40px;text-align:center}
  .backlink{margin-bottom:12px;display:inline-block}
  code.big{font-size:15px;color:var(--fg)}
  .gobtn{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:7px 14px;font-size:13px;cursor:pointer;font-weight:600}
  .gobtn:hover{filter:brightness(1.1)}
  .scopebtn{background:var(--panel2);color:var(--dim);border:1px solid var(--border);border-radius:6px;padding:6px 14px;font-size:13px;cursor:pointer}
  .scopebtn.on{color:#fff;background:var(--accent);border-color:var(--accent);font-weight:600}
  input[type=number]{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:6px 8px;font-size:13px}
  .pillbtn{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:6px 12px;font-size:12px;cursor:pointer}
  #cy{width:100%;height:min(70vh,640px);background:var(--bg);border:1px solid var(--border);border-radius:8px;margin:8px 0}
  .gleg{display:inline-flex;align-items:center;gap:5px;color:var(--dim);font-size:12px;text-transform:capitalize}
  .gdot{width:10px;height:10px;border-radius:50%;display:inline-block}
  .graphlink{margin-left:12px;font-size:13px}
  .nform{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
  input[type=date],input[type=text].ntitle,textarea.nbody{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:13px;font-family:inherit}
  input[type=text].ntitle{flex:1;min-width:220px}
  textarea.nbody{width:100%;resize:vertical}
  .nerr{color:var(--crit)}
  .daychip{display:inline-block;padding:3px 9px;border-radius:12px;border:1px solid var(--border);background:var(--panel2);color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums}
  .daychip.on{border-color:var(--accent);color:var(--accent)}
  .daychip.today{border-color:var(--low)}
  .st-open{background:rgba(227,179,65,.16);color:var(--med)}
  .st-resolved{background:rgba(63,185,80,.18);color:var(--low)}
  .evcell{color:var(--high);max-width:280px;display:inline-block;overflow-wrap:anywhere}
  .wcell{max-width:280px;display:inline-block;overflow-wrap:anywhere}
  .newshdr{display:flex;align-items:baseline;gap:12px;margin-bottom:10px}
  .refresh{cursor:pointer;font-size:15px;line-height:1;color:var(--accent);text-decoration:none}
  .refresh:hover{filter:brightness(1.2)}
  .pflow{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
  .pcol{flex:1;min-width:200px;background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:10px}
  .pcol-h{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px}
  .ph-foot{color:var(--high)} .ph-priv{color:var(--crit)} .ph-imp{color:var(--med)}
  .pchips{display:flex;flex-wrap:wrap;gap:6px}
  .pchip{display:inline-flex;align-items:center;gap:3px;background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:2px 7px;font-size:12px}
  .pchip-exp{color:var(--med)}
  .parrow{display:flex;align-items:center;color:var(--dim);font-size:20px;font-weight:700}
  @media(max-width:820px){.parrow{transform:rotate(90deg)}}
  .intro{padding-bottom:10px}
  .newsitem{margin-bottom:10px}
  .nhead{display:flex;align-items:center;gap:12px}
  .nday{font-variant-numeric:tabular-nums;color:var(--accent);font-size:13px;font-weight:600}
  .ntitletxt{font-weight:600;flex:1}
  .nbodytxt{margin-top:6px;white-space:pre-wrap;color:var(--fg)}
  .nmeta{margin-top:6px;font-size:11px}
  .del{color:var(--dim);font-size:12px}
  .del:hover{color:var(--crit)}
  /* ---- Mobile (phones, e.g. iPhone Pro Max ~430px) ---- */
  html,body{max-width:100%;overflow-x:hidden}
  @media(max-width:640px){
    header{gap:8px 10px;padding:9px 12px;flex-wrap:wrap}
    header h1{font-size:14px}
    header .badge{font-size:10px;padding:2px 6px}
    .brand svg{height:26px;width:26px}
    nav{margin-left:0;width:100%;flex-wrap:nowrap;overflow-x:auto;gap:2px;-webkit-overflow-scrolling:touch;scrollbar-width:none}
    nav::-webkit-scrollbar{display:none}
    nav button{white-space:nowrap;padding:6px 10px;flex:0 0 auto}
    main{padding:12px}
    .panel{padding:12px;margin-bottom:12px}
    .panel h2{font-size:12px}
    /* EVERY data table becomes a stacked card layout — no horizontal scroll.
       Each cell is prefixed with its column name via data-label. */
    table{font-size:12px}
    thead{display:none}
    table,tbody,tr,td{display:block;width:auto}
    tr{border:1px solid var(--border);border-radius:8px;padding:8px 10px;margin-bottom:8px;background:var(--panel2)}
    tr:hover td{background:transparent}
    td{border:none;padding:3px 0;white-space:normal;text-align:left;overflow-wrap:anywhere}
    td:empty{display:none}
    td::before{content:attr(data-label);display:inline-block;min-width:74px;color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.4px;margin-right:8px}
    td[data-label='']::before{content:none}
    .tcell,.evcell,.wcell{max-width:100%}
    /* filters/toolbars: let inputs shrink and fill the row */
    .toolbar{gap:6px;margin-bottom:10px}
    input[type=search]{min-width:0;width:100%;flex:1 1 100%}
    select{max-width:100%}
    .cards{grid-template-columns:repeat(auto-fill,minmax(96px,1fr));gap:10px}
    .card{padding:10px}
    .card .n{font-size:20px}
    code.big{font-size:13px;overflow-wrap:anywhere;word-break:break-all}
    #cy{height:min(58vh,420px)}
    .pcol{min-width:150px}
    .nform{flex-direction:column;align-items:stretch}
    .backlink,.graphlink{display:inline-block;margin-bottom:6px}
  }
</style>
</head>
<body>
<header>
  <span class="brand">${LOGO_SVG}</span>
  <h1>Operation Hussar <span class="muted">·</span> readonly</h1>
  <span class="badge" id="dbbadge">…</span>
  <nav id="nav"></nav>
</header>
<main id="view"><div class="loading">loading…</div></main>
<script>
const $ = (s,r=document)=>r.querySelector(s);
const el = (t,a={},...kids)=>{const e=document.createElement(t);for(const k in a){const v=a[k];if(v==null||v===false)continue;if(k==='class')e.className=v;else if(k==='html')e.innerHTML=v;else if(k.startsWith('on'))e.addEventListener(k.slice(2),v);else e.setAttribute(k,v===true?'':v);}for(const kid of kids.flat()){if(kid==null||kid===false)continue;e.append(kid.nodeType?kid:document.createTextNode(kid));}return e;};
const esc = s => (s==null?'':String(s));
const num = n => (n==null?'':Number(n).toLocaleString());
const SEV=['critical','high','medium','low','info'];
const SEVCOL={critical:'var(--crit)',high:'var(--high)',medium:'var(--med)',low:'var(--low)',info:'var(--info)'};
async function api(name,params={}){const u=new URL('/api/'+name,location.origin);for(const k in params)if(params[k]!=null&&params[k]!=='')u.searchParams.set(k,params[k]);const r=await fetch(u);if(!r.ok)throw new Error('api '+name+' '+r.status);return r.json();}
let _cyLoad;
function loadCytoscape(){if(window.cytoscape)return Promise.resolve();if(_cyLoad)return _cyLoad;_cyLoad=new Promise((res,rej)=>{const s=document.createElement('script');s.src='https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js';s.onload=()=>res();s.onerror=()=>rej(new Error('failed to load cytoscape (offline?)'));document.head.append(s);});return _cyLoad;}
function todayStr(){const d=new Date();const p=n=>String(n).padStart(2,'0');return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate());}
function sevPill(s){s=s||'info';return el('span',{class:'pill sev-'+s},s);}
function statusPill(resolved){return el('span',{class:'pill '+(resolved?'st-resolved':'st-open')},resolved?'resolved':'open');}
// Linkify canonical CVE ids to NVD; leave non-CVE identifiers (e.g. vulners
// UUIDs) as plain text.
// Link a vuln identifier. A field may hold several tokens (e.g. two CVEs).
// CVE-YYYY-NNNN → NVD; vulners-hosted ids (nmap-vulners) → vulners.com.
function vulnHref(tok){
  const m=tok.match(/^cve-(\d{4})-(\d+)$/i);
  if(m)return {label:'CVE-'+m[1]+'-'+m[2],href:'https://nvd.nist.gov/vuln/detail/CVE-'+m[1]+'-'+m[2]};
  let href;
  if(/^1337DAY-ID-/i.test(tok))href='https://vulners.com/1337day/'+encodeURIComponent(tok);
  else if(/^PACKETSTORM:/i.test(tok))href='https://vulners.com/packetstorm/'+encodeURIComponent(tok);
  else if(/^EDB-ID:/i.test(tok))href='https://vulners.com/exploitdb/'+encodeURIComponent(tok);
  else href='https://vulners.com/search?query='+encodeURIComponent(tok);
  return {label:tok,href};
}
function cveLink(id){
  if(!id)return '';
  const toks=String(id).trim().split(/[\s,]+/).filter(Boolean);
  if(!toks.length)return '';
  const kids=[];
  toks.forEach((tok,i)=>{
    if(i)kids.push(' ');
    const {label,href}=vulnHref(tok);
    kids.push(el('a',{href,target:'_blank',rel:'noopener'},label));
  });
  return el('span',{class:'mono'},...kids);
}

const TABS=[['overview','Overview'],['targets','Targets'],['graph','Graph'],['findings','Findings'],['cves','CVEs'],['secrets','Secrets'],['paths','Attack Paths'],['ports','Ports'],['recon','Recon'],['news','News']];
let current='overview';
function buildNav(){const n=$('#nav');n.innerHTML='';for(const [id,label] of TABS){n.append(el('button',{class:id===current?'active':'',onclick:()=>go(id)},label));}}
function go(tab,arg){current=tab;buildNav();history.pushState(null,'','#'+tab+(arg?'/'+encodeURIComponent(arg):''));render(tab,arg);}

const view=$('#view');
function setView(...nodes){view.innerHTML='';view.append(...nodes);}
function loading(){setView(el('div',{class:'loading'},'loading…'));}

let overviewTimer=null;
async function render(tab,arg){
  clearTimeout(overviewTimer);  // stop overview auto-refresh when leaving it
  loading();
  try{
    if(tab==='overview')return renderOverview();
    if(tab==='targets')return renderTargets();
    if(tab==='target')return renderTarget(arg);
    if(tab==='findings')return renderFindings();
    if(tab==='cves')return renderCves();
    if(tab==='ports')return renderPorts();
    if(tab==='recon')return renderRecon();
    if(tab==='graph')return renderGraph(arg);
    if(tab==='paths')return renderPaths();
    if(tab==='secrets')return renderSecrets();
    if(tab==='news')return renderNews();
  }catch(e){setView(el('div',{class:'loading'},'error: '+e.message));}
}

async function renderOverview(){
  const d=await api('overview');
  $('#dbbadge').textContent=num(d.counts.targets)+' targets · '+num(d.counts.findings)+' findings';
  const cards=el('div',{class:'grid cards'});
  const cardDefs=[['targets','Targets'],['findings','Findings'],['cves','CVEs'],['ports','Open Ports'],['http_probes','HTTP'],['certificates','Certs'],['dns_records','DNS'],['discovered_urls','URLs'],['screenshots','Shots'],['runs','Runs']];
  for(const [k,l] of cardDefs)cards.append(el('div',{class:'card'},el('div',{class:'n'},num(d.counts[k])),el('div',{class:'l'},l)));
  // severity panel
  const totalSev=SEV.reduce((a,s)=>a+(d.severity[s]||0),0)||1;
  const bar=el('div',{class:'sevbar'});
  for(const s of SEV){const w=(d.severity[s]||0)/totalSev*100;if(w>0)bar.append(el('span',{style:'width:'+w+'%;background:'+SEVCOL[s],title:s+': '+d.severity[s]}));}
  const sevRows=el('div',{class:'toolbar'});
  for(const s of SEV)sevRows.append(el('div',{},sevPill(s),' ',el('b',{},num(d.severity[s]||0))));
  const sevPanel=el('div',{class:'panel'},el('h2',{},'Findings by severity'),sevRows,bar);
  // exploitable panel (CVEs with a known exploit)
  let exploitPanel='';
  if(d.exploitable){
    const e=d.exploitable;
    const toExploit=()=>{cState={...cState,q:'',exploit:'1',offset:0};go('cves');};
    const stats=el('div',{class:'toolbar'},
      el('a',{onclick:toExploit,title:'view exploitable CVEs'},el('b',{class:'score'},num(e.issues)),' exploitable issues ▸'),
      el('div',{},el('b',{},num(e.cves)),' ',el('span',{class:'muted'},'distinct CVEs')),
      el('div',{},el('b',{},num(e.targets)),' ',el('span',{class:'muted'},'affected targets')));
    const chips=el('div',{class:'toolbar'});
    for(const s of SEV)if(e.bySeverity[s])chips.append(el('div',{},sevPill(s),' ',el('b',{},num(e.bySeverity[s]))));
    const total=SEV.reduce((a,s)=>a+(e.bySeverity[s]||0),0)||1;
    const ebar=el('div',{class:'sevbar'});
    for(const s of SEV){const w=(e.bySeverity[s]||0)/total*100;if(w>0)ebar.append(el('span',{style:'width:'+w+'%;background:'+SEVCOL[s],title:s+': '+e.bySeverity[s]}));}
    exploitPanel=el('div',{class:'panel'},el('h2',{},'Exploitable (known exploit available)'),stats,chips,ebar);
  }
  // top risk + ports
  const riskTbl=table(['Target','Score'],d.topRisk.map(r=>[link(r.target),el('span',{class:'score'},r.score)]));
  const portTbl=table(['Port','Service','Targets'],d.topPorts.map(r=>[el('a',{onclick:()=>go('ports')},String(r.port)),esc(r.service),num(r.c)],),[2]);
  const recentTbl=table(['Target','Score','Crit','High','Findings','Last scan'],(d.recentTargets||[]).map(r=>[
    link(r.target),el('span',{class:'score'},r.score==null?'—':r.score),
    r.critical?el('span',{class:'pill sev-critical'},r.critical):el('span',{class:'muted'},'0'),
    r.high?el('span',{class:'pill sev-high'},r.high):el('span',{class:'muted'},'0'),
    num(r.findings),el('span',{class:'mono muted'},fmtTime(r.last_scan))]),[1,4]);
  const cols=el('div',{class:'cols2'},
    el('div',{class:'panel'},el('h2',{},'Highest risk'),riskTbl),
    el('div',{class:'panel'},el('h2',{},'Top ports'),portTbl));
  // Scanner attribution: which port scanners produced how many rows,
  // and how many times each tool has been run.
  const pbt=d.portsByTool||[],rbt=d.runsByTool||[];
  const scannerTbl=table(['Tool','Port rows','Runs'],
    (()=>{const runsBy=Object.fromEntries(rbt.map(r=>[r.tool,r.c]));
      const tools=Array.from(new Set([...pbt.map(r=>r.tool),...rbt.map(r=>r.tool)]));
      tools.sort((a,b)=>((Object.fromEntries(pbt.map(r=>[r.tool,r.c]))[b]||0)-(Object.fromEntries(pbt.map(r=>[r.tool,r.c]))[a]||0)));
      const portsBy=Object.fromEntries(pbt.map(r=>[r.tool,r.c]));
      return tools.map(t=>[esc(t),num(portsBy[t]||0),num(runsBy[t]||0)]);})(),[1,2]);
  const scannerPanel=el('div',{class:'panel'},el('h2',{},'Scanners'),scannerTbl);
  const stamp=new Date().toLocaleTimeString();
  const refreshBtn=el('a',{class:'refresh',title:'refresh now',onclick:()=>renderOverview()},'⟳');
  const recentHdr=el('div',{class:'newshdr'},el('h2',{},'Recently scanned'),el('span',{class:'muted'},'as of '+stamp+' · auto every 30s '),refreshBtn);
  const recentPanel=el('div',{class:'panel'},recentHdr,recentTbl);
  const nodes=[el('div',{class:'panel'},el('h2',{},'Inventory'),cards),sevPanel,...(exploitPanel?[exploitPanel]:[]),cols,scannerPanel,recentPanel];
  if(d.recon)nodes.splice(1,0,el('div',{class:'panel'},el('h2',{},'Recon'),el('div',{class:'toolbar'},el('div',{},'Hosts ',el('b',{},num(d.recon.hosts))),el('div',{},'IPs ',el('b',{},num(d.recon.ips))))));
  setView(...nodes);
  // Live dashboard: re-fetch periodically while Overview is the active, visible view.
  clearTimeout(overviewTimer);
  overviewTimer=setTimeout(()=>{if(current==='overview'&&!document.hidden)renderOverview();},30000);
}

const T_DEFAULT={q:'',severities:[],cve:'',minScore:'',maxScore:'',sort:'score',offset:0,limit:100};
let tState={...T_DEFAULT};
async function renderTargets(){
  const d=await api('targets',{q:tState.q,severity:tState.severities.join(','),cve:tState.cve,minScore:tState.minScore,maxScore:tState.maxScore,sort:tState.sort,offset:tState.offset,limit:tState.limit});
  // severity facet chips — targets having ≥1 finding of that severity
  const sevChips=el('div',{class:'toolbar'},el('span',{class:'muted'},'has severity:'),...SEV.map(s=>{
    const on=tState.severities.includes(s);
    return el('a',{class:'daychip'+(on?' on':''),onclick:()=>{tState.severities=on?tState.severities.filter(x=>x!==s):[...tState.severities,s];tState.offset=0;renderTargets();}},
      el('span',{class:'gdot',style:'background:'+SEVCOL[s]}),' '+s+' ('+num(d.sevCounts?d.sevCounts[s]||0:0)+')');
  }),el('span',{class:'muted'},num(d.total)+' targets'));
  const cveSel=fsel(tState.cve,[{value:'',label:'CVE: any'},{value:'1',label:'has CVE'},{value:'0',label:'no CVE'}],v=>{tState.cve=v;tState.offset=0;renderTargets();});
  const sortSel=fsel(tState.sort,[{value:'score',label:'sort: risk score'},{value:'critical',label:'sort: critical'},{value:'high',label:'sort: high'},{value:'findings',label:'sort: findings'},{value:'cves',label:'sort: CVEs'},{value:'updated',label:'sort: updated'},{value:'created',label:'sort: created'},{value:'target',label:'sort: name'}],v=>{tState.sort=v;tState.offset=0;renderTargets();});
  const minS=el('input',{type:'number',min:'0',max:'100',placeholder:'min',value:tState.minScore,style:'width:70px',title:'min risk score'});
  minS.addEventListener('change',()=>{tState.minScore=minS.value;tState.offset=0;renderTargets();});
  const maxS=el('input',{type:'number',min:'0',max:'100',placeholder:'max',value:tState.maxScore,style:'width:70px',title:'max risk score'});
  maxS.addEventListener('change',()=>{tState.maxScore=maxS.value;tState.offset=0;renderTargets();});
  const search=el('input',{type:'search',placeholder:'filter target name…',value:tState.q});
  search.addEventListener('input',debounce(()=>{tState.q=search.value;tState.offset=0;renderTargets();},250));
  const active=tState.severities.length||tState.cve||tState.minScore||tState.maxScore||tState.q||tState.sort!=='score';
  const clear=el('button',{class:'pillbtn',onclick:()=>{tState={...T_DEFAULT,severities:[]};renderTargets();}},'clear'+(active?' ✕':''));
  const filterRow=el('div',{class:'toolbar'},cveSel,sortSel,el('span',{class:'muted'},'score'),minS,el('span',{class:'muted'},'–'),maxS,search,clear);
  const rows=d.rows.map(r=>[link(r.target),el('span',{class:'score'},r.score),
    r.critical?el('span',{class:'pill sev-critical'},r.critical):'',
    r.high?el('span',{class:'pill sev-high'},r.high):'',
    r.medium?el('span',{class:'pill sev-medium'},r.medium):'',
    num(r.findings),
    r.cves?el('span',{class:'pill sev-critical'},r.cves):'',
    el('span',{class:'mono muted'},isoSec(r.created_at)),
    el('span',{class:'mono muted'},isoSec(r.updated_at))]);
  setView(sevChips,filterRow,
    el('div',{class:'panel'},table(['Target','Score','Crit','High','Med','Findings','CVEs','Created','Updated'],rows,[1,5]),pager(tState,d.total,renderTargets)));
}

async function renderTarget(t){
  const d=await api('target',{t});
  if(d.error){setView(el('div',{class:'loading'},d.error));return;}
  const back=el('a',{class:'backlink',onclick:()=>go('targets')},'← targets');
  const glink=el('a',{class:'graphlink',onclick:()=>{graphTarget=d.target;go('graph',d.target);}},'graph ▸');
  const head=el('div',{class:'panel'},back,glink,el('h2',{},'Target'),el('code',{class:'big'},d.target),
    el('div',{class:'toolbar',style:'margin-top:12px'},
      d.risk?el('div',{},'Risk score ',el('b',{class:'score'},d.risk.score)):'',
      d.created_at?el('div',{class:'muted'},'created ',el('span',{class:'mono'},isoSec(d.created_at))):'',
      d.updated_at?el('div',{class:'muted'},'updated ',el('span',{class:'mono'},isoSec(d.updated_at))):'',
      d.risk&&d.risk.breakdown&&d.risk.breakdown.keywords&&d.risk.breakdown.keywords.length?el('div',{class:'muted'},'keywords: '+d.risk.breakdown.keywords.join(', ')):''));
  const panels=[head];
  if(d.ports.length)panels.push(el('div',{class:'panel'},el('h2',{},'Ports ('+d.ports.length+')'),
    table(['Port','Proto','Service','Product','Version','TLS','Found by'],d.ports.map(p=>[String(p.port),esc(p.protocol),esc(p.service),esc(p.product),esc(p.version),esc(p.tunnel),el('span',{class:'mono muted'},esc(p.tools||''))]))));
  if(d.http.length)panels.push(el('div',{class:'panel'},el('h2',{},'HTTP ('+d.http.length+')'),
    table(['URL','Status','Title','Server'],d.http.map(h=>[el('a',{href:h.url,target:'_blank',rel:'noopener',class:'mono'},h.url),String(esc(h.status_code)),esc(h.title),esc(h.web_server)]))));
  if(d.findings.length)panels.push(el('div',{class:'panel'},
    el('div',{class:'newshdr'},el('h2',{},'Findings ('+d.findings.length+')'),
      d.findingsSummary?el('span',{class:'muted'},statusPill(0),' '+d.findingsSummary.open+' open · ',statusPill(1),' '+d.findingsSummary.resolved+' resolved'):''),
    table(['Sev','Status','Tool','Title','CVE','First','Last'],d.findings.map(f=>[sevPill(f.severity),statusPill(f.resolved),esc(f.tool),esc(f.title),cveLink(f.cve),el('span',{class:'mono muted'},isoSec(f.first_seen)),el('span',{class:'mono muted'},isoSec(f.last_seen))]))));
  if(d.cves.length)panels.push(el('div',{class:'panel'},el('h2',{},'CVEs ('+d.cves.length+')'),
    table(['CVE','Sev','CVSS','Tools','Exploit'],d.cves.map(c=>[cveLink(c.cve_id),sevPill(c.severity),String(esc(c.cvss)),esc(c.tools),c.exploit?el('span',{class:'pill sev-critical'},'yes'):''],),[2])));
  if(d.certs.length)panels.push(el('div',{class:'panel'},el('h2',{},'Certificates ('+d.certs.length+')'),
    table(['CN','Issuer','Expires','Key','SelfSigned'],d.certs.map(c=>[esc(c.common_name),esc(c.issuer),esc(c.not_after),esc(c.key_algo)+' '+esc(c.key_size),c.self_signed?'yes':'']))));
  if(d.dns.length)panels.push(el('div',{class:'panel'},el('h2',{},'DNS ('+d.dns.length+')'),
    table(['Type','Value','TTL'],d.dns.map(r=>[esc(r.type),el('span',{class:'mono'},r.value),String(esc(r.ttl))]))));
  setView(...panels);
}

const F_DEFAULT={q:'',severities:[],tool:'',category:'',cve:'',status:'',since:'',until:'',sort:'severity',offset:0,limit:100};
let fState={...F_DEFAULT};
function fsel(current,options,onchange){
  const s=el('select',{},...options.map(o=>el('option',{value:o.value},o.label)));
  s.value=current;s.addEventListener('change',()=>onchange(s.value));return s;
}
async function renderFindings(){
  const d=await api('findings',{q:fState.q,severity:fState.severities.join(','),tool:fState.tool,category:fState.category,cve:fState.cve,status:fState.status,since:fState.since,until:fState.until,sort:fState.sort,offset:fState.offset,limit:fState.limit});
  const sc=d.statusCounts||{open:0,resolved:0};
  // severity facet chips (multi-select, with live counts)
  const sevChips=el('div',{class:'toolbar'},el('span',{class:'muted'},'severity:'),...SEV.map(s=>{
    const on=fState.severities.includes(s);
    return el('a',{class:'daychip'+(on?' on':''),onclick:()=>{fState.severities=on?fState.severities.filter(x=>x!==s):[...fState.severities,s];fState.offset=0;renderFindings();}},
      el('span',{class:'gdot',style:'background:'+SEVCOL[s]}),' '+s+' ('+num(d.sevCounts?d.sevCounts[s]||0:0)+')');
  }),el('span',{class:'muted'},num(d.total)+' findings'));
  // status facet chips
  const statusChips=el('div',{class:'toolbar'},el('span',{class:'muted'},'status:'),
    ...[['','all',(sc.open||0)+(sc.resolved||0)],['open','open',sc.open||0],['resolved','resolved',sc.resolved||0]].map(([v,lbl,cnt])=>
      el('a',{class:'daychip'+(fState.status===v?' on':''),onclick:()=>{fState.status=v;fState.offset=0;renderFindings();}},lbl+' ('+num(cnt)+')')));
  // filter row
  const toolSel=fsel(fState.tool,[{value:'',label:'all tools'},...(d.tools||[]).map(t=>({value:t.tool,label:t.tool+' ('+t.c+')'}))],v=>{fState.tool=v;fState.offset=0;renderFindings();});
  const catSel=fsel(fState.category,[{value:'',label:'all categories ('+(d.categories||[]).length+')'},...(d.categories||[]).map(c=>({value:c.category,label:c.category+' ('+c.c+')'}))],v=>{fState.category=v;fState.offset=0;renderFindings();});
  const cveSel=fsel(fState.cve,[{value:'',label:'CVE: any'},{value:'1',label:'has CVE'},{value:'0',label:'no CVE'}],v=>{fState.cve=v;fState.offset=0;renderFindings();});
  const sortSel=fsel(fState.sort,[{value:'severity',label:'sort: severity'},{value:'newest',label:'sort: newest seen'},{value:'oldest',label:'sort: oldest seen'},{value:'target',label:'sort: target'}],v=>{fState.sort=v;fState.offset=0;renderFindings();});
  const since=el('input',{type:'date',value:fState.since,title:'last seen from'});
  since.addEventListener('change',()=>{fState.since=since.value;fState.offset=0;renderFindings();});
  const until=el('input',{type:'date',value:fState.until,title:'last seen until'});
  until.addEventListener('change',()=>{fState.until=until.value;fState.offset=0;renderFindings();});
  const search=el('input',{type:'search',placeholder:'target / title / CVE…',value:fState.q});
  search.addEventListener('input',debounce(()=>{fState.q=search.value;fState.offset=0;renderFindings();},250));
  const active=fState.severities.length||fState.tool||fState.category||fState.cve||fState.status||fState.since||fState.until||fState.q||fState.sort!=='severity';
  const clear=el('button',{class:'pillbtn',onclick:()=>{fState={...F_DEFAULT,severities:[]};renderFindings();}},'clear'+(active?' ✕':''));
  const filterRow=el('div',{class:'toolbar'},toolSel,catSel,cveSel,sortSel,el('span',{class:'muted'},'last seen'),since,el('span',{class:'muted'},'→'),until,search,clear);
  const rows=d.rows.map(f=>[sevPill(f.severity),statusPill(f.resolved),link(f.target),el('span',{class:'tcell'},esc(f.title)),cveLink(f.cve),esc(f.tool),el('span',{class:'mono muted'},isoSec(f.first_seen)),el('span',{class:'mono muted'},isoSec(f.last_seen))]);
  setView(sevChips,statusChips,filterRow,
    el('div',{class:'panel'},table(['Sev','Status','Target','Title','CVE','Tool','First','Last'],rows),pager(fState,d.total,renderFindings)));
}

let cState={q:'',exploit:'',offset:0,limit:100};
async function renderCves(){
  const d=await api('cves',{q:cState.q,exploit:cState.exploit,offset:cState.offset,limit:cState.limit});
  const ec=d.exploitCounts||{yes:0,no:0};
  const expChips=el('div',{class:'toolbar'},el('span',{class:'muted'},'exploit:'),
    ...[['','all',ec.yes+ec.no],['1','exploitable',ec.yes],['0','no exploit',ec.no]].map(([v,lbl,cnt])=>
      el('a',{class:'daychip'+(cState.exploit===v?' on':''),onclick:()=>{cState.exploit=v;cState.offset=0;renderCves();}},lbl+' ('+num(cnt)+')')));
  const search=el('input',{type:'search',placeholder:'CVE id / target…',value:cState.q});
  search.addEventListener('input',debounce(()=>{cState.q=search.value;cState.offset=0;renderCves();},250));
  const rows=d.rows.map(c=>[cveLink(c.cve_id),link(c.target),sevPill(c.severity),String(esc(c.cvss)),esc(c.tools),c.exploit?el('span',{class:'pill sev-critical'},'exploit'):'',num(c.hit_count)]);
  setView(expChips,el('div',{class:'toolbar'},search,el('span',{class:'muted'},num(d.total)+' cve rows')),
    el('div',{class:'panel'},table(['CVE','Target','Sev','CVSS','Tools','','Hits'],rows,[3,6]),pager(cState,d.total,renderCves)));
}

function phaseCol(title,cls,items){
  const chips=el('div',{class:'pchips'});
  if(!items.length)chips.append(el('span',{class:'muted'},'—'));
  for(const it of items){
    const chip=el('span',{class:'pchip '+cls,title:(it.severity||'')+' · CVSS '+(it.cvss==null?'?':it.cvss)+(it.exploit?' · exploit':'')},cveLink(it.cve));
    if(it.exploit)chip.append(el('span',{class:'pchip-exp'},'⚡'));
    chips.append(chip);
  }
  return el('div',{class:'pcol'},el('div',{class:'pcol-h '+cls},title),chips);
}
async function renderPaths(){
  const d=await api('attackPaths');
  const cov=d.coverage||{vectoredCves:0,totalCves:0,hostsAnalyzed:0};
  const intro=el('div',{class:'panel intro'},el('h2',{},'Attack paths — multi-CVE chains'),
    el('p',{class:'muted'},'Hosts where a single CVE isn’t enough but combining them is: a remote-unauthenticated '+
      '“foothold” CVE plus a privilege-escalation CVE (roles inferred from CVSS vectors). Heuristic, for prioritisation — not a proven exploit chain.'),
    el('p',{class:'muted'},
      el('b',{},String(d.chains.length)),' complete chain'+(d.chains.length===1?'':'s'),' · ',
      el('b',{},String(d.partial)),' partial · analysed '+num(cov.hostsAnalyzed)+' hosts from '+num(cov.vectoredCves)+'/'+num(cov.totalCves)+' CVEs that have CVSS vectors'));
  const nodes=[intro];
  if(!d.chains.length)nodes.push(el('div',{class:'panel'},el('p',{class:'muted'},'No complete foothold→privesc chains found in the vectored CVE set. Enriching more CVEs (cve-enrich) would widen coverage.')));
  for(const h of d.chains){
    const hdr=el('div',{class:'newshdr'},link(h.target),el('span',{class:'score'},h.score==null?'':h.score),
      el('span',{class:'pill st-open'},'chain'));
    const flow=el('div',{class:'pflow'},
      phaseCol('① Foothold ('+h.footholdN+')','ph-foot',h.foothold),
      el('span',{class:'parrow'},'→'),
      phaseCol('② Priv-esc ('+h.privescN+')','ph-priv',h.privesc),
      el('span',{class:'parrow'},'→'),
      phaseCol('③ Impact','ph-imp',h.impact));
    nodes.push(el('div',{class:'panel'},hdr,flow));
  }
  setView(...nodes);
}

let secState={q:'',type:'',severity:'',status:'',offset:0,limit:100};
async function renderSecrets(){
  const d=await api('secrets',{q:secState.q,type:secState.type,severity:secState.severity,status:secState.status,offset:secState.offset,limit:secState.limit});
  const sc=d.statusCounts||{open:0,resolved:0};
  const intro=el('div',{class:'panel intro'},el('h2',{},'Leaked secrets'),
    el('p',{class:'muted'},'Exposed credentials, API keys and secret config files (verified exposed Google API keys, cloud keys, wp-config/DB creds, exposed .env/.git/.htaccess, etc.).'),
    el('div',{class:'toolbar'},
      el('div',{},el('b',{class:'score'},num(d.totalSecrets)),' ',el('span',{class:'muted'},'secret findings')),
      el('div',{},el('b',{},num(d.affectedTargets)),' ',el('span',{class:'muted'},'affected targets'))));
  // severity chips
  const sevChips=el('div',{class:'toolbar'},el('span',{class:'muted'},'severity:'),...SEV.map(s=>{
    const on=secState.severity===s;
    return el('a',{class:'daychip'+(on?' on':''),onclick:()=>{secState.severity=on?'':s;secState.offset=0;renderSecrets();}},
      el('span',{class:'gdot',style:'background:'+SEVCOL[s]}),' '+s+' ('+num(d.sevCounts?d.sevCounts[s]||0:0)+')');
  }),el('span',{class:'muted'},num(d.total)+' shown'));
  // status chips
  const statusChips=el('div',{class:'toolbar'},el('span',{class:'muted'},'status:'),
    ...[['','all',(sc.open||0)+(sc.resolved||0)],['open','open',sc.open||0],['resolved','resolved',sc.resolved||0]].map(([v,lbl,cnt])=>
      el('a',{class:'daychip'+(secState.status===v?' on':''),onclick:()=>{secState.status=v;secState.offset=0;renderSecrets();}},lbl+' ('+num(cnt)+')')));
  const typeSel=fsel(secState.type,[{value:'',label:'all types ('+(d.types||[]).length+')'},...(d.types||[]).map(t=>({value:t.type,label:t.type+' ('+t.c+')'}))],v=>{secState.type=v;secState.offset=0;renderSecrets();});
  const search=el('input',{type:'search',placeholder:'target / detail / type…',value:secState.q});
  search.addEventListener('input',debounce(()=>{secState.q=search.value;secState.offset=0;renderSecrets();},250));
  const clear=el('button',{class:'pillbtn',onclick:()=>{secState={q:'',type:'',severity:'',status:'',offset:0,limit:100};renderSecrets();}},'clear');
  const filterRow=el('div',{class:'toolbar'},typeSel,search,clear);
  const where=(u)=>{const s=esc(u);if(!s)return '';return /^https?:\/\//.test(s)?el('a',{href:s,target:'_blank',rel:'noopener',class:'mono wcell'},s):el('span',{class:'mono muted wcell'},s);};
  const rows=d.rows.map(f=>[sevPill(f.severity),statusPill(f.resolved),link(f.target),el('span',{class:'mono'},esc(f.category)),el('span',{class:'tcell'},esc(f.title)),el('span',{class:'mono evcell'},esc(f.evidence)),where(f.matched_at)]);
  setView(intro,sevChips,statusChips,filterRow,
    el('div',{class:'panel'},table(['Sev','Status','Target','Type','Detail','Evidence','Where'],rows,[],'stack'),pager(secState,d.total,renderSecrets)));
}

async function renderPorts(){
  const d=await api('ports');
  const rows=d.rows.map(r=>[el('a',{onclick:()=>showPort(r.port)},String(r.port)),esc(r.protocol),esc(r.service),num(r.targets),el('span',{class:'mono muted'},esc(r.tools||''))]);
  setView(el('div',{class:'panel'},el('h2',{},'Ports by prevalence'),table(['Port','Proto','Service','Targets','Found by'],rows,[3])));
}
async function showPort(port){
  loading();
  const d=await api('ports',{port});
  const back=el('a',{class:'backlink',onclick:()=>renderPorts()},'← ports');
  const rows=d.rows.map(r=>[link(r.target),el('span',{class:'mono'},esc(r.ip)),esc(r.service),esc(r.product),esc(r.version),el('span',{class:'mono muted'},esc(r.tools||''))]);
  setView(el('div',{class:'panel'},back,el('h2',{},'Port '+port+' · '+d.rows.length+' hosts'),table(['Target','IP','Service','Product','Version','Found by'],rows)));
}

async function renderRecon(){
  const d=await api('recon');
  if(!d.enabled){setView(el('div',{class:'panel'},el('h2',{},'Recon'),el('p',{class:'muted'},'recon.db not loaded')));return;}
  const cards=el('div',{class:'grid cards'},
    el('div',{class:'card'},el('div',{class:'n'},num(d.hosts)),el('div',{class:'l'},'Hosts')),
    el('div',{class:'card'},el('div',{class:'n'},num(d.ips)),el('div',{class:'l'},'IPs')));
  const country=table(['Country','Code','IPs'],d.byCountry.map(r=>[esc(r.country),el('span',{class:'mono'},esc(r.country_code)),num(r.c)]),[2]);
  const asn=table(['ASN','Org','IPs'],d.byAsn.map(r=>[el('span',{class:'mono'},esc(r.asn)),esc(r.as_name),num(r.c)]),[2]);
  const src=d.bySource.length?table(['Source','Hosts'],d.bySource.map(r=>[esc(r.source),num(r.c)]),[1]):el('p',{class:'muted'},'no source data');
  setView(el('div',{class:'panel'},el('h2',{},'Recon inventory'),cards),
    el('div',{class:'cols2'},el('div',{class:'panel'},el('h2',{},'IPs by country'),country),el('div',{class:'panel'},el('h2',{},'IPs by ASN'),asn)),
    el('div',{class:'panel'},el('h2',{},'Hosts by source'),src));
}

const GRAPH_COLORS={host:'#58a6ff',port:'#3fb950',tech:'#a371f7',dns:'#e3b341',cve:'#f85149',ip:'#2dd4bf',asn:'#f0883e'};
let graphTarget=null;
let graphScope='host';
function scopeBar(){
  const mk=(id,label)=>el('button',{class:'scopebtn'+(graphScope===id?' on':''),onclick:()=>{graphScope=id;history.pushState(null,'','#graph'+(id==='global'?'/~global':(graphTarget?'/'+encodeURIComponent(graphTarget):'')));renderGraph();}},label);
  return el('div',{class:'toolbar'},el('span',{class:'muted'},'scope:'),mk('host','Host'),mk('global','Global'));
}
function legendBar(keys){
  return el('div',{class:'toolbar'},...keys.map(k=>el('span',{class:'gleg'},el('span',{class:'gdot',style:'background:'+GRAPH_COLORS[k]}),k)));
}
// Shared Cytoscape renderer. Node size scales with data('weight') when present.
async function drawCy(box,d,onHostTap){
  try{await loadCytoscape();}catch(e){box.append(el('div',{class:'loading'},String(e.message)));return;}
  const els=[...d.nodes.map(n=>({data:n.data})),...d.edges.map(e=>({data:e.data}))];
  const sizeFor=ele=>{const w=ele.data('weight');if(w)return Math.min(70,12+Math.sqrt(w)*5);return ele.data('type')==='host'?26:16;};
  const cy=window.cytoscape({
    container:box,
    elements:els,
    style:[
      {selector:'node',style:{'background-color':ele=>GRAPH_COLORS[ele.data('type')]||'#8b949e','label':'data(label)','font-size':'9px','color':'#e6edf3','text-outline-color':'#0d1117','text-outline-width':2,'width':sizeFor,'height':sizeFor,'min-zoomed-font-size':6}},
      {selector:'node[type="host"]',style:{'font-weight':'bold'}},
      {selector:'node[type="asn"]',style:{'font-size':'12px','font-weight':'bold','shape':'round-rectangle'}},
      {selector:'node[type="ip"]',style:{'shape':'diamond'}},
      {selector:'edge',style:{'width':1,'line-color':'#2a3140','curve-style':'haystack','opacity':0.6}}
    ],
    layout:{name:'cose',animate:false,nodeRepulsion:8000,idealEdgeLength:80,padding:20,componentSpacing:100}
  });
  if(onHostTap)cy.on('tap','node[type="host"]',e=>onHostTap(e.target.data('label')));
}
async function renderGraph(arg){
  if(arg){if(arg==='~global'){graphScope='global';}else{graphTarget=arg;graphScope='host';}}
  if(graphScope==='global')return renderGraphGlobal();
  return renderGraphHost();
}
async function renderGraphHost(){
  const d=await api('graph',{t:graphTarget||''});
  const pick=(t)=>{graphTarget=t;graphScope='host';history.pushState(null,'','#graph'+(t?'/'+encodeURIComponent(t):''));renderGraph();};
  const search=el('input',{type:'search',placeholder:'host FQDN or search (e.g. zimbra, gov.hu)…',value:graphTarget||''});
  const load=()=>pick(search.value.trim());
  search.addEventListener('keydown',e=>{if(e.key==='Enter')load();});
  const goBtn=el('button',{class:'gobtn',onclick:load},'Render');
  const toolbar=el('div',{class:'toolbar'},search,goBtn);
  if(!d.target){
    const q=(d.query||'').trim();
    const head=q
      ? 'No exact host “'+q+'”. '+(d.suggest.length?d.suggest.length+' match'+(d.suggest.length===1?'':'es')+' — pick one:':'No matches.')
      : 'Pick a target';
    const picks=el('div',{class:'panel'},el('h2',{},head),
      table(['Target','Score'],(d.suggest||[]).map(r=>[el('a',{onclick:()=>pick(r.target)},r.target),el('span',{class:'score'},r.score)]),[1]));
    setView(scopeBar(),toolbar,picks);
    return;
  }
  const box=el('div',{id:'cy'});
  const info=el('span',{class:'muted'},d.nodes.length+' nodes · '+d.edges.length+' edges');
  setView(scopeBar(),toolbar,el('div',{class:'panel'},el('h2',{},'Estate graph · '+d.target),legendBar(['host','port','tech','dns','cve']),box,info));
  drawCy(box,d);
}
let globalOpts={min:2,hosts:false};
async function renderGraphGlobal(){
  const d=await api('graph',{scope:'global',min:globalOpts.min,hosts:globalOpts.hosts?'1':''});
  const minIn=el('input',{type:'number',min:'1',value:String(globalOpts.min),style:'width:70px'});
  minIn.addEventListener('change',()=>{globalOpts.min=Math.max(1,Number(minIn.value)||2);renderGraphGlobal();});
  const hostsChk=el('input',{type:'checkbox',...(globalOpts.hosts?{checked:''}:{})});
  hostsChk.addEventListener('change',()=>{globalOpts.hosts=hostsChk.checked;renderGraphGlobal();});
  const controls=el('div',{class:'toolbar'},
    el('label',{class:'muted'},'min hosts / IP ',minIn),
    el('label',{class:'muted'},hostsChk,' show host nodes'),
    d.source==='scan'?el('span',{class:'muted'},'(no recon.db → no ASN)'):'',
    d.truncated?el('span',{class:'nerr'},'host list capped'):'');
  const box=el('div',{id:'cy'});
  const info=el('span',{class:'muted'},d.asnCount+' ASNs · '+d.sharedIpCount+' shared IPs · '+d.nodes.length+' nodes · '+d.edges.length+' edges — tap a host to drill in');
  const keys=d.source==='scan'?['ip','host']:['asn','ip','host'];
  setView(scopeBar(),controls,el('div',{class:'panel'},el('h2',{},'Global infrastructure overview'),legendBar(keys),box,info));
  drawCy(box,d,(host)=>{graphTarget=host;graphScope='host';history.pushState(null,'','#graph/'+encodeURIComponent(host));renderGraph();});
}

// News = read-only feed of newly-discovered findings, grouped by first-seen day.
let newsState={day:'',q:'',severity:''};
async function renderNews(){
  const d=await api('news',{day:newsState.day,q:newsState.q,severity:newsState.severity});
  const today=todayStr();
  // day chips (with per-day new-finding counts; today highlighted)
  const dayChips=el('div',{class:'toolbar'},...(d.days||[]).slice(0,21).map(x=>el('a',{class:'daychip'+(newsState.day===x.day?' on':'')+(x.day===today?' today':''),onclick:()=>{newsState.day=(newsState.day===x.day?'':x.day);renderNews();}},x.day+' · '+x.c)));
  // filters
  const dayFilter=el('input',{type:'date',value:newsState.day});
  dayFilter.addEventListener('change',()=>{newsState.day=dayFilter.value;renderNews();});
  const sevSel=el('select',{},el('option',{value:''},'all severities'),...SEV.map(s=>el('option',{value:s},s)));
  sevSel.value=newsState.severity;
  sevSel.addEventListener('change',()=>{newsState.severity=sevSel.value;renderNews();});
  const search=el('input',{type:'search',placeholder:'target / title / CVE…',value:newsState.q});
  search.addEventListener('input',debounce(()=>{newsState.q=search.value;renderNews();},250));
  const clear=el('button',{class:'pillbtn',onclick:()=>{newsState={day:'',q:'',severity:''};renderNews();}},'clear');
  const filters=el('div',{class:'toolbar'},dayFilter,sevSel,search,clear,el('span',{class:'muted'},d.rows.length+(d.rows.length>=800?'+':'')+' new findings'+(newsState.day?(' on '+newsState.day):'')));
  // group rows by first-seen day, newest first
  const groups=[];const byDay={};
  for(const r of d.rows){const day=(r.first_seen||'').slice(0,10);if(!byDay[day]){byDay[day]=[];groups.push(day);}byDay[day].push(r);}
  const sections=[];
  if(!d.rows.length)sections.push(el('div',{class:'panel'},el('p',{class:'muted'},'no new findings'+(newsState.day?(' on '+newsState.day):'')+'.')));
  for(const day of groups){
    const rows=byDay[day].map(r=>[sevPill(r.severity),link(r.target),el('span',{class:'tcell'},esc(r.title)),cveLink(r.cve),esc(r.tool),el('span',{class:'mono muted'},fmtTime(r.first_seen).slice(11))]);
    sections.push(el('div',{class:'panel'},
      el('div',{class:'newshdr'},el('span',{class:'nday'},day),el('span',{class:'muted'},byDay[day].length+' new'+(day===today?' · today':''))),
      table(['Sev','Target','Title','CVE','Tool','Time'],rows,[],'stack')));
  }
  setView(el('div',{class:'panel intro'},el('h2',{},'New findings'),el('p',{class:'muted'},'Findings by the day they were first observed. Read-only — sourced from scan.db.')),
    dayChips,filters,...sections);
}

// helpers
function table(headers,rows,numCols=[],cls){
  const thead=el('thead',{},el('tr',{},...headers.map((h,i)=>el('th',{class:numCols.includes(i)?'num':''},h))));
  const tbody=el('tbody',{});
  if(!rows.length)tbody.append(el('tr',{},el('td',{colspan:String(headers.length),class:'muted'},'—')));
  for(const r of rows)tbody.append(el('tr',{},...r.map((c,i)=>el('td',{class:numCols.includes(i)?'num':'','data-label':String(headers[i]||'')},c==null?'':(c.nodeType?c:String(c))))));
  return el('table',cls?{class:cls}:{},thead,tbody);
}
function link(target){return el('a',{onclick:()=>go2target(target)},target);}
function go2target(t){current='target';buildNav();history.pushState(null,'','#target/'+encodeURIComponent(t));render('target',t);}
function pager(state,total,rerender){
  const from=state.offset+1,to=Math.min(state.offset+state.limit,total);
  const prev=el('button',{disabled:state.offset<=0?'':null,onclick:()=>{state.offset=Math.max(0,state.offset-state.limit);rerender();}},'‹ prev');
  const next=el('button',{disabled:to>=total?'':null,onclick:()=>{state.offset+=state.limit;rerender();}},'next ›');
  return el('div',{class:'pager'},prev,next,el('span',{},total?from+'–'+to+' of '+num(total):'0'));
}
function fmtTime(s){if(!s)return '';return s.replace('T',' ').replace(/\.\d+Z$/,'').replace('Z','');}
function isoSec(s){if(!s)return '';return String(s).replace(/\.\d+Z$/,'Z');}
function debounce(fn,ms){let t;return(...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms);};}

// Render the view named by the current URL hash, WITHOUT pushing history.
// Used at boot and on browser back/forward (popstate). Forward navigation
// (go / go2target / graph handlers) pushes a history entry, so Back returns
// here to re-render the previous view.
function route(){
  const h=location.hash.slice(1);
  if(h){
    const i=h.indexOf('/');
    const tab=i<0?h:h.slice(0,i);
    const arg=i<0?'':decodeURIComponent(h.slice(i+1));
    if(tab==='target'&&arg){current='target';buildNav();render('target',arg);return;}
    if(TABS.some(t=>t[0]===tab)){current=tab;buildNav();render(tab,arg||undefined);return;}
  }
  current='overview';buildNav();render('overview');
}
window.addEventListener('popstate',route);
// Refresh the live Overview as soon as the tab regains focus.
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&current==='overview')renderOverview();});
// boot
route();
</script>
</body>
</html>`;
