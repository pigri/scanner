#!/usr/bin/env -S node --loader tsx
import path from 'node:path';
import Database from 'better-sqlite3';
import { openDb } from './lib/db.js';
import { computeScore, type TargetSignals, type Finding, type Port, type HttpProbe } from './lib/risk.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';
import { buildTargetResolver } from './lib/identity.js';

interface Opts {
  db: string;
  discoveryDb: string | null;
  hostSuffix: string | null;
  top: number;
  minScore: number;
  showBreakdown: boolean;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    // DB path (--sqlite / --db alias) resolved by the shared helper.
    db: resolveDbArg(argv),
    discoveryDb: null,
    hostSuffix: null,
    top: 25,
    minScore: 0,
    showBreakdown: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (isDbFlag(a)) { i++; continue; } // flag + value already consumed by resolveDbArg
    else if (a === '--discovery-db') opts.discoveryDb = next();
    else if (a === '--suffix') opts.hostSuffix = next();
    else if (a === '--top') opts.top = parseInt(next(), 10);
    else if (a === '--min') opts.minScore = parseInt(next(), 10);
    else if (a === '--breakdown') opts.showBreakdown = true;
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: risk [options]

Computes a 0-100 threat risk score per target from the scan.db (and optionally
the discovery.db) and stores it in the risk_scores table. Prints top-N ranked.

Options:
  --sqlite <path>        scan SQLite DB (default: scan.db) [alias: --db]
  --discovery-db <path>  discovery SQLite DB for shared-IP + country + freshness
  --suffix <domain>      expected country-of-origin suffix, e.g. gov.hu
                         (only used to mark foreign-hosted targets)
  --top <N>              print top N (default: 25)
  --min <N>              only print scores >= this (default: 0)
  --breakdown            include per-component breakdown per line
`);
}

interface HostFacts {
  countryCode: string | null;
  shared: number;
  firstSeen: string | null;
}

function loadHostFactsFromDiscovery(discoveryDbPath: string): Map<string, HostFacts> {
  // Read-only raw open — the discovery DB has its own schema (hosts/resolutions/ips)
  // and applying the scan schema on top errors on column mismatches in `runs`.
  const d = new Database(discoveryDbPath, { readonly: true });
  const rows = d.prepare(`
    SELECT
      h.name AS domain,
      h.first_seen AS first_seen,
      i.country_code AS country_code,
      (SELECT COUNT(DISTINCT r2.host_id)
         FROM resolutions r2 WHERE r2.ip = r.ip) AS shared
    FROM hosts h
    JOIN resolutions r ON r.host_id = h.id
    JOIN ips i         ON i.ip = r.ip
    GROUP BY h.id
  `).all() as { domain: string; first_seen: string; country_code: string | null; shared: number }[];
  d.close();
  const map = new Map<string, HostFacts>();
  for (const r of rows) {
    map.set(r.domain, {
      countryCode: r.country_code,
      shared: r.shared,
      firstSeen: r.first_seen,
    });
  }
  return map;
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }
  const db = openDb(opts.db);
  // The scan workers hold write locks for whole batches; the 5s default on this
  // connection was losing races with them mid-loop (SQLITE_BUSY). 60s is well
  // over the longest observed worker write and still fails loudly if something
  // is genuinely stuck.
  db.raw.pragma('busy_timeout = 60000');
  const facts = opts.discoveryDb ? loadHostFactsFromDiscovery(opts.discoveryDb) : new Map<string, HostFacts>();
  const now = new Date().toISOString();
  const runId = db.startRun('risk', { db: opts.db, discoveryDb: opts.discoveryDb, suffix: opts.hostSuffix }, now);

  // Resolver folds each raw target onto its canonical identity: reverse-DNS
  // pseudo-names collapse to their IP, and an IP the scan unambiguously ties to
  // a single hostname folds onto that hostname (prefer-hostname policy). The
  // ports table is the mapping source since it carries both target and ip.
  const ipPairs = db.raw.prepare('SELECT DISTINCT target, ip FROM ports').all() as { target: string; ip: string | null }[];
  const resolve = buildTargetResolver(ipPairs);

  // union of every target that appears in findings, ports, or http_probes
  const targets = new Set<string>();
  for (const r of db.raw.prepare('SELECT DISTINCT target FROM findings').all() as { target: string }[]) targets.add(resolve(r.target));
  for (const r of db.raw.prepare('SELECT DISTINCT target FROM ports').all() as { target: string }[]) targets.add(resolve(r.target));
  for (const r of db.raw.prepare('SELECT DISTINCT target FROM http_probes').all() as { target: string }[]) targets.add(resolve(r.target));

  if (opts.discoveryDb) for (const domain of facts.keys()) targets.add(resolve(domain));

  const findingsByTarget = new Map<string, Finding[]>();
  const findingRows = db.raw.prepare('SELECT target, tool, severity, title, cve, needs_review FROM findings')
    .all() as { target: string; tool: string; severity: string | null; title: string; cve: string | null; needs_review: number }[];
  for (const r of findingRows) {
    const key = resolve(r.target);
    if (!findingsByTarget.has(key)) findingsByTarget.set(key, []);
    findingsByTarget.get(key)!.push({
      tool: r.tool, severity: r.severity, title: r.title, cve: r.cve,
      needsReview: !!r.needs_review,
    });
  }
  const portsByTarget = new Map<string, Port[]>();
  for (const r of db.raw.prepare('SELECT target, port, protocol, service FROM ports').all() as { target: string; port: number; protocol: string | null; service: string | null }[]) {
    const key = resolve(r.target);
    if (!portsByTarget.has(key)) portsByTarget.set(key, []);
    portsByTarget.get(key)!.push({ port: r.port, service: r.service, protocol: r.protocol });
  }
  const httpByTarget = new Map<string, HttpProbe[]>();
  for (const r of db.raw.prepare('SELECT target, url, status_code, tech_json FROM http_probes').all() as { target: string; url: string; status_code: number | null; tech_json: string | null }[]) {
    const tech = r.tech_json ? JSON.parse(r.tech_json) as string[] : null;
    const key = resolve(r.target);
    if (!httpByTarget.has(key)) httpByTarget.set(key, []);
    httpByTarget.get(key)!.push({ url: r.url, status_code: r.status_code, tech });
  }

  const insertStmt = db.raw.prepare(
    'INSERT INTO risk_scores(target, score, breakdown_json, computed_at, run_id) VALUES(?, ?, ?, ?, ?)'
  );
  const results: { target: string; score: number; breakdown: unknown }[] = [];
  const rows: { target: string; score: number; breakdownJson: string }[] = [];
  for (const t of targets) {
    const f = facts.get(t) ?? { countryCode: null, shared: 0, firstSeen: null };
    const signals: TargetSignals = {
      target: t,
      findings: findingsByTarget.get(t) ?? [],
      ports: portsByTarget.get(t) ?? [],
      http: httpByTarget.get(t) ?? [],
      hostShared: f.shared,
      hostCountryCode: f.countryCode,
      firstSeen: f.firstSeen,
      now,
      ...(opts.hostSuffix ? { hostSuffix: opts.hostSuffix } : {}),
    };
    const r = computeScore(signals);
    rows.push({ target: t, score: r.score, breakdownJson: JSON.stringify(r.breakdown) });
    if (r.score >= opts.minScore) results.push({ target: t, score: r.score, breakdown: r.breakdown });
  }
  // Single BEGIN IMMEDIATE txn: takes the write lock once (waiting up to the
  // bumped busy_timeout for it) instead of racing the workers on each row.
  const writeAll = db.raw.transaction((batch: typeof rows) => {
    for (const row of batch) insertStmt.run(row.target, row.score, row.breakdownJson, now, runId);
  });
  writeAll.immediate(rows);

  db.finishRun(runId, { targetsCount: targets.size, findingsCount: results.length, at: new Date().toISOString() });

  results.sort((a, b) => b.score - a.score);
  const shown = results.slice(0, opts.top);
  console.log(`# top ${shown.length} of ${results.length} scored targets (of ${targets.size} total)`);
  for (const r of shown) {
    if (opts.showBreakdown) {
      const b = r.breakdown as {
        critical: number; high: number; medium: number; low: number; info: number;
        reviewSkipped: number;
        keywords: string[]; takeover: number; tlsWeak: number; wordpress: number;
        portPoints: number; sharedIp: number; foreign: number; fresh: number;
      };
      const flags: string[] = [];
      if (b.critical) flags.push(`crit=${b.critical}`);
      if (b.high) flags.push(`high=${b.high}`);
      if (b.medium) flags.push(`med=${b.medium}`);
      if (b.low) flags.push(`low=${b.low}`);
      if (b.info) flags.push(`info=${b.info}`);
      if (b.reviewSkipped) flags.push(`review=${b.reviewSkipped}`);
      if (b.takeover) flags.push('takeover');
      if (b.tlsWeak) flags.push('tls-weak');
      if (b.wordpress) flags.push('wordpress');
      if (b.portPoints) flags.push(`ports=${b.portPoints / 2}`);
      if (b.keywords.length) flags.push(`kw=${b.keywords.join(',')}`);
      if (b.sharedIp) flags.push('shared-ip');
      if (b.foreign) flags.push('foreign');
      if (b.fresh) flags.push('fresh');
      console.log(`${String(r.score).padStart(3)}  ${r.target}  [${flags.join(' ')}]`);
    } else {
      console.log(`${String(r.score).padStart(3)}  ${r.target}`);
    }
  }
  console.error(`\nwrote ${results.length} score(s) to ${path.resolve(opts.db)} (run #${runId})`);
  db.close();
}

main();
