#!/usr/bin/env -S node --loader tsx
import { openDb } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';

interface Opts {
  db: string;
  cmd: 'findings' | 'severity' | 'ports' | 'runs' | 'risk' | 'cves' | 'new-since' | 'cert-peers' | 'review' | 'sql';
  since: string | null;
  until: string | null;
  severity: string | null;
  tool: string | null;
  sql: string;
  limit: number | null;
  target: string | null;
  help?: boolean;
}

function normalizeDate(v: string, boundary: 'start' | 'end'): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) {
    return boundary === 'start' ? `${v}T00:00:00.000Z` : `${v}T23:59:59.999Z`;
  }
  return v;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    // DB path (--sqlite / --db alias) resolved by the shared helper.
    db: resolveDbArg(argv), cmd: 'findings',
    since: null, until: null, severity: null, tool: null, sql: '',
    limit: null, target: null,
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (isDbFlag(a)) { i++; continue; } // flag + value already consumed by resolveDbArg
    else if (a === '--since') opts.since = normalizeDate(next(), 'start');
    else if (a === '--until') opts.until = normalizeDate(next(), 'end');
    else if (a === '--severity') opts.severity = next();
    else if (a === '--tool') opts.tool = next();
    else if (a === '--limit') opts.limit = parseInt(next(), 10);
    else if (a === '--target') opts.target = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  if (rest[0] === 'findings' || rest[0] === 'severity' || rest[0] === 'ports' || rest[0] === 'runs' || rest[0] === 'risk' || rest[0] === 'cves' || rest[0] === 'new-since' || rest[0] === 'cert-peers' || rest[0] === 'review' || rest[0] === 'sql') {
    opts.cmd = rest[0];
    if (rest[0] === 'sql') opts.sql = rest.slice(1).join(' ');
    // `new-since <iso>` — support positional ISO date after the command.
    if (rest[0] === 'new-since' && rest[1] && !opts.since) opts.since = normalizeDate(rest[1], 'start');
    // `cert-peers <fqdn>` — support positional single-host filter.
    if (rest[0] === 'cert-peers' && rest[1]) (opts as { certPeerFocus?: string }).certPeerFocus = rest[1];
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: query <cmd> [options]

Commands:
  findings           List findings, optionally filtered
  severity           Aggregate counts by severity
  ports              List open ports
  runs               Recent runs (last 20)
  risk               Latest risk_scores rows, ranked
  cves               CVE rollup: worst-severity per (target, cve) with source tools
  new-since <iso>    Findings whose earliest seen_at is >= iso (differential digest)
  cert-peers [fqdn]  Hosts sharing certificates (blast radius). With fqdn: peers of that host.
  review             List findings the scanner flagged as likely-false-positive (needs_review=1).
                     Shows preserved page body + real HTTP status so a human can confirm/dismiss.
  sql "<query>"      Arbitrary read-only SQL

Filters:
  --sqlite <path>    SQLite DB (default: scan.db) [alias: --db]
  --since <iso>      Only rows with seen_at >= this ISO date
  --until <iso>      Only rows with seen_at <= this ISO date
  --severity <s>     info | low | medium | high | critical
  --tool <t>         nuclei | wpscan | testssl | takeover | ...
  --target <host>    restrict to one target (review command)
  --limit <N>        cap output rows (review command; default 20)

Examples:
  query findings --since 2026-08-19 --severity high
  query findings --tool nuclei --severity critical
  query severity
  query ports --since 2026-08-19
  query sql "SELECT target, COUNT(*) FROM findings WHERE severity='high' GROUP BY target ORDER BY 2 DESC LIMIT 20"
`);
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }
  const db = openDb(opts.db);

  if (opts.cmd === 'findings') {
    let sql = 'SELECT tool, severity, target, title, cve, seen_at FROM findings WHERE 1=1';
    const params: unknown[] = [];
    if (opts.since) { sql += ' AND seen_at >= ?'; params.push(opts.since); }
    if (opts.until) { sql += ' AND seen_at <= ?'; params.push(opts.until); }
    if (opts.severity) { sql += ' AND severity = ?'; params.push(opts.severity); }
    if (opts.tool) { sql += ' AND tool = ?'; params.push(opts.tool); }
    sql += ' ORDER BY seen_at DESC';
    const rows = db.raw.prepare(sql).all(...params) as any[];
    for (const r of rows) {
      console.log(`${r.seen_at}  [${r.severity ?? '-'}]  ${r.tool}  ${r.target}  ${r.title}${r.cve ? '  ' + r.cve : ''}`);
    }
    console.error(`\n${rows.length} finding(s)`);
  } else if (opts.cmd === 'severity') {
    const counts = db.countBySeverity();
    for (const r of counts) console.log(`${String(r.n).padStart(6)}  ${r.severity}`);
  } else if (opts.cmd === 'ports') {
    let sql = 'SELECT target, ip, port, protocol, service, product, version, seen_at FROM ports WHERE 1=1';
    const params: unknown[] = [];
    if (opts.since) { sql += ' AND seen_at >= ?'; params.push(opts.since); }
    if (opts.until) { sql += ' AND seen_at <= ?'; params.push(opts.until); }
    sql += ' ORDER BY seen_at DESC, target, port';
    const rows = db.raw.prepare(sql).all(...params) as any[];
    for (const r of rows) {
      console.log(`${r.seen_at}  ${r.target}  ${r.port}/${r.protocol}  ${r.service ?? ''}  ${r.product ?? ''} ${r.version ?? ''}`.trim());
    }
    console.error(`\n${rows.length} port(s)`);
  } else if (opts.cmd === 'risk') {
    // Latest score per target within date window
    let sql = `
      SELECT target, MAX(score) AS score, MAX(computed_at) AS computed_at
      FROM risk_scores WHERE 1=1
    `;
    const params: unknown[] = [];
    if (opts.since) { sql += ' AND computed_at >= ?'; params.push(opts.since); }
    if (opts.until) { sql += ' AND computed_at <= ?'; params.push(opts.until); }
    sql += ' GROUP BY target ORDER BY score DESC LIMIT 100';
    const rows = db.raw.prepare(sql).all(...params) as any[];
    for (const r of rows) {
      console.log(`${String(r.score).padStart(3)}  ${r.target}   ${r.computed_at}`);
    }
    console.error(`\n${rows.length} target(s)`);
  } else if (opts.cmd === 'cves') {
    // CVE rollup — read from the `cves` table populated by cve-rollup.ts.
    // Ordered by severity rank (critical→low), then CVSS desc.
    let sql = `
      SELECT target, cve_id, severity, cvss, tools, hit_count, exploit, last_seen
      FROM cves WHERE 1=1
    `;
    const params: unknown[] = [];
    if (opts.severity) { sql += ' AND severity = ?'; params.push(opts.severity); }
    if (opts.since) { sql += ' AND last_seen >= ?'; params.push(opts.since); }
    if (opts.until) { sql += ' AND last_seen <= ?'; params.push(opts.until); }
    sql += `
      ORDER BY CASE severity
        WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
        cvss DESC, target, cve_id`;
    const rows = db.raw.prepare(sql).all(...params) as any[];
    for (const r of rows) {
      const excl = r.exploit ? ' [EXPLOIT]' : '';
      const cvss = r.cvss ? ` cvss=${r.cvss}` : '';
      console.log(`[${r.severity ?? '-'}]  ${r.cve_id}  ${r.target}  ${r.tools}  (hit ${r.hit_count})${cvss}${excl}`);
    }
    console.error(`\n${rows.length} unique (target, cve) row(s)`);
  } else if (opts.cmd === 'new-since') {
    // Differential digest — rows where the (target, tool, category, title)
    // combo was FIRST seen at/after --since. Effectively "what's genuinely
    // new since <date>", not just "what showed up again on a rescan".
    if (!opts.since) { console.error('new-since needs a date, e.g. `query new-since 2026-08-19`'); process.exit(1); }
    const sql = `
      WITH firsts AS (
        SELECT tool, target, COALESCE(category,'') cat, title, MIN(seen_at) first_seen
        FROM findings GROUP BY tool, target, cat, title
      )
      SELECT f.seen_at, f.tool, f.target, f.severity, f.title, f.cve
      FROM findings f
      JOIN firsts fi ON fi.tool = f.tool AND fi.target = f.target
                    AND COALESCE(f.category,'') = fi.cat AND fi.title = f.title
                    AND fi.first_seen = f.seen_at
      WHERE fi.first_seen >= ?
      ${opts.severity ? 'AND f.severity = ?' : ''}
      ${opts.tool ? 'AND f.tool = ?' : ''}
      ORDER BY CASE f.severity
        WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
        f.seen_at DESC
    `;
    const params: unknown[] = [opts.since];
    if (opts.severity) params.push(opts.severity);
    if (opts.tool) params.push(opts.tool);
    const rows = db.raw.prepare(sql).all(...params) as any[];
    for (const r of rows) {
      console.log(`${r.seen_at}  [${r.severity ?? '-'}]  ${r.tool}  ${r.target}  ${r.title}${r.cve ? '  ' + r.cve : ''}`);
    }
    console.error(`\n${rows.length} NEW finding(s) since ${opts.since}`);
  } else if (opts.cmd === 'cert-peers') {
    // Certificates deployed to more than one host — blast radius mapping. A
    // stolen private key or a mis-issuance affects every host in the group.
    const focus = (opts as { certPeerFocus?: string }).certPeerFocus;
    if (focus) {
      // Single-host mode: for each cert this host presents, list every OTHER
      // host that presents the same fingerprint.
      const sql = `
        SELECT c.fingerprint_sha256, c.common_name, c.not_after, c.san_json,
               (SELECT GROUP_CONCAT(target) FROM certificates
                WHERE fingerprint_sha256 = c.fingerprint_sha256 AND target != ?) AS peers,
               (SELECT COUNT(DISTINCT target) FROM certificates
                WHERE fingerprint_sha256 = c.fingerprint_sha256) AS host_count
        FROM certificates c
        WHERE c.target = ?
        ORDER BY host_count DESC
      `;
      const rows = db.raw.prepare(sql).all(focus, focus) as any[];
      for (const r of rows) {
        const fp = r.fingerprint_sha256 ? String(r.fingerprint_sha256).slice(0, 16) : '(no-fp)';
        console.log(`fp=${fp}  cn=${r.common_name ?? '-'}  expires=${r.not_after ?? '-'}  peers=${r.host_count}`);
        if (r.peers) for (const p of String(r.peers).split(',')) console.log(`  ${p}`);
      }
      console.error(`\n${rows.length} certificate(s) for ${focus}`);
    } else {
      // Estate mode: any fingerprint deployed to > 1 host, ranked by fan-out.
      const sql = `
        SELECT fingerprint_sha256, common_name, MIN(not_after) not_after,
               COUNT(DISTINCT target) hosts,
               GROUP_CONCAT(DISTINCT target) targets
        FROM certificates
        WHERE fingerprint_sha256 IS NOT NULL
        GROUP BY fingerprint_sha256
        HAVING hosts > 1
        ORDER BY hosts DESC
        LIMIT 50
      `;
      const rows = db.raw.prepare(sql).all() as any[];
      for (const r of rows) {
        const fp = String(r.fingerprint_sha256).slice(0, 16);
        const preview = String(r.targets).split(',').slice(0, 4).join(', ');
        const tail = r.hosts > 4 ? `, +${r.hosts - 4} more` : '';
        console.log(`hosts=${String(r.hosts).padStart(3)}  cn=${r.common_name ?? '-'}  fp=${fp}...  → ${preview}${tail}`);
      }
      console.error(`\n${rows.length} shared certificate(s)`);
    }
  } else if (opts.cmd === 'runs') {
    const rows = db.raw
      .prepare('SELECT id, tool, started_at, finished_at, targets_count, findings_count FROM runs ORDER BY id DESC LIMIT 20')
      .all() as any[];
    for (const r of rows) {
      console.log(`#${r.id}  ${r.tool}  ${r.started_at} -> ${r.finished_at ?? '(running)'}  ${r.targets_count}t/${r.findings_count}f`);
    }
  } else if (opts.cmd === 'review') {
    // Human-review queue: findings the scanner suspects are false positives
    // (catch-all responders, decoy pages, echoing SPAs). Shows the preserved
    // body preview + real HTTP status so a human can confirm or dismiss.
    let sql = `
      SELECT tool, target, severity, title, matched_at, meta_json, seen_at
      FROM findings
      WHERE needs_review = 1
    `;
    const params: unknown[] = [];
    if (opts.since) { sql += ' AND seen_at >= ?'; params.push(opts.since); }
    if (opts.until) { sql += ' AND seen_at <= ?'; params.push(opts.until); }
    if (opts.tool) { sql += ' AND tool = ?'; params.push(opts.tool); }
    if (opts.target) { sql += ' AND target = ?'; params.push(opts.target); }
    sql += ' ORDER BY target, seen_at DESC, id';
    const limit = opts.limit ?? 20;
    sql += ' LIMIT ?'; params.push(limit);
    const rows = db.raw.prepare(sql).all(...params) as any[];
    for (const r of rows) {
      let meta: Record<string, unknown> | null = null;
      try { meta = r.meta_json ? JSON.parse(r.meta_json) : null; } catch { /* ignore */ }
      const bodyStatus = meta?.body_status ?? '?';
      const cluster = meta?.near_cluster_count;
      const confirmed = meta?.confirmed_fake ? '  [CONFIRMED FAKE — body hash matched canary]' : '';
      const clusterTag = cluster ? `  (${cluster} similar responses)` : '';
      console.log('─'.repeat(80));
      console.log(`${r.target}  ${r.tool}  [${r.severity ?? '-'}]  ${r.seen_at}`);
      console.log(`  ${r.title}`);
      console.log(`  matched_at: ${r.matched_at ?? '-'}`);
      console.log(`  real HTTP status when re-fetched: ${bodyStatus}${clusterTag}${confirmed}`);
      const canary = meta?.canary as { url?: string; status?: number; size?: number; hash?: string } | undefined;
      if (canary) {
        console.log(`  canary: ${canary.url}  status=${canary.status}  size=${canary.size}b  hash=${(canary.hash ?? '').slice(0, 16)}...`);
      }
      const preview = meta?.body_preview;
      if (typeof preview === 'string' && preview.length) {
        // Trim runs of blank space so the console output stays compact but
        // preserve enough that the reviewer can eyeball what was actually
        // served (page title, form action, error message, etc.).
        const compact = preview.replace(/\s+/g, ' ').trim();
        const shown = compact.length > 800 ? compact.slice(0, 800) + '…' : compact;
        console.log(`  body (first ${preview.length}B): ${shown}`);
      } else {
        console.log('  body: (not preserved — either not fetched or fetch failed)');
      }
    }
    if (!rows.length) console.error('\nNothing awaiting review.');
    else console.error(`\n${rows.length} finding(s) awaiting manual review (limit ${limit})`);
  } else if (opts.cmd === 'sql') {
    if (!opts.sql) { console.error('sql command requires a query string'); process.exit(1); }
    try {
      const rows = db.raw.prepare(opts.sql).all();
      for (const row of rows) console.log(JSON.stringify(row));
      console.error(`\n${rows.length} row(s)`);
    } catch (e: unknown) {
      console.error('SQL error:', e instanceof Error ? e.message : String(e));
      process.exit(1);
    }
  }
  db.close();
}

main();
