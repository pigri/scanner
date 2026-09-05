#!/usr/bin/env -S node --loader tsx
// query-secrets: single-command inventory of every secret / credential /
// sensitive-file exposure across the scan corpus. Union of every tool that
// can surface a leak, classified into a shared taxonomy so a reviewer sees
// one flat list per host regardless of which detector fired.
//
// Sources folded in:
//   - `secrets`          — gitleaks + trufflehog raw hits
//   - `vendor-key-enrich`— per-vendor capability enumeration (github/slack/aws/openai/anthropic)
//   - `gapi-key-check`   — Google API surface enumeration
//   - `nuclei`           — templates that flag exposed configs, backups,
//                          debug pages, embedded API keys
//   - `content-sigs`     — bytewise signatures for docker-compose / .env / etc.
//   - `ffuf`             — sensitive-path hits (`.git/`, `.svn/`, `.env`,
//                          wp-config backups, credentials.json…). Downgraded
//                          401/403 rows stay in the report but marked so a
//                          reviewer can tell "server refused" from "leaked".
//
// Deliberately excluded:
//   - `checkdmarc` / `sslyze` / `headers` — email/TLS posture, not leaks.
//   - `nuclei` info-level detection-only templates (dkim-record-detect etc.).

import fs from 'node:fs';
import { openDb, type Db } from './lib/db.js';

interface Row {
  host: string;
  tool: string;
  category: string;
  severity: string;
  title: string;
  matched_at: string | null;
  seen_at: string;
  needs_review: number;
}

// One SELECT unioning every leak-class category. Kept as a single SQL query
// so it's easy to audit which classes are counted; add a category here and
// it shows up in the report immediately.
const QUERY = `
  SELECT target AS host, tool, category, severity, title, matched_at, seen_at, needs_review
    FROM findings
   WHERE tool IN ('secrets', 'vendor-key-enrich', 'gapi-key-check')
      OR (tool = 'nuclei' AND (
             category LIKE '%api-key%'
          OR category LIKE '%exposure%'
          OR category LIKE '%wp-config%'
          OR category LIKE '%wpconfig%'
          OR category LIKE '%backup%'
          OR category LIKE '%dump%'
          OR category LIKE '%debug%'
          OR category LIKE '%infoleak%'
          OR category LIKE 'firebase-%'
          OR category LIKE '%docker-compose%'
          OR category LIKE '%dockerfile%'
          OR category LIKE '%env-file%'
          OR category IN ('composer-config', 'behat-config', 'gruntfile-exposure',
                          'npm-shrinkwrap-exposure', 'browserconfig-xml',
                          'htaccess-config', 'web-config', 'wp-cli-exposure',
                          'zip-backup-files', 'backup-directory-listing')
          )
      )
      OR (tool = 'content-sigs' AND category LIKE 'exposure-%')
      OR (tool = 'ffuf' AND (
             category LIKE 'path-2%'
          OR (category LIKE 'path-4%' AND severity IN ('low', 'medium', 'high', 'critical'))
          )
      )
   ORDER BY
     CASE severity
       WHEN 'critical' THEN 0
       WHEN 'high'     THEN 1
       WHEN 'medium'   THEN 2
       WHEN 'low'      THEN 3
       WHEN 'info'     THEN 4
       ELSE 5
     END,
     host, tool, seen_at DESC
`;

interface Opts { db: string; format: 'table' | 'markdown' | 'json' | 'csv'; host: string | null; sinceIso: string | null; showLow: boolean; help?: boolean }

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { db: 'scan.db', format: 'table', host: null, sinceIso: null, showLow: true };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--db' || a === '--sqlite') opts.db = next();
    else if (a === '--format' || a === '-f') opts.format = next() as Opts['format'];
    else if (a === '--host') opts.host = next();
    else if (a === '--since') opts.sinceIso = next();
    else if (a === '--no-low') opts.showLow = false;
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: query-secrets [options]

Inventory every credential / secret / sensitive-file exposure across the
scan corpus. Union of gitleaks + trufflehog + vendor-key-enrich +
gapi-key-check + nuclei exposure templates + content-sigs + ffuf
sensitive-path hits.

Options:
  --db <path>          scan.db path (default: scan.db)
  --format <fmt>       table | markdown | json | csv (default: table)
  --host <host>        Filter to one host
  --since <iso-date>   Only rows first seen at/after this date
  --no-low             Suppress low + info rows
`);
}

function formatTable(rows: Row[]): string {
  if (!rows.length) return '(no secret findings)';
  const cols: Array<[string, keyof Row, number]> = [
    ['SEVERITY', 'severity', 8],
    ['HOST', 'host', 32],
    ['TOOL', 'tool', 18],
    ['CATEGORY', 'category', 30],
    ['TITLE', 'title', 90],
  ];
  const header = cols.map(([h, , w]) => h.padEnd(w)).join('  ');
  const lines = [header, '-'.repeat(header.length)];
  for (const r of rows) {
    const line = cols.map(([, k, w]) => String(r[k] ?? '').slice(0, w).padEnd(w)).join('  ');
    lines.push(line);
  }
  return lines.join('\n');
}

function formatMarkdown(rows: Row[], counts: Record<string, number>): string {
  const lines: string[] = [];
  lines.push('# Secret findings inventory\n');
  lines.push(`Total: ${rows.length}`);
  lines.push(`Breakdown: ${Object.entries(counts).map(([k, v]) => `**${k}** ${v}`).join(' · ')}\n`);
  const byHost = new Map<string, Row[]>();
  for (const r of rows) {
    if (!byHost.has(r.host)) byHost.set(r.host, []);
    byHost.get(r.host)!.push(r);
  }
  for (const [host, hostRows] of byHost) {
    lines.push(`## \`${host}\``);
    lines.push('');
    lines.push('| severity | tool | category | title | matched_at |');
    lines.push('|---|---|---|---|---|');
    for (const r of hostRows) {
      const title = r.title.replace(/\|/g, '\\|').slice(0, 140);
      const mAt = (r.matched_at ?? '').replace(/\|/g, '\\|').slice(0, 80);
      lines.push(`| **${r.severity}** | ${r.tool} | ${r.category} | ${title} | \`${mAt}\` |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }
  if (!fs.existsSync(opts.db)) { console.error(`db not found: ${opts.db}`); process.exit(1); }

  const db: Db = openDb(opts.db);
  let rows = db.raw.prepare(QUERY).all() as Row[];
  if (opts.host) rows = rows.filter((r) => r.host === opts.host);
  if (opts.sinceIso) rows = rows.filter((r) => r.seen_at >= opts.sinceIso!);
  if (!opts.showLow) rows = rows.filter((r) => r.severity !== 'low' && r.severity !== 'info');

  // Dedupe (host, tool, category, title) — findings are append-only so the
  // same leak recurs on every rescan; keep the freshest row.
  const seen = new Map<string, Row>();
  for (const r of rows) {
    const key = `${r.host}|${r.tool}|${r.category}|${r.title}`;
    const prev = seen.get(key);
    if (!prev || r.seen_at > prev.seen_at) seen.set(key, r);
  }
  rows = [...seen.values()].sort((a, b) => {
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const d = sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity);
    if (d !== 0) return d;
    return a.host.localeCompare(b.host);
  });

  const counts: Record<string, number> = {};
  for (const r of rows) counts[r.severity] = (counts[r.severity] ?? 0) + 1;

  switch (opts.format) {
    case 'json': console.log(JSON.stringify({ rows, counts }, null, 2)); break;
    case 'csv': {
      console.log('severity,host,tool,category,title,matched_at,seen_at,needs_review');
      for (const r of rows) {
        const esc = (s: string): string => /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        console.log([r.severity, r.host, r.tool, r.category, r.title, r.matched_at ?? '', r.seen_at, r.needs_review].map((v) => esc(String(v))).join(','));
      }
      break;
    }
    case 'markdown': console.log(formatMarkdown(rows, counts)); break;
    case 'table':
    default:
      console.log(`Total: ${rows.length} findings · ${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(' ')}\n`);
      console.log(formatTable(rows));
      break;
  }
  db.close();
}

main();
