#!/usr/bin/env node
// Export findings CSV WITHOUT tool column (for external audiences).
// Filters by seen_at window if --since / --until supplied.
import fs from 'node:fs';
import Database from '../node_modules/better-sqlite3/lib/index.js';

const argv = process.argv.slice(2);
let dbPath = 'scan.db';
let outFile = null;
let since = null;
let until = null;
let minSev = 'info';
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--sqlite' || a === '--db') dbPath = argv[++i];
  else if (a === '--out') outFile = argv[++i];
  else if (a === '--since') since = argv[++i];
  else if (a === '--until') until = argv[++i];
  else if (a === '--min-severity') minSev = argv[++i];
}
if (!outFile) {
  console.error('usage: export-findings-notool.mjs --out <file> [--since <iso>] [--until <iso>] [--min-severity info|low|medium|high|critical]');
  process.exit(2);
}
const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const min = rank[minSev] ?? 0;

function csv(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

const db = new Database(dbPath, { readonly: true });
const where = [];
const params = {};
if (since) { where.push('f.seen_at >= @since'); params.since = since; }
if (until) { where.push('f.seen_at <= @until'); params.until = until; }
const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

const rows = db.prepare(`
  SELECT f.severity, f.target, COALESCE(f.category,'') category, f.title,
         COALESCE(f.cve,'') cve, COALESCE(f.matched_at,'') matched_at, f.seen_at,
         c.cvss AS internal_cvss, c.nvd_cvss AS nvd_cvss,
         c.exploit AS exploit, c.description AS description, c.published_at AS published_at
  FROM findings f
  LEFT JOIN cves c ON f.cve IS NOT NULL AND f.cve != '' AND c.target = f.target AND c.cve_id = f.cve
  ${whereSql}
  ORDER BY CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
    COALESCE(c.nvd_cvss, c.cvss, 0) DESC,
    f.target, f.seen_at DESC
`).all(params);

const header = ['severity','cvss','cve','target','category','title','matched_at','seen_at','exploit','description','published_at'];
const out = fs.createWriteStream(outFile);
out.write(header.join(',') + '\n');
let written = 0;
for (const r of rows) {
  if ((rank[r.severity] ?? 0) < min) continue;
  const cvss = r.nvd_cvss ?? r.internal_cvss ?? '';
  out.write([
    csv(r.severity),
    csv(cvss),
    csv(r.cve),
    csv(r.target),
    csv(r.category),
    csv(r.title),
    csv(r.matched_at),
    csv(r.seen_at),
    csv(r.exploit ? 'yes' : ''),
    csv((r.description || '').replace(/\s+/g,' ').slice(0,500)),
    csv(r.published_at || ''),
  ].join(',') + '\n');
  written++;
}
out.end();
out.on('finish', () => console.log(`${outFile}\t${written} row(s)`));
