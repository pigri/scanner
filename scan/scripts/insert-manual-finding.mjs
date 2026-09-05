#!/usr/bin/env node
// Insert a single manual finding (tool='manual') into scan.db.
// usage: insert-manual-finding.mjs --target <t> --severity <s> --title <t> [--category <c>] [--cve <c>] [--matched-at <url>] [--meta '<json>'] [--sqlite scan.db]
import Database from '../node_modules/better-sqlite3/lib/index.js';

const argv = process.argv.slice(2);
const opts = { sqlite: 'scan.db', category: 'manual' };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const v = argv[++i];
  if (a === '--target') opts.target = v;
  else if (a === '--severity') opts.severity = v;
  else if (a === '--title') opts.title = v;
  else if (a === '--category') opts.category = v;
  else if (a === '--cve') opts.cve = v;
  else if (a === '--matched-at') opts.matched_at = v;
  else if (a === '--meta') opts.meta_json = v;
  else if (a === '--sqlite') opts.sqlite = v;
}
if (!opts.target || !opts.severity || !opts.title) {
  console.error('missing --target / --severity / --title'); process.exit(2);
}
const db = new Database(opts.sqlite);
const nowIso = new Date().toISOString();
const stmt = db.prepare(`
  INSERT INTO findings (tool, target, category, severity, title, cve, matched_at, meta_json, seen_at, run_id)
  VALUES ('manual', @target, @category, @severity, @title, @cve, @matched_at, @meta_json, @seen_at, NULL)
`);
const info = stmt.run({
  target: opts.target,
  category: opts.category ?? null,
  severity: opts.severity,
  title: opts.title,
  cve: opts.cve ?? null,
  matched_at: opts.matched_at ?? null,
  meta_json: opts.meta_json ?? null,
  seen_at: nowIso,
});
console.log(`inserted id=${info.lastInsertRowid} tool=manual target=${opts.target} sev=${opts.severity} at=${nowIso}`);
