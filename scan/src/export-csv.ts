#!/usr/bin/env -S node --loader tsx
// export-csv: dump every finding as CSV, joined with NVD-enriched CVE data
// when available. One row per finding row (dedup within severity/target/cve
// happens at consumer time).
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

function usage(): void {
  console.error(`Usage: export-csv --sqlite <path> [--out <file>] [--min-severity <s>]

Emits a CSV with one row per findings row. When a finding has a cve, the
cves table is joined for NVD-enriched CVSS + description + published date.

Columns: severity, cvss, cve, target, tool, category, title, matched_at,
         seen_at, exploit, description

Options:
  --sqlite <path>       default: scan.db
  --out <file>          default: reports/findings-<date>.csv
  --min-severity <s>    only include rows at or above this severity (default: info)
`);
}

function csvEscape(v: unknown): string {
  if (v === null || v === undefined) return '';
  const s = String(v);
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let dbPath = 'scan.db';
  let outFile: string | null = null;
  let minSev = 'info';
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h' || a === '--help') { usage(); process.exit(0); }
    if (a === '--sqlite' || a === '--db') dbPath = argv[++i]!;
    else if (a === '--out') outFile = argv[++i]!;
    else if (a === '--min-severity') minSev = argv[++i]!;
  }
  const rank: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const min = rank[minSev] ?? 0;

  const db = new Database(dbPath, { readonly: true });
  const rows = db.prepare(`
    SELECT f.severity, f.tool, f.target, COALESCE(f.category,'') category, f.title,
           COALESCE(f.matched_at,'') matched_at, f.seen_at, COALESCE(f.cve,'') cve,
           c.cvss AS internal_cvss, c.nvd_cvss AS nvd_cvss,
           c.exploit AS exploit, c.description AS description, c.published_at AS published_at
    FROM findings f
    LEFT JOIN cves c ON f.cve IS NOT NULL AND f.cve != '' AND c.target = f.target AND c.cve_id = f.cve
    ORDER BY CASE f.severity
      WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
      COALESCE(c.nvd_cvss, c.cvss, 0) DESC,
      f.target, f.seen_at DESC
  `).all() as Array<{
    severity: string | null; tool: string; target: string; category: string; title: string;
    matched_at: string; seen_at: string; cve: string;
    internal_cvss: number | null; nvd_cvss: number | null;
    exploit: number | null; description: string | null; published_at: string | null;
  }>;

  const filtered = rows.filter((r) => (rank[r.severity ?? 'info'] ?? 0) >= min);

  const header = ['severity','cvss','cve','target','category','title','matched_at','seen_at','exploit','published_at','description'];
  const out: string[] = [header.join(',')];
  for (const r of filtered) {
    out.push([
      r.severity ?? '',
      r.nvd_cvss ?? r.internal_cvss ?? '',
      r.cve,
      r.target,
      r.category,
      r.title,
      r.matched_at,
      r.seen_at,
      r.exploit ? 'yes' : '',
      r.published_at ?? '',
      (r.description ?? '').replace(/[\r\n]+/g, ' ').slice(0, 800),
    ].map(csvEscape).join(','));
  }

  const now = new Date().toISOString().slice(0, 10);
  const target = outFile ?? path.join('reports', `findings-${now}.csv`);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, out.join('\n') + '\n');
  console.error(`export-csv done: ${filtered.length} row(s) → ${path.resolve(target)}`);
  db.close();
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
