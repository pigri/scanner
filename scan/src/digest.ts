#!/usr/bin/env -S node --loader tsx
// digest: compact "what changed" report for a time window. Turns `query
// new-since` into a hand-offable markdown (and HTML) document — severity
// totals, top-N hosts, top-N new CVEs, per-tool deltas.
//
// Meant to run after scan-rescan.timer completes each Sunday (or on demand).
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

interface DigestRow {
  seen_at: string; tool: string; target: string;
  severity: string | null; title: string; cve: string | null;
}
interface CveRow {
  target: string; cve_id: string; severity: string | null; cvss: number | null;
  tools: string; exploit: number; first_seen: string;
  description: string | null; nvd_cvss: number | null;
}

function usage(): void {
  console.error(`Usage: digest --sqlite <path> [--since <iso>] [--out-dir reports]

Emits a markdown + HTML digest of everything genuinely new (findings whose
earliest seen_at is >= --since). Default window: last 7 days.

Options:
  --sqlite <path>   default: scan.db
  --since <iso>     default: 7 days before now
  --out-dir <dir>   default: reports/
`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let dbPath = 'scan.db';
  let sinceIso: string | null = null;
  let outDir = 'reports';
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h' || a === '--help') { usage(); process.exit(0); }
    if (a === '--sqlite' || a === '--db') dbPath = argv[++i]!;
    else if (a === '--since') sinceIso = argv[++i]!;
    else if (a === '--out-dir') outDir = argv[++i]!;
  }
  const since = sinceIso ?? new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();

  const db = new Database(dbPath, { readonly: true });

  // ─── Δ findings — first sighting at or after `since` ─────────────────────
  const newFindings = db.prepare(`
    WITH firsts AS (
      SELECT tool, target, COALESCE(category,'') cat, title, MIN(seen_at) first_seen
      FROM findings GROUP BY tool, target, cat, title
    )
    SELECT f.seen_at, f.tool, f.target, f.severity, f.title, f.cve
    FROM findings f
    JOIN firsts fi ON fi.tool=f.tool AND fi.target=f.target
                  AND COALESCE(f.category,'')=fi.cat AND fi.title=f.title
                  AND fi.first_seen=f.seen_at
    WHERE fi.first_seen >= ?
    ORDER BY CASE f.severity
      WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
      f.seen_at DESC
  `).all(since) as DigestRow[];

  // ─── Δ CVE rows (first_seen >= window) ───────────────────────────────────
  const newCves = db.prepare(`
    SELECT target, cve_id, severity, cvss, tools, exploit, first_seen,
           description, nvd_cvss
    FROM cves WHERE first_seen >= ?
    ORDER BY CASE severity
      WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
      COALESCE(nvd_cvss, cvss) DESC
  `).all(since) as CveRow[];

  // ─── Aggregates ──────────────────────────────────────────────────────────
  const bySev = new Map<string, number>();
  const byTool = new Map<string, number>();
  const byTarget = new Map<string, { crit: number; high: number; med: number; total: number }>();
  for (const f of newFindings) {
    bySev.set(f.severity ?? 'unknown', (bySev.get(f.severity ?? 'unknown') ?? 0) + 1);
    byTool.set(f.tool, (byTool.get(f.tool) ?? 0) + 1);
    const t = byTarget.get(f.target) ?? { crit: 0, high: 0, med: 0, total: 0 };
    t.total++;
    if (f.severity === 'critical') t.crit++;
    else if (f.severity === 'high') t.high++;
    else if (f.severity === 'medium') t.med++;
    byTarget.set(f.target, t);
  }
  const topHosts = [...byTarget.entries()]
    .sort((a, b) => (b[1].crit - a[1].crit) || (b[1].high - a[1].high) || (b[1].total - a[1].total))
    .slice(0, 15);
  const topSeverities = ['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, bySev.get(s) ?? 0] as const);
  const toolRows = [...byTool.entries()].sort((a, b) => b[1] - a[1]);

  const runs = db.prepare(
    `SELECT tool, COUNT(*) runs FROM runs WHERE started_at >= ? GROUP BY tool ORDER BY runs DESC`
  ).all(since) as { tool: string; runs: number }[];

  db.close();

  // ─── Render markdown ─────────────────────────────────────────────────────
  const now = new Date().toISOString();
  const stamp = now.slice(0, 10);
  const md: string[] = [];
  const pushHdr = (h: string): number => md.push(`## ${h}\n`);
  const pushLine = (l: string): number => md.push(`${l}`);
  const pushRow = (l: string): number => md.push(l);

  md.push(`# Weekly digest — ${stamp}\n`);
  md.push(`**Window:** ${since} → ${now}\n`);
  md.push(`**New findings:** ${newFindings.length}\n`);
  md.push(`**New CVEs (target × cve):** ${newCves.length}\n`);
  md.push('');
  pushHdr('Severity');
  md.push('');
  md.push('| Severity | Count |');
  md.push('|----------|------:|');
  for (const [s, n] of topSeverities) if (n) md.push(`| ${s} | ${n} |`);
  md.push('');

  if (topHosts.length) {
    pushHdr('Top hosts (by critical → high → total)');
    md.push('');
    md.push('| Host | critical | high | medium | total |');
    md.push('|------|---------:|-----:|-------:|------:|');
    for (const [host, t] of topHosts) md.push(`| ${host} | ${t.crit} | ${t.high} | ${t.med} | ${t.total} |`);
    md.push('');
  }

  const critCves = newCves.filter((c) => c.severity === 'critical').slice(0, 25);
  if (critCves.length) {
    pushHdr('New critical CVEs');
    md.push('');
    md.push('| Host | CVE | CVSS | Description |');
    md.push('|------|-----|-----:|-------------|');
    for (const c of critCves) {
      const cvss = c.nvd_cvss ?? c.cvss ?? '-';
      const desc = (c.description ?? '').slice(0, 110).replace(/\|/g, '\\|').replace(/\n/g, ' ');
      const excl = c.exploit ? ' **[EXPLOIT]**' : '';
      md.push(`| \`${c.target}\` | ${c.cve_id}${excl} | ${cvss} | ${desc || '_(not yet enriched)_'} |`);
    }
    md.push('');
  }

  const highCves = newCves.filter((c) => c.severity === 'high').slice(0, 20);
  if (highCves.length) {
    pushHdr('New high CVEs (top 20)');
    md.push('');
    md.push('| Host | CVE | CVSS |');
    md.push('|------|-----|-----:|');
    for (const c of highCves) {
      const cvss = c.nvd_cvss ?? c.cvss ?? '-';
      md.push(`| \`${c.target}\` | ${c.cve_id}${c.exploit ? ' **[EXPLOIT]**' : ''} | ${cvss} |`);
    }
    md.push('');
  }

  if (toolRows.length) {
    pushHdr('Deltas by tool');
    md.push('');
    md.push('| Tool | New findings |');
    md.push('|------|-------------:|');
    for (const [tool, n] of toolRows) md.push(`| ${tool} | ${n} |`);
    md.push('');
  }

  if (runs.length) {
    pushHdr('Runs in the window');
    md.push('');
    md.push('| Tool | Runs |');
    md.push('|------|-----:|');
    for (const r of runs) md.push(`| ${r.tool} | ${r.runs} |`);
    md.push('');
  }

  if (!newFindings.length && !newCves.length) {
    md.push('*Nothing genuinely new since the previous window. Estate stable.*\n');
  }

  const mdText = md.join('\n');

  // ─── Write markdown + HTML ───────────────────────────────────────────────
  fs.mkdirSync(outDir, { recursive: true });
  const mdPath = path.join(outDir, `digest-${stamp}.md`);
  const htmlPath = path.join(outDir, `digest-${stamp}.html`);
  fs.writeFileSync(mdPath, mdText);

  // Cheap HTML wrapper — the report-worker knows how to render our .md but
  // we ship an .html too for direct-open convenience. Basic table CSS only.
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Digest ${stamp}</title>
<style>
body { font: 13px/1.5 -apple-system, sans-serif; max-width: 1000px; margin: 24px auto; padding: 0 20px; color: #1a1a1a; }
h1 { border-bottom: 2px solid #b00020; padding-bottom: 6px; }
h2 { margin-top: 22px; border-bottom: 1px solid #ddd; padding-bottom: 3px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 12px; }
th, td { border: 1px solid #d0d0d5; padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: #eef1f5; }
tr:nth-child(even) td { background: #fafafa; }
code { background: #f2f2f5; padding: 1px 4px; border-radius: 3px; font-family: ui-monospace, monospace; }
strong { color: #b00020; }
</style></head><body>${mdToHtml(mdText)}</body></html>`;
  fs.writeFileSync(htmlPath, html);

  console.error(`digest window: ${since} → ${now}`);
  console.error(`  new findings: ${newFindings.length} (${topSeverities.filter(([, n]) => n).map(([s, n]) => `${s}=${n}`).join(' ')})`);
  console.error(`  new CVEs:     ${newCves.length}`);
  console.error(`  wrote ${mdPath}`);
  console.error(`  wrote ${htmlPath}`);
}

// Tiny markdown → HTML shim so we don't take a runtime dep. Handles headers,
// pipe tables, code spans, bold, blockquotes, italic. Good enough for our
// digest shape — anything richer, use the markdown-it path in mk-html.mjs.
function mdToHtml(md: string): string {
  const lines = md.split('\n');
  const out: string[] = [];
  let inTable = false; let tableCols = 0;
  const inline = (s: string): string => s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g, '<em>$1</em>');
  for (const raw of lines) {
    const line = raw;
    if (line.startsWith('# ')) { out.push(`<h1>${inline(line.slice(2))}</h1>`); continue; }
    if (line.startsWith('## ')) { out.push(`<h2>${inline(line.slice(3))}</h2>`); continue; }
    if (/^\|.*\|$/.test(line)) {
      const cells = line.slice(1, -1).split('|').map((c) => c.trim());
      if (/^:?-+:?$/.test(cells[0] ?? '') && cells.every((c) => /^:?-+:?$/.test(c))) continue;
      if (!inTable) { out.push('<table>'); inTable = true; tableCols = cells.length; out.push('<thead><tr>' + cells.map((c) => `<th>${inline(c)}</th>`).join('') + '</tr></thead><tbody>'); continue; }
      out.push('<tr>' + cells.map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>');
      continue;
    } else if (inTable) { out.push('</tbody></table>'); inTable = false; tableCols = 0; }
    if (line.trim() === '') { out.push(''); continue; }
    if (line.startsWith('> ')) { out.push(`<blockquote>${inline(line.slice(2))}</blockquote>`); continue; }
    out.push(`<p>${inline(line)}</p>`);
  }
  if (inTable) out.push('</tbody></table>');
  return out.join('\n');
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
