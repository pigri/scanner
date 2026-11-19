import type Database from 'better-sqlite3';
import { currentFindingsSelect, findingsRuleOpts, watermarkSelect } from './current-findings.js';
import { keyOf } from './resolved.js';
import type { ReportFinding } from './report.js';

/**
 * A target's open logical findings, the nuclei family merged: the same set the
 * UI detail page counts as open. Resolved findings are left out, so the report
 * agrees with the risk score beside it. The cve cell lists every distinct CVE
 * of the finding's current rows (a template with several CVEs writes one row
 * per CVE); a CVE seen only on a row older than the watermark is left out.
 */
export function openReportFindings(raw: Database.Database, target: string): ReportFinding[] {
  const opts = { ...findingsRuleOpts(raw), targetParam: '@t' };
  const rows = raw
    .prepare(
      `SELECT severity, tool, category, title, cve
       FROM (${currentFindingsSelect(opts)})
       WHERE resolved = 0`,
    )
    .all({ t: target }) as (ReportFinding & { category: string | null })[];
  const current = raw
    .prepare(
      `SELECT f.tool, f.category, f.title, f.cve
       FROM findings f JOIN (${watermarkSelect(opts)}) wm ON wm.target = f.target AND wm.tool = f.tool
       WHERE f.target = @t AND f.seen_at >= wm.w AND f.cve IS NOT NULL AND f.cve != ''`,
    )
    .all({ t: target }) as { tool: string; category: string | null; title: string; cve: string }[];
  const cves = new Map<string, Set<string>>();
  for (const r of current) {
    const k = keyOf({ tool: r.tool, category: r.category ?? '', title: r.title });
    const set = cves.get(k);
    if (set) set.add(r.cve);
    else cves.set(k, new Set([r.cve]));
  }
  return rows.map(({ category, ...f }) => {
    const set = cves.get(keyOf({ tool: f.tool, category: category ?? '', title: f.title }));
    return { ...f, cve: set ? [...set].sort().join(', ') : f.cve };
  });
}
