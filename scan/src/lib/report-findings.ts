import type Database from 'better-sqlite3';
import { currentFindingsSelect, findingsRuleOpts } from './current-findings.js';
import type { ReportFinding } from './report.js';

/**
 * A target's open logical findings, the nuclei family merged: the same set the
 * UI detail page counts as open. Resolved findings are left out, so the report
 * agrees with the risk score beside it.
 */
export function openReportFindings(raw: Database.Database, target: string): ReportFinding[] {
  return raw
    .prepare(
      `SELECT severity, tool, title, cve
       FROM (${currentFindingsSelect({ ...findingsRuleOpts(raw), targetParam: '@t' })})
       WHERE resolved = 0`,
    )
    .all({ t: target }) as ReportFinding[];
}
