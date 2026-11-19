import { describe, it, expect } from 'vitest';
import { currentFindingsSelect, watermarkSelect } from '../src/lib/current-findings.js';

// The SQL text main shipped before partial runs existed. partial:false MUST keep it
// byte for byte, so a DB without markers runs the same query plan as before.
const LEGACY: Record<string, string> = {
  "false|undefined": "SELECT t.target, t.tool,\n         CASE WHEN t.tool IN ('synthesize-eol','manual','manual-triage') THEN '' ELSE t.tmax END AS w\n         FROM (SELECT target, tool, MAX(seen_at) tmax FROM findings GROUP BY target, tool) t",
  "false|@t": "SELECT t.target, t.tool,\n         CASE WHEN t.tool IN ('synthesize-eol','manual','manual-triage') THEN '' ELSE t.tmax END AS w\n         FROM (SELECT target, tool, MAX(seen_at) tmax FROM findings WHERE target = @t GROUP BY target, tool) t",
  "true|undefined": "SELECT t.target, t.tool,\n         CASE WHEN t.tool IN ('synthesize-eol','manual','manual-triage') THEN '' ELSE COALESCE(c.seen_at, t.tmax) END AS w\n         FROM (SELECT target, tool, MAX(seen_at) tmax FROM findings GROUP BY target, tool) t LEFT JOIN tool_coverage c ON c.target = t.target AND c.tool = t.tool",
  "true|@t": "SELECT t.target, t.tool,\n         CASE WHEN t.tool IN ('synthesize-eol','manual','manual-triage') THEN '' ELSE COALESCE(c.seen_at, t.tmax) END AS w\n         FROM (SELECT target, tool, MAX(seen_at) tmax FROM findings WHERE target = @t GROUP BY target, tool) t LEFT JOIN tool_coverage c ON c.target = t.target AND c.tool = t.tool",
};

describe('watermarkSelect with partial:false', () => {
  for (const coverage of [false, true]) {
    for (const targetParam of [undefined, '@t']) {
      it(`is byte-identical to the legacy text (coverage=${coverage}, target=${targetParam})`, () => {
        const extra = targetParam ? { targetParam } : {};
        const sql = watermarkSelect({ coverage, partial: false, ...extra });
        expect(sql).toBe(LEGACY[`${coverage}|${targetParam}`]);
        expect(currentFindingsSelect({ coverage, partial: false, ...extra })).toContain(sql);
      });
    }
  }
});
