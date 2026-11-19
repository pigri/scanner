import { it, expect } from 'vitest';
import { openDb } from '../src/lib/db.js';
import { currentFindingsSelect, findingsRuleOpts } from '../src/lib/current-findings.js';
it('a partial nuclei-url run does not close an older url-pass finding (merged key)', () => {
  const db = openDb(':memory:');
  const r1 = db.startRun('nuclei', {}, '2026-01-01T00:00:00.000Z');
  db.insertFinding({ tool: 'nuclei-url', target: 'a.example.com', title: 'old', severity: 'high' }, '2026-01-01T00:00:00.000Z', r1);
  db.finishRun(r1, { partial: false });
  const r2 = db.startRun('nuclei', {}, '2026-01-02T00:00:00.000Z');
  db.insertFinding({ tool: 'nuclei-url', target: 'a.example.com', title: 'new', severity: 'low' }, '2026-01-02T00:00:00.000Z', r2);
  db.finishRun(r2, { partial: true });
  const rows = db.raw.prepare(currentFindingsSelect(findingsRuleOpts(db.raw))).all() as { title: string; resolved: number; tool: string }[];
  expect(rows.map((r) => `${r.tool}/${r.title}:${r.resolved}`).sort()).toEqual(['nuclei/new:0', 'nuclei/old:0']);
});
