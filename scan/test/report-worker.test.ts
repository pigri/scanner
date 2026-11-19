import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { currentFindingsSelect, findingsRuleOpts } from '../src/lib/current-findings.js';
import { run, tmpDb, T0, T1, T2 } from './helpers/cli-rule.js';

describe('report-worker', () => {
  it('counts open logical findings, the nuclei family merged, like the UI', () => {
    const { dir, file, db } = tmpDb();
    const t = 'host.example';
    const ins = (tool: string, title: string, at: string) =>
      db.raw.prepare(`INSERT INTO findings (target, tool, severity, category, title, seen_at)
                      VALUES (?, ?, 'high', 'cat', ?, ?)`).run(t, tool, title, at);
    ins('version-match', 'gone', T0);   // resolved: the tool reported again at T2
    ins('version-match', 'kept', T2);
    ins('nuclei', 'twin', T1);          // one match found by both passes
    ins('nuclei-url', 'twin', T1);
    db.reportQueue.enqueueMany([{ target: t, priority: 0 }], T0);
    const opts = findingsRuleOpts(db.raw);
    const open = (db.raw
      .prepare(`SELECT resolved FROM (${currentFindingsSelect({ ...opts, targetParam: '@t' })})`)
      .all({ t }) as { resolved: number }[]).filter((r) => !r.resolved).length;
    db.close();
    expect(open).toBe(2);

    const out = path.join(dir, 'reports');
    const r = run('src/report-worker.ts', ['--sqlite', file, '--out-dir', out, '--max-batches', '1', '--log', path.join(dir, 'w.log')]);
    expect(r.status).toBe(0);
    const md = fs.readFileSync(path.join(out, 'host.example.md'), 'utf8');
    expect(md).toContain(`Findings: ${open}`);
    expect(md).not.toContain('gone');
    expect(md.match(/\| twin \|/g)).toHaveLength(1);
  });
});

