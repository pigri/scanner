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


describe('report-worker CVEs', () => {
  it('lists every distinct CVE of a finding current rows, and none from a superseded row', () => {
    const { dir, file, db } = tmpDb();
    const t = 'host.example';
    const ins = (cve: string, at: string) =>
      db.raw.prepare(`INSERT INTO findings (target, tool, severity, category, title, cve, seen_at)
                      VALUES (?, 'nuclei', 'critical', 'multi-cve', 'multi', ?, ?)`).run(t, cve, at);
    ins('CVE-2026-0003', T0);           // superseded: the newer run reported only the two below
    ins('CVE-2026-0001', T2);
    ins('CVE-2026-0002', T2);
    db.reportQueue.enqueueMany([{ target: t, priority: 0 }], T0);
    db.close();
    const out = path.join(dir, 'reports');
    const r = run('src/report-worker.ts', ['--sqlite', file, '--out-dir', out, '--max-batches', '1', '--log', path.join(dir, 'w.log')]);
    expect(r.status).toBe(0);
    const md = fs.readFileSync(path.join(out, 'host.example.md'), 'utf8');
    expect(md).toContain('Findings: 1');
    expect(md).toContain('| critical | nuclei | multi | CVE-2026-0001, CVE-2026-0002 |');
    expect(md).not.toContain('CVE-2026-0003');
  });
});

describe('report-worker CVE cell', () => {
  const build = (rows: [string, string | null, string, string?][]) => {
    const { dir, file, db } = tmpDb();
    for (const [tool, cve, at, title] of rows)
      db.raw.prepare(`INSERT INTO findings (target, tool, severity, category, title, cve, seen_at)
                      VALUES ('host.example', ?, 'critical', 'multi-cve', ?, ?, ?)`).run(tool, title ?? 'multi', cve, at);
    db.reportQueue.enqueueMany([{ target: 'host.example', priority: 0 }], T0);
    db.close();
    const out = path.join(dir, 'reports');
    const r = run('src/report-worker.ts', ['--sqlite', file, '--out-dir', out, '--max-batches', '1', '--log', path.join(dir, 'w.log')]);
    expect(r.status).toBe(0);
    return fs.readFileSync(path.join(out, 'host.example.md'), 'utf8');
  };

  it('shows no CVE when the current rows carry none, though an older row did', () => {
    const md = build([['nuclei', 'CVE-2020-0001', T0], ['nuclei', null, T2]]);
    expect(md).toContain('Findings: 1');
    expect(md).toContain('| critical | nuclei | multi |  |');
    expect(md).not.toContain('CVE-2020-0001');
  });

  it('shows no CVE when only the resolved nuclei-url twin carries one', () => {
    const md = build([
      ['nuclei-url', 'CVE-2020-0002', T0],   // resolved: the nuclei-url pass reported something else at T2
      ['nuclei-url', null, T2, 'other'],
      ['nuclei', null, T2],
    ]);
    expect(md).toContain('Findings: 2');
    expect(md).toContain('| critical | nuclei | multi |  |');
    expect(md).not.toContain('CVE-2020-0002');
  });

  it('lists both current CVEs of a nuclei-url-only finding', () => {
    const md = build([['nuclei-url', 'CVE-2026-0001', T2], ['nuclei-url', 'CVE-2026-0002', T2]]);
    expect(md).toContain('| critical | nuclei | multi | CVE-2026-0001, CVE-2026-0002 |');
  });
});
