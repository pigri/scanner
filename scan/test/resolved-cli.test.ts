import { describe, it, expect } from 'vitest';
import { currentFindingsSelect, findingsRuleOpts } from '../src/lib/current-findings.js';
import { run, tmpDb, seedKilledNuclei, T0, T1, T2, T3 } from './helpers/cli-rule.js';

describe('resolved clean-now', () => {
  it.each([
    ['a NULL category', { category: null }],
    ['a nuclei-url-only finding', { tool: 'nuclei-url' }],
  ])('keeps the host out of clean-now: %s', (_n, o) => {
    const { file, db } = tmpDb();
    seedKilledNuclei(db, 'host.example', o);
    db.close();
    expect(run('src/resolved.ts', ['--sqlite', file, '--json']).out.trim()).toBe('');
    const t = JSON.parse(run('src/resolved.ts', ['--sqlite', file, '--target', 'host.example', '--json']).out) as { status: string; resolved: unknown[]; stillOpen: unknown[] };
    expect(t.resolved).toHaveLength(0);
    expect(t.stillOpen).toHaveLength(1);
  });

  it('does not call a finding resolved when a killed nuclei run left it open', () => {
    const { file, db } = tmpDb();
    seedKilledNuclei(db, 'host.example');
    const opts = findingsRuleOpts(db.raw);
    const rows = db.raw.prepare(`SELECT title, resolved FROM (${currentFindingsSelect(opts)})`).all() as { title: string; resolved: number }[];
    db.close();
    expect(rows.find((r) => r.title === 'cve-a')!.resolved).toBe(0);

    const r = run('src/resolved.ts', ['--sqlite', file, '--json']);
    expect(r.status).toBe(0);
    expect(r.out.trim()).toBe('');
    const t = run('src/resolved.ts', ['--sqlite', file, '--target', 'host.example', '--json']);
    const diff = JSON.parse(t.out) as { status: string; resolved: unknown[] };
    expect(diff.resolved).toHaveLength(0);
    expect(diff.status).toBe('still-dirty');
  });

  it('still lists a finding the shared rule calls resolved (control)', () => {
    const { file, db } = tmpDb();
    const target = 'host.example';
    const r1 = db.startRun('nuclei', {}, T0);
    db.insertFinding({ tool: 'nuclei', target, category: 'cve-a', severity: 'medium', title: 'cve-a' }, T0, r1);
    db.finishRun(r1, { at: T1 });
    const r2 = db.startRun('nuclei', {}, T2);
    db.insertFinding({ tool: 'nuclei', target, category: 'tech', severity: 'info', title: 'tech-detect' }, T2, r2);
    db.finishRun(r2, { at: T3 });
    db.raw.prepare(
      `INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES (?, 'done', ?, ?, ?)`,
    ).run(target, T0, T2, T3);
    db.close();
    const r = run('src/resolved.ts', ['--sqlite', file, '--json']);
    expect(JSON.parse(r.out.trim()).target).toBe(target);
  });
});

