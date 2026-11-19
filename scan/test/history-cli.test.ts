import { describe, it, expect } from 'vitest';
import { run, tmpDb, seedKilledNuclei, T0, T1, T2, T3 } from './helpers/cli-rule.js';

describe('history', () => {
  it.each([
    ['a NULL category', { category: null }],
    ['a nuclei-url-only finding', { tool: 'nuclei-url' }],
  ])('is open, not resolved, after a partial run: %s', (_n, o) => {
    const { file, db } = tmpDb();
    seedKilledNuclei(db, 'host.example', o);
    db.close();
    const r = run('src/history.ts', ['--sqlite', file, '--target', 'host.example', '--json']);
    const rows = r.out.trim().split('\n').map((l) => JSON.parse(l) as { title: string; status: string });
    expect(rows.find((x) => x.title === 'cve-a')!.status).toBe('open');
  });

  it('does not mark a finding resolved after a partial run window', () => {
    const { file, db } = tmpDb();
    seedKilledNuclei(db, 'host.example');
    db.close();
    const r = run('src/history.ts', ['--sqlite', file, '--target', 'host.example', '--json']);
    expect(r.status).toBe(0);
    const rows = r.out.trim().split('\n').map((l) => JSON.parse(l) as { title: string; status: string; firstSeen: string; lastSeen: string });
    const a = rows.find((x) => x.title === 'cve-a')!;
    expect(a.status).toBe('open');
    expect(a.firstSeen).toBe(T0);
    expect(a.lastSeen).toBe(T0);
  });

  it('still reports resolved when the shared rule resolves it (control)', () => {
    const { file, db } = tmpDb();
    const target = 'host.example';
    const r1 = db.startRun('nuclei', {}, T0);
    db.insertFinding({ tool: 'nuclei', target, category: 'cve-a', severity: 'medium', title: 'cve-a' }, T0, r1);
    db.finishRun(r1, { at: T1 });
    const r2 = db.startRun('nuclei', {}, T2);
    db.insertFinding({ tool: 'nuclei', target, category: 'tech', severity: 'info', title: 'tech-detect' }, T2, r2);
    db.finishRun(r2, { at: T3 });
    db.close();
    const r = run('src/history.ts', ['--sqlite', file, '--target', target, '--json']);
    const rows = r.out.trim().split('\n').map((l) => JSON.parse(l) as { title: string; status: string });
    expect(rows.find((x) => x.title === 'cve-a')!.status).toBe('resolved');
  });
});
