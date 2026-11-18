import { describe, it, expect } from 'vitest';
import Database from 'better-sqlite3';
import { currentFindingsSelect, tableExists, STICKY_TOOLS } from '../src/lib/current-findings.js';
import { openDb } from '../src/lib/db.js';

const T0 = '2026-11-10T10:00:00.000Z';
const T1 = '2026-11-10T11:00:00.000Z';
const T2 = '2026-11-10T12:00:00.000Z';

function seed() {
  const { raw } = openDb(':memory:');
  const ins = raw.prepare(
    `INSERT INTO findings (target, tool, severity, category, title, seen_at)
     VALUES (@target, @tool, 'high', 'cve', @title, @seen_at)`,
  );
  // host.example: "gone" last seen at T0, "kept" at T2 (the tool's latest row).
  ins.run({ target: 'host.example', tool: 'version-match', title: 'gone', seen_at: T0 });
  ins.run({ target: 'host.example', tool: 'version-match', title: 'kept', seen_at: T0 });
  ins.run({ target: 'host.example', tool: 'version-match', title: 'kept', seen_at: T2 });
  // Another tool on the same host has its own watermark.
  ins.run({ target: 'host.example', tool: 'nuclei', title: 'only', seen_at: T1 });
  // A second target is independent.
  ins.run({ target: 'other.example', tool: 'version-match', title: 'solo', seen_at: T0 });
  return raw;
}

type Row = { target: string; tool: string; title: string; resolved: number };
const byTitle = (rows: Row[]) => Object.fromEntries(rows.map((r) => [`${r.target}/${r.title}`, r.resolved]));

describe('currentFindingsSelect (rule 3: watermark = MAX(seen_at) per target, tool)', () => {
  it('resolves a finding last seen before its tool latest row and keeps the latest open', () => {
    const raw = seed();
    const rows = raw.prepare(currentFindingsSelect({ coverage: false })).all() as Row[];
    expect(byTitle(rows)).toEqual({
      'host.example/gone': 1,
      'host.example/kept': 0,
      'host.example/only': 0,
      'other.example/solo': 0,
    });
  });

  it('per-target variant equals the global one for that target', () => {
    const raw = seed();
    const global = (raw.prepare(currentFindingsSelect({ coverage: false })).all() as Row[])
      .filter((r) => r.target === 'host.example');
    const scoped = raw
      .prepare(currentFindingsSelect({ coverage: false, targetParam: '@t' }))
      .all({ t: 'host.example' }) as Row[];
    const key = (r: Row) => `${r.tool}|${r.title}`;
    expect(scoped.map(key).sort()).toEqual(global.map(key).sort());
    expect(byTitle(scoped)).toEqual(
      byTitle(global),
    );
  });

  it('rejects coverage until WP3 implements it', () => {
    expect(() => currentFindingsSelect({ coverage: true })).toThrow();
  });
});

describe('helpers', () => {
  it('tableExists probes sqlite_master', () => {
    const db = new Database(':memory:');
    db.exec('CREATE TABLE a(x)');
    expect(tableExists(db, 'a')).toBe(true);
    expect(tableExists(db, 'b')).toBe(false);
  });

  it('STICKY_TOOLS lists the tools that never close', () => {
    expect([...STICKY_TOOLS].sort()).toEqual(['manual', 'manual-triage', 'synthesize-eol']);
  });
});
