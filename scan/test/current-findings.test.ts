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

});

describe('currentFindingsSelect (rules 1 and 2: sticky tools and tool_coverage)', () => {
  const cover = (raw: ReturnType<typeof seed>, target: string, tool: string, at: string) =>
    raw
      .prepare('INSERT INTO tool_coverage (target, tool, seen_at, run_id) VALUES (?, ?, ?, NULL)')
      .run(target, tool, at);
  const open = (raw: ReturnType<typeof seed>, coverage = true) =>
    byTitle(raw.prepare(currentFindingsSelect({ coverage })).all() as Row[]);

  it('resolves every row of a tool that a newer coverage record outlasts', () => {
    const raw = seed();
    cover(raw, 'host.example', 'version-match', '2026-11-10T13:00:00.000Z');
    expect(open(raw)).toMatchObject({
      'host.example/gone': 1,
      'host.example/kept': 1,
      'host.example/only': 0,
      'other.example/solo': 0,
    });
  });

  it('keeps rows seen at or after the coverage stamp open', () => {
    const raw = seed();
    cover(raw, 'host.example', 'version-match', T2);
    expect(open(raw)).toMatchObject({ 'host.example/gone': 1, 'host.example/kept': 0 });
    raw.prepare(
      `INSERT INTO findings (target, tool, severity, category, title, seen_at)
       VALUES ('host.example', 'version-match', 'high', 'cve', 'later', '2026-11-10T12:30:00.000Z')`,
    ).run();
    expect(open(raw)).toMatchObject({ 'host.example/gone': 1, 'host.example/kept': 0, 'host.example/later': 0 });
  });

  it('never resolves sticky tools, with or without coverage', () => {
    const raw = seed();
    const ins = raw.prepare(
      `INSERT INTO findings (target, tool, severity, category, title, seen_at)
       VALUES ('host.example', ?, 'high', 'eol', ?, ?)`,
    );
    for (const tool of STICKY_TOOLS) {
      ins.run(tool, `${tool}-old`, T0);
      ins.run(tool, `${tool}-new`, T2);
      cover(raw, 'host.example', tool, '2026-11-10T13:00:00.000Z');
    }
    for (const coverage of [true, false]) {
      const r = open(raw, coverage);
      for (const tool of STICKY_TOOLS) {
        expect(r[`host.example/${tool}-old`]).toBe(0);
        expect(r[`host.example/${tool}-new`]).toBe(0);
      }
    }
  });

  it('works scoped to one target', () => {
    const raw = seed();
    cover(raw, 'host.example', 'version-match', '2026-11-10T13:00:00.000Z');
    cover(raw, 'other.example', 'version-match', '2026-11-10T13:00:00.000Z');
    const rows = raw
      .prepare(currentFindingsSelect({ coverage: true, targetParam: '@t' }))
      .all({ t: 'host.example' }) as Row[];
    expect(byTitle(rows)).toEqual({
      'host.example/gone': 1,
      'host.example/kept': 1,
      'host.example/only': 0,
    });
  });

  it('ignores coverage rows when coverage is false', () => {
    const raw = seed();
    cover(raw, 'host.example', 'version-match', '2026-11-10T13:00:00.000Z');
    expect(open(raw, false)).toMatchObject({ 'host.example/gone': 1, 'host.example/kept': 0 });
  });
});
