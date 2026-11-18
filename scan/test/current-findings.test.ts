import { describe, it, expect } from 'vitest';
import Database from 'better-sqlite3';
import { currentFindingsSelect, tableExists, STICKY_TOOLS } from '../src/lib/current-findings.js';
import { openDb } from '../src/lib/db.js';
import { riskToolKey, riskToolKeySql } from '../src/lib/nuclei-tool.js';

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
    const rows = raw.prepare(currentFindingsSelect({ coverage: false, partial: false })).all() as Row[];
    expect(byTitle(rows)).toEqual({
      'host.example/gone': 1,
      'host.example/kept': 0,
      'host.example/only': 0,
      'other.example/solo': 0,
    });
  });

  it('per-target variant equals the global one for that target', () => {
    const raw = seed();
    const global = (raw.prepare(currentFindingsSelect({ coverage: false, partial: false })).all() as Row[])
      .filter((r) => r.target === 'host.example');
    const scoped = raw
      .prepare(currentFindingsSelect({ coverage: false, partial: false, targetParam: '@t' }))
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
    byTitle(raw.prepare(currentFindingsSelect({ coverage, partial: false })).all() as Row[]);

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
      .prepare(currentFindingsSelect({ coverage: true, partial: false, targetParam: '@t' }))
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

describe('currentFindingsSelect with partial:true (partial runs leave the watermark alone)', () => {
  const T3 = '2026-11-10T13:00:00.000Z';
  const fresh = () => openDb(':memory:').raw;
  const add = (raw: Database.Database, title: string, at: string, tool = 'nuclei', target = 'host.example') =>
    raw
      .prepare(
        `INSERT INTO findings (target, tool, severity, category, title, seen_at)
         VALUES (?, ?, 'high', 'cve', ?, ?)`,
      )
      .run(target, tool, title, at);
  const mark = (raw: Database.Database, at: string, tool = 'nuclei', run = 7) =>
    raw.prepare('INSERT INTO partial_stamps (tool, seen_at, run_id) VALUES (?, ?, ?)').run(tool, at, run);
  const sel = (raw: Database.Database, partial: boolean, coverage = false) =>
    byTitle(raw.prepare(currentFindingsSelect({ coverage, partial })).all() as Row[]);

  function oneComplete() {
    const raw = fresh();
    add(raw, 'old', T0);
    add(raw, 'new', T2);
    mark(raw, T2);
    return raw;
  }

  it('a later partial row does not resolve an older row', () => {
    const raw = oneComplete();
    expect(sel(raw, true)).toEqual({ 'host.example/old': 0, 'host.example/new': 0 });
  });

  it('partial:false keeps the legacy result on the same data (control)', () => {
    const raw = oneComplete();
    expect(sel(raw, false)).toEqual({ 'host.example/old': 1, 'host.example/new': 0 });
  });

  it('keeps every row open when all of a pair are partial', () => {
    const raw = fresh();
    add(raw, 'a', T0);
    add(raw, 'b', T2);
    mark(raw, T0, 'nuclei', 6);
    mark(raw, T2);
    expect(sel(raw, true)).toEqual({ 'host.example/a': 0, 'host.example/b': 0 });
  });

  it('a later complete run resolves both older rows', () => {
    const raw = oneComplete();
    add(raw, 'latest', T3);
    expect(sel(raw, true)).toEqual({ 'host.example/old': 1, 'host.example/new': 1, 'host.example/latest': 0 });
  });

  it("another tool's marker at the same stamp changes nothing", () => {
    const raw = fresh();
    add(raw, 'old', T0);
    add(raw, 'new', T2);
    mark(raw, T2, 'ffuf');
    expect(sel(raw, true)).toEqual({ 'host.example/old': 1, 'host.example/new': 0 });
  });

  it('coverage wins over a marker', () => {
    const raw = oneComplete();
    raw.prepare('INSERT INTO tool_coverage (target, tool, seen_at, run_id) VALUES (?, ?, ?, NULL)').run('host.example', 'nuclei', T3);
    expect(sel(raw, true, true)).toEqual({ 'host.example/old': 1, 'host.example/new': 1 });
  });

  it('scoped to one target gives the global answer for that target', () => {
    const raw = oneComplete();
    add(raw, 'solo', T0, 'nuclei', 'other.example');
    const global = (raw.prepare(currentFindingsSelect({ coverage: false, partial: true })).all() as Row[])
      .filter((r) => r.target === 'host.example');
    const scoped = raw
      .prepare(currentFindingsSelect({ coverage: false, partial: true, targetParam: '@t' }))
      .all({ t: 'host.example' }) as Row[];
    expect(byTitle(scoped)).toEqual(byTitle(global));
    expect(byTitle(scoped)).toEqual({ 'host.example/old': 0, 'host.example/new': 0 });
  });

  it('keeps sticky tools open', () => {
    const raw = fresh();
    for (const tool of STICKY_TOOLS) {
      add(raw, `${tool}-old`, T0, tool);
      add(raw, `${tool}-new`, T2, tool);
      mark(raw, T2, tool);
    }
    for (const v of Object.values(sel(raw, true))) expect(v).toBe(0);
  });
});

describe('currentFindingsSelect (nuclei passes are one tool)', () => {
  type Full = Row & { occ: number; first_seen: string; last_seen: string; cve: string | null };
  const add = (raw: ReturnType<typeof seed>, tool: string, title: string, at: string, target = 'twin.example') =>
    raw
      .prepare(
        `INSERT INTO findings (target, tool, severity, category, title, cve, seen_at)
         VALUES (?, ?, 'high', 'cve', ?, 'CVE-2026-1', ?)`,
      )
      .run(target, tool, title, at);
  const rowsOf = (raw: ReturnType<typeof seed>, targetParam?: string) =>
    (targetParam
      ? raw.prepare(currentFindingsSelect({ coverage: false, partial: true, targetParam })).all({ t: 'twin.example' })
      : raw.prepare(currentFindingsSelect({ coverage: false, partial: true })).all()) as Full[];
  const twin = (rows: Full[]) => rows.filter((r) => r.target === 'twin.example');

  it('gives one row for a match both passes report, as tool nuclei, with occurrences summed', () => {
    const raw = seed();
    add(raw, 'nuclei', 'same', T0);
    add(raw, 'nuclei', 'same', T1);
    add(raw, 'nuclei-url', 'same', T2);
    const rows = twin(rowsOf(raw));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tool: 'nuclei', occ: 3, first_seen: T0, last_seen: T2, cve: 'CVE-2026-1', resolved: 0 });
  });

  it('keeps a finding open when either twin still reports it', () => {
    const raw = seed();
    add(raw, 'nuclei', 'same', T0);
    add(raw, 'nuclei', 'later', T2); // nuclei watermark T2: nuclei side of "same" is resolved
    add(raw, 'nuclei-url', 'same', T1);
    add(raw, 'nuclei-url', 'other', T1); // nuclei-url watermark T1: "same" is open there
    expect(twin(rowsOf(raw))).toHaveLength(3);
    expect(byTitle(twin(rowsOf(raw)))).toEqual({
      'twin.example/same': 0,
      'twin.example/later': 0,
      'twin.example/other': 0,
    });
  });

  it('resolves a finding only when both twins have resolved it', () => {
    const raw = seed();
    add(raw, 'nuclei', 'same', T0);
    add(raw, 'nuclei-url', 'same', T0);
    add(raw, 'nuclei', 'news', T2);
    add(raw, 'nuclei-url', 'news2', T2);
    const rows = twin(rowsOf(raw));
    expect(rows).toHaveLength(3);
    expect(byTitle(rows)['twin.example/same']).toBe(1);
  });

  it('does not let a newer nuclei-url row resolve a finding only nuclei reported', () => {
    const raw = seed();
    add(raw, 'nuclei', 'solo', T0);
    add(raw, 'nuclei-url', 'url-only', T2);
    const rows = twin(rowsOf(raw));
    expect(rows.map((r) => r.tool)).toEqual(['nuclei', 'nuclei']);
    expect(byTitle(rows)).toEqual({ 'twin.example/solo': 0, 'twin.example/url-only': 0 });
  });

  it('per-target variant equals the global one for the twin rows', () => {
    const raw = seed();
    add(raw, 'nuclei', 'same', T0);
    add(raw, 'nuclei-url', 'same', T2);
    add(raw, 'nuclei', 'solo', T1);
    const strip = (rows: Full[]) => twin(rows).map((r) => JSON.stringify(r)).sort();
    expect(strip(rowsOf(raw, '@t'))).toEqual(strip(rowsOf(raw)));
  });
});

describe('riskToolKeySql', () => {
  it('agrees with riskToolKey', () => {
    const { raw } = openDb(':memory:');
    for (const tool of ['nuclei', 'nuclei-url', 'httpx', 'version-match', '']) {
      const got = (raw.prepare(`SELECT ${riskToolKeySql('t')} k FROM (SELECT ? t)`).get(tool) as { k: string }).k;
      expect(got).toBe(riskToolKey(tool));
    }
  });
});
