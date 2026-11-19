import { describe, it, expect } from 'vitest';
import Database from 'better-sqlite3';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb } from '../src/lib/db.js';
import { frozenReport, frozenPairsSql } from '../src/lib/frozen-pairs.js';

const T0 = '2026-11-10T10:00:00.000Z';
const T1 = '2026-11-10T11:00:00.000Z';
const T2 = '2026-11-10T12:00:00.000Z';
const NOW = new Date('2026-11-12T12:00:00.000Z');

function fresh() {
  const { raw } = openDb(':memory:');
  const ins = raw.prepare(
    `INSERT INTO findings (target, tool, severity, category, title, seen_at) VALUES (?, ?, 'high', 'c', ?, ?)`,
  );
  const mark = raw.prepare('INSERT INTO partial_stamps (tool, seen_at, run_id) VALUES (?, ?, 1)');
  const cover = raw.prepare('INSERT INTO tool_coverage (target, tool, seen_at) VALUES (?, ?, ?)');
  return { raw, row: (t: string, tool: string, at: string, title = 'x') => ins.run(t, tool, title, at), mark: (tool: string, at: string) => mark.run(tool, at), cover: (t: string, tool: string, at: string) => cover.run(t, tool, at) };
}
const report = (raw: Database.Database) => frozenReport(raw, 10, NOW);

describe('frozenReport', () => {
  it('lists a pair whose newest stamp is marked, with its newest unmarked stamp as watermark', () => {
    const d = fresh();
    d.row('a.example', 'ffuf', T0, 'old');
    d.row('a.example', 'ffuf', T1, 'mid');
    d.row('a.example', 'ffuf', T2, 'new');
    d.mark('ffuf', T2);
    const r = report(d.raw);
    expect(r.tools).toEqual([
      { tool: 'ffuf', pairs: 1, allMarked: 0, rows: 2, oldestMarker: T2, oldestMarkerAgeDays: 2 },
    ]);
    expect(r.top).toEqual([{ target: 'a.example', tool: 'ffuf', rows: 2, newest: T2, oldestMarker: T2, allMarked: false }]);
  });

  it('counts a pair with every stamp marked as w = empty and holds all rows', () => {
    const d = fresh();
    d.row('a.example', 'ffuf', T0, 'one');
    d.row('a.example', 'ffuf', T2, 'two');
    d.mark('ffuf', T0);
    d.mark('ffuf', T2);
    const [t] = report(d.raw).tools;
    expect(t).toMatchObject({ pairs: 1, allMarked: 1, rows: 2, oldestMarker: T0, oldestMarkerAgeDays: 2 });
  });

  it('skips a pair that has a coverage row, even when marked', () => {
    const d = fresh();
    d.row('a.example', 'ffuf', T2);
    d.mark('ffuf', T2);
    d.cover('a.example', 'ffuf', T2);
    expect(report(d.raw).tools).toEqual([]);
  });

  it('skips a pair whose newest stamp is clean although an older one is marked', () => {
    const d = fresh();
    d.row('a.example', 'ffuf', T0);
    d.row('a.example', 'ffuf', T2);
    d.mark('ffuf', T0);
    expect(report(d.raw).tools).toEqual([]);
  });

  it('excludes sticky tools', () => {
    const d = fresh();
    d.row('a.example', 'manual', T2);
    d.mark('manual', T2);
    expect(report(d.raw).tools).toEqual([]);
  });

  it('keys the marker by tool: another tool marked at the same seen_at does not count', () => {
    const d = fresh();
    d.row('a.example', 'ffuf', T2);
    d.row('a.example', 'headers', T2);
    d.mark('headers', T2);
    const r = report(d.raw);
    expect(r.tools.map((t) => t.tool)).toEqual(['headers']);
  });

  it('keys every marker lookup by tool, including the watermark and the oldest marker', () => {
    const d = fresh();
    d.row('a.example', 'ffuf', T0, 'a');
    d.row('a.example', 'ffuf', T1, 'b');
    d.row('a.example', 'ffuf', T2, 'c');
    d.mark('ffuf', T2);
    d.mark('headers', T1);
    expect(report(d.raw).top).toEqual([
      { target: 'a.example', tool: 'ffuf', rows: 2, newest: T2, oldestMarker: T2, allMarked: false },
    ]);
  });

  it('reports the oldest marker across the pairs of a tool', () => {
    const d = fresh();
    d.row('a.example', 'ffuf', T0);
    d.row('b.example', 'ffuf', T2);
    d.mark('ffuf', T0);
    d.mark('ffuf', T2);
    expect(report(d.raw).tools[0]).toMatchObject({ pairs: 2, oldestMarker: T0, oldestMarkerAgeDays: 2 });
  });

  it('prints zeros for a DB without partial_stamps', () => {
    const raw = new Database(':memory:');
    raw.exec('CREATE TABLE findings (target TEXT, tool TEXT, seen_at TEXT)');
    expect(frozenReport(raw, 5, NOW)).toEqual({ tools: [], top: [] });
  });

  it('tolerates a DB without tool_coverage', () => {
    const d = fresh();
    d.raw.exec('DROP TABLE tool_coverage');
    d.row('a.example', 'ffuf', T2);
    d.mark('ffuf', T2);
    expect(report(d.raw).tools).toHaveLength(1);
  });

  it('orders --top by rows and caps it', () => {
    const d = fresh();
    for (const [t, n] of [['a.example', 1], ['b.example', 3], ['c.example', 2]] as const) {
      for (let i = 0; i < n; i++) d.row(t, 'ffuf', T2, `f${i}`);
    }
    d.mark('ffuf', T2);
    const r = frozenReport(d.raw, 2, NOW);
    expect(r.top.map((p) => p.target)).toEqual(['b.example', 'c.example']);
    expect(r.tools[0]).toMatchObject({ pairs: 3, rows: 6 });
  });

  it('plans every per-pair lookup on an index', () => {
    const d = fresh();
    const plan = (d.raw.prepare(`EXPLAIN QUERY PLAN ${frozenPairsSql(true)}`).all() as { detail: string }[])
      .map((p) => p.detail);
    expect(plan.filter((l) => /^SCAN f\b/.test(l))).toEqual([]);
  });
});

describe('frozen-pairs CLI', () => {
  it('prints JSON, reads read-only', () => {
    const dir = mkdtempSync(join(tmpdir(), 'frozen-'));
    try {
      const path = join(dir, 'scan.db');
      const { raw } = openDb(path);
      raw.prepare(`INSERT INTO findings (target, tool, severity, category, title, seen_at) VALUES ('a.example','ffuf','high','c','x',?)`).run(T2);
      raw.prepare(`INSERT INTO partial_stamps (tool, seen_at, run_id) VALUES ('ffuf', ?, 1)`).run(T2);
      raw.close();
      const out = execFileSync('npx', ['tsx', 'src/frozen-pairs.ts', '--sqlite', path, '--json', '--top', '1'], { encoding: 'utf8' });
      const j = JSON.parse(out);
      expect(j.tools[0]).toMatchObject({ tool: 'ffuf', pairs: 1, allMarked: 1, rows: 1 });
      expect(j.top).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
