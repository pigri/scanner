import { describe, it, expect } from 'vitest';
import { parseRunIds, parseExpect, applyPrune } from '../src/prune-runs.js';
import { openDb } from '../src/lib/db.js';
import { currentFindingsSelect, findingsRuleOpts } from '../src/lib/current-findings.js';
import { recordRiskScores, deleteRiskScoresForRuns } from '../src/lib/risk-latest.js';

describe('parseRunIds', () => {
  it('parses a comma-separated list', () => {
    expect(parseRunIds('21,22')).toEqual([21, 22]);
  });
  it('accepts whitespace separators and dedupes + sorts', () => {
    expect(parseRunIds('22 21  21,3')).toEqual([3, 21, 22]);
  });
  it('rejects non-positive / non-integer ids', () => {
    expect(() => parseRunIds('21,abc')).toThrow(/invalid run id/);
    expect(() => parseRunIds('0')).toThrow(/invalid run id/);
    expect(() => parseRunIds('-5')).toThrow(/invalid run id/);
  });
});

describe('parseExpect', () => {
  it('maps id:tool pairs', () => {
    const m = parseExpect(['21:synthesize-eol', '22:risk']);
    expect(m.get(21)).toBe('synthesize-eol');
    expect(m.get(22)).toBe('risk');
  });
  it('rejects malformed pairs', () => {
    expect(() => parseExpect(['21'])).toThrow(/invalid --expect/);
    expect(() => parseExpect(['x:risk'])).toThrow(/invalid --expect/);
  });
});

describe('pruning runs keeps risk_latest consistent', () => {
  it('falls back to the previous score, and drops a target whose only run is pruned', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, '2026-01-01T00:00:00Z');
    const r2 = db.startRun('risk', {}, '2026-01-02T00:00:00Z');
    recordRiskScores(db.raw, [
      { target: 'a.example.com', score: 10, breakdownJson: '{}' },
    ], '2026-01-01T00:00:00Z', r1);
    recordRiskScores(db.raw, [
      { target: 'a.example.com', score: 50, breakdownJson: '{}' },
      { target: 'b.example.com', score: 5, breakdownJson: '{}' },
    ], '2026-01-02T00:00:00Z', r2);
    db.raw.transaction(() => deleteRiskScoresForRuns(db.raw, [r2]))();
    expect(db.raw.prepare('SELECT target, score FROM risk_latest ORDER BY target').all())
      .toEqual([{ target: 'a.example.com', score: 10 }]);
  });
});

describe('applyPrune (the prune-runs CLI body)', () => {
  it('deletes runs and findings and keeps risk_latest in step', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('risk', {}, '2026-01-01T00:00:00Z');
    const r2 = db.startRun('risk', {}, '2026-01-02T00:00:00Z');
    recordRiskScores(db.raw, [{ target: 'a.example.com', score: 10, breakdownJson: '{}' }], '2026-01-01T00:00:00Z', r1);
    recordRiskScores(db.raw, [
      { target: 'a.example.com', score: 50, breakdownJson: '{}' },
      { target: 'b.example.com', score: 5, breakdownJson: '{}' },
    ], '2026-01-02T00:00:00Z', r2);
    applyPrune(db.raw, [r2]);
    expect(db.raw.prepare('SELECT id FROM runs').all()).toEqual([{ id: r1 }]);
    expect(db.raw.prepare('SELECT target, score FROM risk_latest ORDER BY target').all())
      .toEqual([{ target: 'a.example.com', score: 10 }]);
  });
});

describe('applyPrune and tool_coverage', () => {
  const cov = (raw: ReturnType<typeof openDb>['raw']) =>
    raw.prepare('SELECT target, tool, run_id FROM tool_coverage ORDER BY target, tool').all();
  const resolved = (raw: ReturnType<typeof openDb>['raw']) =>
    (raw.prepare(currentFindingsSelect(findingsRuleOpts(raw))).all() as { title: string; resolved: number }[])
      .map((r) => `${r.title}:${r.resolved}`).sort();

  function seed() {
    const db = openDb(':memory:');
    const old = db.startRun('nmap', {}, '2026-01-01T00:00:00Z');
    const bad = db.startRun('nmap', {}, '2026-01-02T00:00:00Z');
    const other = db.startRun('nmap', {}, '2026-01-03T00:00:00Z');
    db.insertFinding({ tool: 'nmap', target: 'a.example.com', title: 'old' }, '2026-01-01T00:00:00Z', old);
    db.recordCoverage('nmap', ['a.example.com'], '2026-01-02T00:00:00Z', bad);
    db.recordCoverage('nmap', ['b.example.com'], '2026-01-03T00:00:00Z', other);
    return { db, bad, other };
  }

  it('deletes the coverage rows of the pruned run', () => {
    const { db, bad } = seed();
    applyPrune(db.raw, [bad]);
    expect(cov(db.raw).map((r) => (r as { run_id: number }).run_id)).not.toContain(bad);
  });

  it('opens an older finding of that target and tool again', () => {
    const { db, bad } = seed();
    expect(resolved(db.raw)).toEqual(['old:1']);
    applyPrune(db.raw, [bad]);
    expect(resolved(db.raw)).toEqual(['old:0']);
  });

  it('keeps the coverage rows of other runs', () => {
    const { db, bad, other } = seed();
    applyPrune(db.raw, [bad]);
    expect(cov(db.raw)).toEqual([{ target: 'b.example.com', tool: 'nmap', run_id: other }]);
  });

  it('keeps a newer run’s stamp on the same target and tool', () => {
    const { db, bad } = seed();
    const newer = db.startRun('nmap', {}, '2026-01-04T00:00:00Z');
    db.recordCoverage('nmap', ['a.example.com'], '2026-01-04T00:00:00Z', newer);
    applyPrune(db.raw, [bad]);
    expect(cov(db.raw)).toContainEqual({ target: 'a.example.com', tool: 'nmap', run_id: newer });
    expect(resolved(db.raw)).toEqual(['old:1']);
  });

  it('drops the pair’s coverage, not back to an older stamp, when the pruned run held it', () => {
    const db = openDb(':memory:');
    const older = db.startRun('nmap', {}, '2026-01-01T00:00:00Z');
    const bad = db.startRun('nmap', {}, '2026-01-02T00:00:00Z');
    db.recordCoverage('nmap', ['a.example.com'], '2026-01-01T00:00:00Z', older);
    db.recordCoverage('nmap', ['a.example.com'], '2026-01-02T00:00:00Z', bad);
    applyPrune(db.raw, [bad]);
    expect(cov(db.raw)).toEqual([]);
  });
});
