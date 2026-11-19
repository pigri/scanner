import { describe, it, expect } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { computeScore, type TargetSignals } from '../src/lib/risk.js';
import { loadRiskSignals } from '../src/risk.js';
import { dryRun } from '../src/risk-dry-run.js';

const NOW = '2026-11-18T12:00:00.000Z';
const D1 = '2026-11-16T00:00:00.000Z';
const D2 = '2026-11-17T00:00:00.000Z';
const D3 = '2026-11-18T00:00:00.000Z';
const base = { discoveryDb: null, hostSuffix: null } as const;

function add(db: Db, tool: string, target: string, severity: string, title: string, at: string, cve: string | null = null): void {
  db.raw.prepare('INSERT INTO findings(tool, target, severity, title, cve, seen_at) VALUES(?,?,?,?,?,?)')
    .run(tool, target, severity, title, cve, at);
}
const signals = (db: Db, findingsRule?: 'current' | 'all'): Map<string, TargetSignals> =>
  loadRiskSignals(db.raw, { ...base, countrySource: 'network', ...(findingsRule ? { findingsRule } : {}) }, NOW);
const score = (db: Db, t: string, rule?: 'current' | 'all', legacyCveCount = false): number =>
  computeScore(signals(db, rule).get(t)!, { legacyCveCount }).score;

describe('loadRiskSignals: current findings only', () => {
  it('a conclusive empty run (coverage newer than every row) lowers the score', () => {
    const db = openDb(':memory:');
    add(db, 'nuclei', 'a.example', 'high', 'old issue', D1);
    const before = score(db, 'a.example');
    expect(before).toBeGreaterThan(0);
    db.recordCoverage('nuclei', ['a.example'], D3, null);
    expect(score(db, 'a.example')).toBeLessThan(before);
    expect(signals(db).get('a.example')!.findings).toEqual([]);
    expect(score(db, 'a.example', 'all')).toBe(before);
  });

  it('without coverage a tool keeps its newest rows and drops older ones', () => {
    const db = openDb(':memory:');
    add(db, 'nuclei', 'a.example', 'high', 'old issue', D1);
    add(db, 'nuclei', 'a.example', 'low', 'new issue', D2);
    expect(signals(db).get('a.example')!.findings.map((f) => f.title)).toEqual(['new issue']);
  });

  it('still scores sticky synthesize-eol findings below the coverage stamp', () => {
    const db = openDb(':memory:');
    add(db, 'synthesize-eol', 'a.example', 'high', 'end of life', D1);
    db.recordCoverage('synthesize-eol', ['a.example'], D3, null);
    expect(signals(db).get('a.example')!.findings).toHaveLength(1);
  });

  it('works on a database without tool_coverage', () => {
    const db = openDb(':memory:');
    add(db, 'nuclei', 'a.example', 'high', 'old issue', D1);
    db.raw.exec('DROP TABLE tool_coverage');
    expect(signals(db).get('a.example')!.findings).toHaveLength(1);
  });

  it('matches coverage on the raw target when the resolver folds an IP onto a hostname', () => {
    const db = openDb(':memory:');
    db.raw.prepare("INSERT INTO ports(target, ip, port, protocol, seen_at) VALUES('a.example', '192.0.2.5', 80, 'tcp', ?)").run(D1);
    add(db, 'nuclei', '192.0.2.5', 'high', 'old issue', D1);
    db.recordCoverage('nuclei', ['192.0.2.5'], D3, null);
    const s = signals(db);
    expect(s.has('192.0.2.5')).toBe(false);
    expect(s.get('a.example')!.findings).toEqual([]);
  });

  it('filters on raw targets: a folded alias keeps its own watermark', () => {
    const db = openDb(':memory:');
    db.raw.prepare("INSERT INTO ports(target, ip, port, protocol, seen_at) VALUES('a.example', '192.0.2.5', 80, 'tcp', ?)").run(D1);
    add(db, 'nuclei', 'a.example', 'high', 'title A', D2);
    add(db, 'nuclei', '192.0.2.5', 'high', 'title B', D1);
    const titles = signals(db).get('a.example')!.findings.map((f) => f.title).sort();
    expect(titles).toEqual(['title A', 'title B']);
  });
});

describe('computeScore: CVE bucket', () => {
  const sig = (): TargetSignals => ({
    target: 'a.example', findings: [], ports: [], http: [], hostShared: 0, hostCountryCode: null, firstSeen: null, now: NOW,
  });
  const f = (title: string, cve: string) => ({ tool: 'nuclei', severity: 'high', title, cve, needsReview: false });

  it('counts the same CVE under two titles once, severity buckets keep both', () => {
    const s = sig();
    s.findings = [f('first title', 'CVE-2024-0001'), f('second title', 'CVE-2024-0001')];
    const b = computeScore(s).breakdown;
    expect(b.cvePoints).toBe(10);
    expect(b.high).toBe(2);
    expect(computeScore(s, { legacyCveCount: true }).breakdown.cvePoints).toBe(20);
  });

  it('counts distinct ids across findings', () => {
    const s = sig();
    s.findings = [f('t1', 'CVE-2024-0001'), f('t2', 'CVE-2024-0002')];
    expect(computeScore(s).breakdown.cvePoints).toBe(20);
  });
});

describe('old rule reproduces the old score', () => {
  it("findingsRule 'all' with legacyCveCount equals the pre-change computation", () => {
    const db = openDb(':memory:');
    add(db, 'nuclei', 'a.example', 'high', 'issue one', D1, 'CVE-2024-0001');
    add(db, 'nuclei', 'a.example', 'high', 'issue two', D1, 'CVE-2024-0001');
    add(db, 'headers', 'a.example', 'medium', 'resolved header', D1);
    add(db, 'headers', 'a.example', 'low', 'new header', D2);
    const s = signals(db, 'all').get('a.example')!;
    expect(s.findings).toHaveLength(4);
    const r = computeScore(s, { legacyCveCount: true });
    expect(r.breakdown.cvePoints).toBe(20);
    expect(r.breakdown.high).toBe(2);
    expect(r.breakdown.medium).toBe(1);
    // 2 high (12 each) + 1 medium (5) + 1 low (1) + 2 cve (10 each)
    expect(r.score).toBe(24 + 5 + 1 + 20);
    expect(score(db, 'a.example')).toBe(24 + 1 + 10);
  });
});

describe('dry run: current findings effect', () => {
  it('reports the old rule against the new rule', () => {
    const db = openDb(':memory:');
    add(db, 'nuclei', 'a.example', 'high', 'old issue', D1, 'CVE-2024-0001');
    db.recordCoverage('nuclei', ['a.example'], D3, null);
    add(db, 'nuclei', 'b.example', 'low', 'still here', D2);
    const r = dryRun(db.raw, { discoveryDb: null, hostSuffix: null, bumps: [], now: NOW, sample: 3 });
    expect(r.currentFindings.changed).toBe(1);
    expect(r.currentFindings.deltas).toEqual({ [-22]: 1 });
    expect(r.currentFindings.samples).toEqual({ [-22]: ['a.example'] });
  });
});

describe('loadRiskSignals: partial runs', () => {
  const find = (db: Db, title: string, severity: 'critical' | 'low', at: string, run: number): void =>
    db.insertFinding({ tool: 'nuclei', target: 'a.example', title, severity }, at, run);

  it('keeps a critical after a partial run that did not report it', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('nuclei', {}, D1);
    find(db, 'old critical', 'critical', D1, r1);
    db.finishRun(r1, { at: D1 });
    const r2 = db.startRun('nuclei', {}, D2);
    find(db, 'new low', 'low', D2, r2);
    db.finishRun(r2, { at: D2, partial: true });
    expect(signals(db).get('a.example')!.findings.map((f) => f.title).sort()).toEqual(['new low', 'old critical']);
    expect(score(db, 'a.example')).toBe(score(db, 'a.example', 'all'));
  });

  it('drops it once the later run finishes clean', () => {
    const db = openDb(':memory:');
    const r1 = db.startRun('nuclei', {}, D1);
    find(db, 'old critical', 'critical', D1, r1);
    db.finishRun(r1, { at: D1 });
    const r2 = db.startRun('nuclei', {}, D2);
    find(db, 'new low', 'low', D2, r2);
    db.finishRun(r2, { at: D2 });
    expect(signals(db).get('a.example')!.findings.map((f) => f.title)).toEqual(['new low']);
  });
});
