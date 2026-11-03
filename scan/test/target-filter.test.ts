import { describe, it, expect } from 'vitest';
import { filterAndFacet, type TargetRowLike } from '../src/lib/target-filter.js';

function row(o: Partial<TargetRowLike> & { target: string }): TargetRowLike {
  return {
    target: o.target,
    score: o.score ?? 0,
    critical: o.critical ?? 0,
    high: o.high ?? 0,
    medium: o.medium ?? 0,
    low: o.low ?? 0,
    info: o.info ?? 0,
    findings: o.findings ?? 0,
    cves: o.cves ?? 0,
    created_at: o.created_at ?? null,
    updated_at: o.updated_at ?? null,
  };
}

const rows: TargetRowLike[] = [
  row({ target: 'a.example.com', score: 90, critical: 2, findings: 5, cves: 3 }),
  row({ target: 'b.example.com', score: 50, high: 1, findings: 2, cves: 0 }),
  row({ target: 'c.other.com', score: 10, info: 4, findings: 4, cves: 1 }),
];

describe('filterAndFacet', () => {
  it('search filters by target substring, case-insensitive', () => {
    const r = filterAndFacet(rows, { search: 'EXAMPLE' });
    expect(r.rows.map((x) => x.target)).toEqual(['a.example.com', 'b.example.com']);
    expect(r.total).toBe(2);
  });

  it('cve=1 keeps hosts with >=1 CVE, cve=0 the inverse', () => {
    expect(filterAndFacet(rows, { cve: '1' }).rows.map((x) => x.target)).toEqual([
      'a.example.com',
      'c.other.com',
    ]);
    expect(filterAndFacet(rows, { cve: '0' }).rows.map((x) => x.target)).toEqual(['b.example.com']);
  });

  it('minScore/maxScore bound the risk score', () => {
    expect(filterAndFacet(rows, { minScore: 50 }).rows.map((x) => x.target)).toEqual([
      'a.example.com',
      'b.example.com',
    ]);
    expect(filterAndFacet(rows, { maxScore: 50 }).rows.map((x) => x.target)).toEqual([
      'b.example.com',
      'c.other.com',
    ]);
  });

  it('severity selection keeps hosts with >=1 of a selected severity; sevCounts stays independent of it', () => {
    const r = filterAndFacet(rows, { sevList: ['critical'] });
    expect(r.rows.map((x) => x.target)).toEqual(['a.example.com']);
    // facet is computed over the base (no severity filter applied)
    expect(r.sevCounts.critical).toBe(1);
    expect(r.sevCounts.high).toBe(1);
    expect(r.sevCounts.info).toBe(1);
    expect(r.sevCounts.medium).toBe(0);
  });

  it('ignores unknown severities in the selection', () => {
    const r = filterAndFacet(rows, { sevList: ['bogus'] });
    // no valid severities selected -> no severity filter
    expect(r.total).toBe(3);
  });

  it('defaults to descending risk score and pages with offset/limit', () => {
    const r = filterAndFacet(rows, { offset: 1, limit: 1 });
    expect(r.rows.map((x) => x.target)).toEqual(['b.example.com']);
    expect(r.total).toBe(3);
    expect(r.limit).toBe(1);
    expect(r.offset).toBe(1);
  });

  it('sort=target orders by name ascending', () => {
    const r = filterAndFacet(rows, { sort: 'target' });
    expect(r.rows.map((x) => x.target)).toEqual(['a.example.com', 'b.example.com', 'c.other.com']);
  });
});
