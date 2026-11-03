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
    organization: o.organization ?? null,
    active: o.active ?? 1,
  };
}

const rows: TargetRowLike[] = [
  row({ target: 'a.example.com', score: 90, critical: 2, findings: 5, cves: 3, organization: 'Acme Kft.' }),
  row({ target: 'b.example.com', score: 50, high: 1, findings: 2, cves: 0, organization: 'Acme Kft.' }),
  row({ target: 'c.other.com', score: 10, info: 4, findings: 4, cves: 1, organization: null }),
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

  it('org filter keeps only rows with the exact Organization; null-org rows excluded', () => {
    const r = filterAndFacet(rows, { org: 'Acme Kft.' });
    expect(r.rows.map((x) => x.target)).toEqual(['a.example.com', 'b.example.com']);
    expect(r.total).toBe(2);
    // a non-matching org yields nothing, and never a null-org row
    expect(filterAndFacet(rows, { org: 'Nope Zrt.' }).rows).toEqual([]);
  });

  it('orgs facet counts each non-null Organization and is independent of the org selection', () => {
    const r = filterAndFacet(rows, { org: 'Acme Kft.' });
    // facet computed over the base (before the org selection), nulls excluded
    expect(r.orgs).toEqual([{ org: 'Acme Kft.', c: 2 }]);
  });

  it('org composes with search, severity and score filters', () => {
    const r = filterAndFacet(rows, { org: 'Acme Kft.', sevList: ['critical'] });
    expect(r.rows.map((x) => x.target)).toEqual(['a.example.com']);
    // sevCounts stays independent of the org selection too
    expect(r.sevCounts.critical).toBe(1);
    expect(r.sevCounts.high).toBe(1);
  });


  describe('archived hosts', () => {
    const withArchived: TargetRowLike[] = [
      ...rows,
      row({ target: 'dead.example.com', score: 70, cves: 1, findings: 1, active: 0 }),
      row({ target: 'gone.other.com', score: 5, active: 0 }),
    ];
    const names = (r: { rows: TargetRowLike[] }) => r.rows.map((x) => x.target);

    it('default and empty archived show only active hosts', () => {
      const expected = ['a.example.com', 'b.example.com', 'c.other.com'];
      expect(names(filterAndFacet(withArchived, {}))).toEqual(expected);
      expect(names(filterAndFacet(withArchived, { archived: '' }))).toEqual(expected);
      expect(filterAndFacet(withArchived, {}).total).toBe(3);
    });

    it("archived='1' shows only archived hosts", () => {
      const r = filterAndFacet(withArchived, { archived: '1' });
      expect(names(r)).toEqual(['dead.example.com', 'gone.other.com']);
      expect(r.total).toBe(2);
    });

    it("archived='all' shows both sets", () => {
      const r = filterAndFacet(withArchived, { archived: 'all' });
      expect(r.total).toBe(5);
      expect(names(r)).toContain('dead.example.com');
      expect(names(r)).toContain('a.example.com');
    });

    it('archivedCount counts archived hosts regardless of the chosen set', () => {
      expect(filterAndFacet(withArchived, {}).archivedCount).toBe(2);
      expect(filterAndFacet(withArchived, { archived: '1' }).archivedCount).toBe(2);
      expect(filterAndFacet(withArchived, { archived: 'all' }).archivedCount).toBe(2);
      expect(filterAndFacet(rows, {}).archivedCount).toBe(0);
    });

    it('search composes with each archived set', () => {
      expect(names(filterAndFacet(withArchived, { search: 'example' }))).toEqual([
        'a.example.com',
        'b.example.com',
      ]);
      expect(names(filterAndFacet(withArchived, { search: 'example', archived: '1' }))).toEqual([
        'dead.example.com',
      ]);
      expect(names(filterAndFacet(withArchived, { search: 'example', archived: 'all' }))).toEqual([
        'a.example.com',
        'dead.example.com',
        'b.example.com',
      ]);
      expect(filterAndFacet(withArchived, { search: 'example' }).archivedCount).toBe(1);
    });
  });
});
