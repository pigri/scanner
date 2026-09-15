import { describe, it, expect, beforeEach } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';

// Fleet split: HU worker gets includeSuffixes=['gov.hu','hu'], foreign worker
// gets excludeSuffixes=['gov.hu','hu']. Every pending row must be claimable by
// exactly one of them, so a target never goes unclaimed and never gets
// double-claimed.

const at = '2026-09-15T10:00:00Z';

function seed(db: Db): void {
  db.enqueueMany([
    { target: 'erdoterkep.nebih.gov.hu', priority: 90 },
    { target: 'gov.hu',                  priority: 80 },
    { target: 'example.hu',              priority: 70 },
    { target: 'example.com',             priority: 60 },
    { target: '84.206.46.212',           priority: 50 },
    { target: 'example.gov.hu.evil.com', priority: 40 },
  ], at);
}

describe('claim filter — HU-include', () => {
  let db: Db;
  beforeEach(() => {
    db = openDb(':memory:', { scanQueueFilter: { includeSuffixes: ['gov.hu', 'hu'] } });
    seed(db);
  });

  it('claims only *.gov.hu / *.hu apex + subdomain rows', () => {
    const rows = db.claimBatch(10, at).map((r) => r.target);
    expect(rows.sort()).toEqual(['erdoterkep.nebih.gov.hu', 'example.hu', 'gov.hu'].sort());
  });

  it('does not match the .gov.hu-as-substring host', () => {
    const rows = db.claimBatch(10, at).map((r) => r.target);
    expect(rows).not.toContain('example.gov.hu.evil.com');
  });
});

describe('claim filter — HU-exclude', () => {
  let db: Db;
  beforeEach(() => {
    db = openDb(':memory:', { scanQueueFilter: { excludeSuffixes: ['gov.hu', 'hu'] } });
    seed(db);
  });

  it('claims everything except *.gov.hu / *.hu apex + subdomain', () => {
    const rows = db.claimBatch(10, at).map((r) => r.target);
    expect(rows.sort()).toEqual(['84.206.46.212', 'example.com', 'example.gov.hu.evil.com'].sort());
  });
});

describe('claim filter — partition covers every row exactly once', () => {
  it('include ∪ exclude = full pending set, and include ∩ exclude = ∅', () => {
    const hu = openDb(':memory:', { scanQueueFilter: { includeSuffixes: ['gov.hu', 'hu'] } });
    const fx = openDb(':memory:', { scanQueueFilter: { excludeSuffixes: ['gov.hu', 'hu'] } });
    seed(hu); seed(fx);
    const huClaims = hu.claimBatch(10, at).map((r) => r.target).sort();
    const fxClaims = fx.claimBatch(10, at).map((r) => r.target).sort();
    expect(new Set([...huClaims, ...fxClaims]).size).toBe(huClaims.length + fxClaims.length); // disjoint
    expect([...huClaims, ...fxClaims].sort()).toEqual([
      '84.206.46.212', 'erdoterkep.nebih.gov.hu', 'example.com',
      'example.gov.hu.evil.com', 'example.hu', 'gov.hu',
    ]);
  });
});

describe('claim filter — no filter still claims everything (regression)', () => {
  it('unfiltered claim returns every pending row', () => {
    const db = openDb(':memory:');
    seed(db);
    const rows = db.claimBatch(10, at).map((r) => r.target).sort();
    expect(rows).toEqual([
      '84.206.46.212', 'erdoterkep.nebih.gov.hu', 'example.com',
      'example.gov.hu.evil.com', 'example.hu', 'gov.hu',
    ]);
  });
});
