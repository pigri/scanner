import { describe, it, expect, vi } from 'vitest';
import { openDb } from '../src/lib/db.js';
import { ingestCheckdmarcRows } from '../src/lib/checkdmarc-ingest.js';
import { currentFindingsSelect } from '../src/lib/current-findings.js';
import { checkdmarcRowConclusive, checkdmarcCoveredTargets } from '../src/lib/checkdmarc-coverage.js';

const clean = (domain: string) => ({
  domain,
  dnssec: false,
  spf: { record: 'v=spf1 -all', valid: true },
  dmarc: { record: 'v=DMARC1; p=reject', valid: true },
  mx: { hosts: [] },
});

describe('checkdmarcRowConclusive', () => {
  it('accepts a clean row that yields no problem', () => {
    expect(checkdmarcRowConclusive(clean('a.example.com'))).toBe(true);
  });

  it('accepts a row whose records are genuinely absent (an answer was received)', () => {
    expect(checkdmarcRowConclusive({ domain: 'a.example.com', dmarc: { record: null, error: 'The domain does not exist' } })).toBe(true);
  });

  it.each([
    'The resolution lifetime expired after 5.1 seconds: Server Do53:192.0.2.53@53 answered The DNS operation timed out.',
    'The Resolution Lifetime Expired after 5.0 seconds',
    'All nameservers failed to answer the query _dmarc.a.example.com. IN TXT: Server Do53:192.0.2.53@53 answered SERVFAIL',
    'The DNS operation timed out after 2.0 seconds',
    'the DNSKEY query for a.example.com failed with SERVFAIL: x',
    'DNS resolution failed',
  ])('rejects a resolver failure anywhere in the row: %s', (msg) => {
    expect(checkdmarcRowConclusive({ domain: 'a.example.com', dmarc: { record: null, error: msg } })).toBe(false);
    expect(checkdmarcRowConclusive({ domain: 'a.example.com', mx: { warnings: [msg] } })).toBe(false);
  });

  it('rejects a row without a domain', () => {
    const noDomain = { domain: undefined, dmarc: { record: 'v=DMARC1; p=none' } };
    expect(checkdmarcRowConclusive(noDomain)).toBe(false);
  });
});

describe('checkdmarcCoveredTargets', () => {
  it('covers conclusive domains with zero findings and skips timeouts and absent domains', () => {
    const slow = { domain: 'slow.example.com', dmarc: { record: null, error: 'The resolution lifetime expired after 5.0 seconds' } };
    const rows = [clean('ok.example.com'), slow];
    // absent.example.com was requested but has no row in the output
    expect(checkdmarcCoveredTargets(rows)).toEqual(['ok.example.com']);
  });

  it('does not cover a domain that has any inconclusive row', () => {
    const failed = { domain: 'dup.example.com', spf: { warnings: ['nameservers failed to answer'] } };
    const rows = [clean('dup.example.com'), failed];
    expect(checkdmarcCoveredTargets(rows)).toEqual([]);
  });
});

describe('ingestCheckdmarcRows', () => {
  const NOW = '2026-01-01T00:00:00.000Z';
  const noSpf = async () => null;
  const coverage = (db: ReturnType<typeof openDb>) =>
    db.raw.prepare('SELECT target, tool, seen_at, run_id FROM tool_coverage ORDER BY target').all();
  const setup = () => {
    const db = openDb(':memory:');
    return { db, runId: db.startRun('checkdmarc', {}, NOW) };
  };
  const weak = {
    domain: 'weak.example.com', dnssec: true,
    spf: { record: 'v=spf1 -all', valid: true }, dmarc: { record: 'v=DMARC1; p=none', valid: true }, mx: { hosts: [] },
  };

  it('records coverage with the stamp, run and domain the findings use', async () => {
    const { db, runId } = setup();
    const r = await ingestCheckdmarcRows(db, [weak, clean('ok.example.com')], NOW, runId, noSpf, 0);
    expect(r.findings).toBeGreaterThan(0);
    const f = db.raw.prepare('SELECT DISTINCT target, seen_at, run_id FROM findings ORDER BY target').all();
    expect(f).toEqual([
      { target: 'ok.example.com', seen_at: NOW, run_id: runId },
      { target: 'weak.example.com', seen_at: NOW, run_id: runId },
    ]);
    expect(coverage(db)).toEqual([
      { target: 'ok.example.com', tool: 'checkdmarc', seen_at: NOW, run_id: runId },
      { target: 'weak.example.com', tool: 'checkdmarc', seen_at: NOW, run_id: runId },
    ]);
  });

  it('does not cover a timed-out domain', async () => {
    const { db, runId } = setup();
    const slow = { domain: 'slow.example.com', dmarc: { record: null, error: 'The resolution lifetime expired after 5.0 seconds' } };
    await ingestCheckdmarcRows(db, [slow], NOW, runId, noSpf, 0);
    expect(coverage(db)).toEqual([]);
  });

  it('adds a run note when the coverage write fails and still finishes the run', async () => {
    const { db, runId } = setup();
    vi.spyOn(db, 'recordCoverage').mockReturnValue(false);
    await ingestCheckdmarcRows(db, [clean('ok.example.com')], NOW, runId, noSpf, 0);
    const run = db.raw.prepare('SELECT notes, finished_at FROM runs WHERE id = ?').get(runId) as { notes: string; finished_at: string | null };
    expect(run.notes).toBe('tool_coverage write failed: scan.db busy');
    expect(run.finished_at).not.toBeNull();
  });

  it('covers nothing and throws when a findings insert fails', async () => {
    const { db, runId } = setup();
    db.raw.exec("CREATE TRIGGER t BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'database is locked'); END");
    await expect(ingestCheckdmarcRows(db, [weak], NOW, runId, noSpf, 0)).rejects.toThrow(/locked/);
    expect(coverage(db)).toEqual([]);
  });

  describe('partial runs', () => {
    const NOW2 = '2026-01-02T00:00:00.000Z';
    const OPEN = { coverage: true, partial: true } as const;
    const slowMissing = { domain: 'slow.example.com', dmarc: { record: null, error: 'The resolution lifetime expired after 5.0 seconds' } };
    const slowPolicy = { domain: 'slow.example.com', dmarc: { record: 'v=DMARC1; p=none', valid: true, error: 'timed out' }, spf: { record: 'v=spf1 -all', valid: true }, mx: { hosts: [{ hostname: 'mx.example.com' }] } };
    const okPolicy = { domain: 'slow.example.com', dnssec: true, dmarc: { record: 'v=DMARC1; p=none', valid: true }, spf: { record: 'v=spf1 -all', valid: true }, mx: { hosts: [{ hostname: 'mx.example.com' }] } };
    const missingResolved = (db: ReturnType<typeof openDb>) =>
      (db.raw.prepare(currentFindingsSelect(OPEN)).all() as Array<{ title: string; resolved: number }>)
        .filter((r) => r.title.startsWith('DMARC missing')).map((r) => r.resolved);
    const notes = (db: ReturnType<typeof openDb>, id: number) =>
      (db.raw.prepare('SELECT notes FROM runs WHERE id = ?').get(id) as { notes: string | null }).notes ?? '';

    it('keeps an older finding open after a run with a resolver failure', async () => {
      const db = openDb(':memory:');
      await ingestCheckdmarcRows(db, [slowMissing], NOW, db.startRun('checkdmarc', {}, NOW), noSpf, 0);
      const id = db.startRun('checkdmarc', {}, NOW2);
      await ingestCheckdmarcRows(db, [slowPolicy], NOW2, id, noSpf, 0);
      expect(missingResolved(db)).toEqual([0]);
      expect(notes(db, id)).toContain('partial run: 1 inconclusive row(s)');
    });

    it('keeps the run markers after a non-zero exit', async () => {
      const db = openDb(':memory:');
      const id = db.startRun('checkdmarc', {}, NOW2);
      await ingestCheckdmarcRows(db, [okPolicy], NOW2, id, noSpf, 1);
      expect(db.raw.prepare('SELECT COUNT(*) n FROM partial_stamps').get()).toEqual({ n: 1 });
      expect(notes(db, id)).toContain('partial run: exit 1');
    });

    it('a clean run still closes an older finding', async () => {
      const db = openDb(':memory:');
      await ingestCheckdmarcRows(db, [slowMissing], NOW, db.startRun('checkdmarc', {}, NOW), noSpf, 0);
      const id = db.startRun('checkdmarc', {}, NOW2);
      await ingestCheckdmarcRows(db, [okPolicy], NOW2, id, noSpf, 0);
      expect(missingResolved(db)).toEqual([1]);
      expect(notes(db, id)).not.toContain('partial');
      expect(db.raw.prepare('SELECT COUNT(*) n FROM partial_stamps WHERE run_id = ?').get(id)).toEqual({ n: 0 });
    });

    it('a clean run with zero findings is complete', async () => {
      const { db, runId } = setup();
      await ingestCheckdmarcRows(db, [], NOW, runId, noSpf, 0);
      expect(notes(db, runId)).not.toContain('partial');
    });
  });
});
