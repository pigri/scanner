import { describe, it, expect, vi } from 'vitest';
import { openDb } from '../src/lib/db.js';
import { ingestCheckdmarcRows } from '../src/lib/checkdmarc-ingest.js';
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
    const r = await ingestCheckdmarcRows(db, [weak, clean('ok.example.com')], NOW, runId, noSpf);
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
    await ingestCheckdmarcRows(db, [slow], NOW, runId, noSpf);
    expect(coverage(db)).toEqual([]);
  });

  it('adds a run note when the coverage write fails and still finishes the run', async () => {
    const { db, runId } = setup();
    vi.spyOn(db, 'recordCoverage').mockReturnValue(false);
    await ingestCheckdmarcRows(db, [clean('ok.example.com')], NOW, runId, noSpf);
    const run = db.raw.prepare('SELECT notes, finished_at FROM runs WHERE id = ?').get(runId) as { notes: string; finished_at: string | null };
    expect(run.notes).toBe('tool_coverage write failed: scan.db busy');
    expect(run.finished_at).not.toBeNull();
  });

  it('covers nothing and throws when a findings insert fails', async () => {
    const { db, runId } = setup();
    db.raw.exec("CREATE TRIGGER t BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'database is locked'); END");
    await expect(ingestCheckdmarcRows(db, [weak], NOW, runId, noSpf)).rejects.toThrow(/locked/);
    expect(coverage(db)).toEqual([]);
  });
});
