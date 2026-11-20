import { describe, it, expect } from 'vitest';
import { openDb } from '../src/lib/db.js';
import {
  exitFailed, exitReason, finishWithWhy, partialFinish, partialNote, partialReasons, rowsAtRisk, incompleteHosts, testsslAborted, wpscanFailed,
} from '../src/lib/run-partial.js';

describe('rowsAtRisk', () => {
  it.each([
    [0, false, false],
    [0, true, false],
    [3, false, false],
    [3, true, true],
  ])('rows=%i failed=%s -> %s', (rows, failed, want) => {
    expect(rowsAtRisk(rows, failed)).toBe(want);
  });
});

describe('partialReasons and partialNote', () => {
  it('keeps positive counts and true flags in order, drops the rest', () => {
    expect(partialReasons([[2, 'host(s) incomplete'], [0, 'zero'], [false, 'no'], [true, 'ingest failed']]))
      .toEqual(['2 host(s) incomplete', 'ingest failed']);
  });
  it('is empty when nothing failed', () => {
    expect(partialReasons([[0, 'a'], [false, 'b']])).toEqual([]);
  });
  it('writes the note for the finish line, none when complete', () => {
    expect(partialNote(['a', 'b'])).toBe('partial run: a, b');
    expect(partialNote([])).toBeUndefined();
  });
});

describe('partialFinish', () => {
  it('flags partial and appends the note after existing notes', () => {
    expect(partialFinish(['x'], ['old'])).toEqual({ partial: true, notes: 'old; partial run: x' });
  });
  it('is complete with no notes key when nothing failed', () => {
    expect(partialFinish([])).toEqual({ partial: false });
  });
  it('keeps existing notes on a complete run', () => {
    expect(partialFinish([], ['old'])).toEqual({ partial: false, notes: 'old' });
  });
});

describe('exitFailed and exitReason', () => {
  it('only zero is a clean exit', () => {
    expect(exitFailed(0)).toBe(false);
    expect(exitFailed(1)).toBe(true);
    expect(exitFailed(-1)).toBe(true);
  });
  it('names a timeout kill and other codes', () => {
    expect(exitReason(-1)).toBe('killed on timeout');
    expect(exitReason(2)).toBe('exit 2');
  });
});

describe('finishWithWhy', () => {
  const notesOf = (db: ReturnType<typeof openDb>, id: number) =>
    db.raw.prepare('SELECT notes FROM runs WHERE id = ?').get(id) as { notes: string | null };
  const markers = (db: ReturnType<typeof openDb>, id: number) =>
    (db.raw.prepare('SELECT COUNT(*) AS n FROM partial_stamps WHERE run_id = ?').get(id) as { n: number }).n;
  const start = () => {
    const db = openDb(':memory:');
    const id = db.startRun('ffuf', {}, '2026-11-01T00:00:00.000Z');
    db.insertFinding({ tool: 'ffuf', target: 'a.example', category: 'c', severity: 'low', title: 't' }, '2026-11-01T00:00:00.000Z', id);
    return { db, id };
  };

  it('keeps the run markers and writes the note when why is non-empty', () => {
    const { db, id } = start();
    finishWithWhy(db, id, { targetsCount: 1, findingsCount: 1, at: '2026-11-01T00:01:00.000Z' }, ['1 host(s) incomplete']);
    expect(notesOf(db, id).notes).toBe('partial run: 1 host(s) incomplete');
    expect(markers(db, id)).toBeGreaterThan(0);
  });
  it('clears the run markers when why is empty', () => {
    const { db, id } = start();
    finishWithWhy(db, id, { targetsCount: 1, findingsCount: 1, at: '2026-11-01T00:01:00.000Z' }, []);
    expect(notesOf(db, id).notes).toBeNull();
    expect(markers(db, id)).toBe(0);
  });
});

describe('testsslAborted', () => {
  const rec = (id: string, severity: string, finding: string) => ({ id, severity, finding });
  it('is true on a scanProblem FATAL record', () => {
    expect(testsslAborted([rec('TLS1', 'HIGH', 'x'), rec('scanProblem', 'FATAL', 'no connect')], 0)).toBe(true);
  });
  it('is true when scanTime says the scan was interrupted', () => {
    expect(testsslAborted([rec('scanTime', 'INFO', 'Scan interrupted')], 0)).toBe(true);
  });
  it('is true for the ERR_* exit range and false below it', () => {
    expect(testsslAborted([], 242)).toBe(true);
    expect(testsslAborted([], 246)).toBe(true);
    expect(testsslAborted([], 255)).toBe(true);
    expect(testsslAborted([], 241)).toBe(false);
    expect(testsslAborted([], 0)).toBe(false);
  });
  it('is false for a finished scan and for non-array input', () => {
    expect(testsslAborted([rec('scanTime', 'INFO', '55'), rec('scanProblem', 'WARN', 'x')], 3)).toBe(false);
    expect(testsslAborted(null, 0)).toBe(false);
    expect(testsslAborted({ id: 'scanProblem', severity: 'FATAL' }, 0)).toBe(false);
  });
});

const NO_TOKEN_NOTICE = 'No WPScan API Token given, as a result vulnerability data has not been output.\nYou can get a free API token with 25 daily requests by registering at https://wpscan.com/register';

describe('wpscanFailed', () => {
  const ok = { vuln_api: { plan: 'free', requests_remaining: 20 } };
  it('treats exit 0 and exit 5 as normal', () => {
    expect(wpscanFailed(0, ok)).toBe(false);
    expect(wpscanFailed(5, ok)).toBe(false);
  });
  it.each([1, 2, 3, 4, -1])('treats exit %i as failed', (code) => {
    expect(wpscanFailed(code, ok)).toBe(true);
  });
  it('is failed on a scan_aborted key', () => {
    expect(wpscanFailed(0, { ...ok, scan_aborted: 'x' })).toBe(true);
  });
  it('is failed on a vuln_api error, http_error or exhausted quota', () => {
    expect(wpscanFailed(0, { vuln_api: { error: 'No token' } })).toBe(true);
    expect(wpscanFailed(0, { vuln_api: { http_error: 'HTTP 500' } })).toBe(true);
    expect(wpscanFailed(0, { vuln_api: { requests_remaining: 0 } })).toBe(true);
  });
  it('treats the no-token notice as a complete scan on exit 0 and 5', () => {
    expect(wpscanFailed(0, { vuln_api: { error: NO_TOKEN_NOTICE } })).toBe(false);
    expect(wpscanFailed(5, { vuln_api: { error: NO_TOKEN_NOTICE } })).toBe(false);
  });
  it('is still failed on the no-token notice with scan_aborted', () => {
    expect(wpscanFailed(0, { scan_aborted: 'x', vuln_api: { error: NO_TOKEN_NOTICE } })).toBe(true);
  });
  it('accepts unlimited quota and a missing vuln_api block as not failed by the api', () => {
    expect(wpscanFailed(0, { vuln_api: { requests_remaining: 'Unlimited' } })).toBe(false);
    expect(wpscanFailed(0, {})).toBe(false);
    expect(wpscanFailed(0, null)).toBe(false);
  });
});

describe('incompleteHosts', () => {
  it('counts the targets with rows that are not covered', () => {
    const rows = new Map([['a.example', 2], ['b.example', 1], ['c.example', 0]]);
    expect(incompleteHosts(rows, new Set(['a.example']))).toBe(1);
    expect(incompleteHosts(rows, new Set())).toBe(2);
    expect(incompleteHosts(rows, new Set(['a.example', 'b.example']))).toBe(0);
  });
});
