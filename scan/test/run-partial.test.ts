import { describe, it, expect } from 'vitest';
import { openDb } from '../src/lib/db.js';
import {
  exitFailed, exitReason, finishWithWhy, partialFinish, partialNote, partialReasons, rowsAtRisk,
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
