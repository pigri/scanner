import { describe, it, expect } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { scanSigs, type LiveUrl } from '../src/content-sigs.js';

const AT = '2026-11-18T10:00:00.000Z';
const A: LiveUrl = { target: 'a.example', seed: 'https://a.example' };
const B: LiveUrl = { target: 'b.example', seed: 'https://b.example' };

type Reply = { status: number; body: string; head: Buffer } | null;
const miss: Reply = { status: 404, body: '', head: Buffer.alloc(0) };
const gitHead: Reply = { status: 200, body: 'ref: refs/heads/main\n', head: Buffer.from('ref: refs/heads/main\n') };

type ProbeFn = NonNullable<Parameters<typeof scanSigs>[2]['probeFn']>;

function probes(reply: (seed: string, path: string) => Reply): ProbeFn {
  return async (seed, sig) => reply(seed, sig.path);
}

async function scan(db: Db, live: LiveUrl[], probeFn: ProbeFn, withRun = true) {
  const runId = withRun ? db.startRun('content-sigs', {}, AT) : null;
  return scanSigs(db, live, { now: AT, runId, timeoutSec: 2, maxKb: 8, concurrency: 2, hostConcurrency: 4, write: () => {}, probeFn });
}
const cov = (db: Db) => db.raw.prepare('SELECT target, tool, seen_at FROM tool_coverage ORDER BY target').all();

describe('scanSigs coverage', () => {
  it('covers a host whose every probe answered, with zero findings', async () => {
    const db = openDb(':memory:');
    expect(await scan(db, [A], probes(() => miss))).toBe(0);
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'content-sigs', seen_at: AT }]);
  });

  it('records coverage with the stamp and target the findings carry', async () => {
    const db = openDb(':memory:');
    const n = await scan(db, [A], probes((_s, p) => (p === '.git/HEAD' ? gitHead : miss)));
    expect(n).toBe(1);
    expect(db.raw.prepare("SELECT target, seen_at FROM findings WHERE tool='content-sigs'").all())
      .toEqual([{ target: 'a.example', seen_at: AT }]);
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'content-sigs', seen_at: AT }]);
  });

  it('does not cover a host with one failed probe, even when another probe hit', async () => {
    const db = openDb(':memory:');
    await scan(db, [A], probes((_s, p) => (p === '.env' ? null : p === '.git/HEAD' ? gitHead : miss)));
    expect(cov(db)).toEqual([]);
  });

  it.each([429, 500, 503])('does not cover a host with one %i probe', async (status) => {
    const db = openDb(':memory:');
    await scan(db, [A], probes((_s, p) => (p === '.env' ? { status, body: '', head: Buffer.alloc(0) } : miss)));
    expect(cov(db)).toEqual([]);
  });

  it('covers a host whose probes got 403 and 404 answers', async () => {
    const db = openDb(':memory:');
    await scan(db, [A], probes((_s, p) => ({ status: p === '.env' ? 403 : 404, body: '', head: Buffer.alloc(0) })));
    expect(cov(db)).toHaveLength(1);
  });

  it('covers only the host that answered every probe', async () => {
    const db = openDb(':memory:');
    await scan(db, [A, B], probes((s) => (s.includes('b.example') ? null : miss)));
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'content-sigs', seen_at: AT }]);
  });

  it('records nothing for a null runId', async () => {
    const db = openDb(':memory:');
    await scan(db, [A], probes(() => miss), false);
    expect(cov(db)).toEqual([]);
  });
});
