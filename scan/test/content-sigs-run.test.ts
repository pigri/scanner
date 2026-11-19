import { describe, it, expect } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { currentFindingsSelect, findingsRuleOpts } from '../src/lib/current-findings.js';
import { scanSigs, finishSigsRun, type LiveUrl } from '../src/content-sigs.js';

const AT = '2026-11-18T10:00:00.000Z';
const A: LiveUrl = { target: 'a.example', seed: 'https://a.example' };
const B: LiveUrl = { target: 'b.example', seed: 'https://b.example' };

type Reply = { status: number; body: string; head: Buffer; mitigated: boolean } | null;
const miss: Reply = { status: 404, body: '', head: Buffer.alloc(0), mitigated: false };
const gitHead: Reply = { status: 200, body: 'ref: refs/heads/main\n', head: Buffer.from('ref: refs/heads/main\n'), mitigated: false };

type ProbeFn = NonNullable<Parameters<typeof scanSigs>[2]['probeFn']>;

function probes(reply: (seed: string, path: string) => Reply): ProbeFn {
  return async (seed, sig) => reply(seed, sig.path);
}

async function scan(db: Db, live: LiveUrl[], probeFn: ProbeFn, withRun = true, notes?: string[], now = AT) {
  const runId = withRun ? db.startRun('content-sigs', {}, now) : null;
  return scanSigs(db, live, { now, runId, timeoutSec: 2, maxKb: 8, concurrency: 2, hostConcurrency: 4, write: () => {}, probeFn, ...(notes ? { notes } : {}) });
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
    await scan(db, [A], probes((_s, p) => (p === '.env' ? { status, body: '', head: Buffer.alloc(0), mitigated: false } : miss)));
    expect(cov(db)).toEqual([]);
  });

  it('covers a host whose probes got 403 and 404 answers', async () => {
    const db = openDb(':memory:');
    await scan(db, [A], probes((_s, p) => ({ status: p === '.env' ? 403 : 404, body: '', head: Buffer.alloc(0), mitigated: false })));
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

  it.each([401, 403, 301, 302])('does not cover a host that answered every probe with %i', async (status) => {
    const db = openDb(':memory:');
    await scan(db, [A], probes(() => ({ status, body: '', head: Buffer.alloc(0), mitigated: false })));
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a host with one cf-mitigated probe', async () => {
    const db = openDb(':memory:');
    await scan(db, [A], probes((_s, p) => (p === '.env' ? { ...miss!, status: 403, mitigated: true } : miss)));
    expect(cov(db)).toEqual([]);
  });

  it('rejects and records no coverage when a findings insert fails', async () => {
    const db = openDb(':memory:');
    db.raw.exec("CREATE TRIGGER t BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT,'database is locked'); END");
    await expect(scan(db, [A], probes((_s, p) => (p === '.git/HEAD' ? gitHead : miss)))).rejects.toThrow();
    expect(cov(db)).toEqual([]);
  });
});

describe('scanSigs coverage and the origin of open findings', () => {
  const open = (db: Db, matched: string) => db.insertFinding({
    tool: 'content-sigs', target: 'a.example', category: 'exposure-.git_HEAD', severity: 'high', title: 'Exposed .git/HEAD', matched_at: matched, meta: {},
  }, '2026-11-10T10:00:00.000Z', null);

  it('does not cover a host with an open finding from another origin, and says so', async () => {
    const db = openDb(':memory:');
    open(db, 'http://a.example:8080/.git/HEAD');
    const notes: string[] = [];
    await scan(db, [A], probes(() => miss), true, notes);
    expect(cov(db)).toEqual([]);
    expect(notes).toEqual(['1 target(s) not covered: an open finding came from an origin outside this run']);
  });

  const PATH_SEED: LiveUrl = { target: 'a.example', seed: 'https://a.example/app' };

  it('does not cover a host whose seed moved from a path to the root', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/app/.git/HEAD');
    await scan(db, [A], probes(() => miss), true, []);
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a host whose seed moved from the root to a path', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/.git/HEAD');
    await scan(db, [PATH_SEED], probes(() => miss), true, []);
    expect(cov(db)).toEqual([]);
  });

  it('covers a host whose open finding is the seed plus a signature path', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/app/.git/HEAD');
    await scan(db, [PATH_SEED], probes(() => miss), true, []);
    expect(cov(db)).toHaveLength(1);
  });

  it('does not cover a host whose open finding is on a path no signature requests', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/.git/gone');
    await scan(db, [A], probes(() => miss), true, []);
    expect(cov(db)).toEqual([]);
  });

  it('covers a host whose open findings all came from the seed origin', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/.git/HEAD');
    const notes: string[] = [];
    await scan(db, [A], probes(() => miss), true, notes);
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'content-sigs', seen_at: AT }]);
    expect(notes).toEqual([]);
  });

  it('records no coverage and says so when the open findings cannot be read', async () => {
    const db = openDb(':memory:');
    db.raw.exec('DROP TABLE findings');
    const notes: string[] = [];
    await scan(db, [A], probes(() => miss), true, notes);
    expect(cov(db)).toEqual([]);
    expect(notes).toEqual(['coverage skipped: cannot read open content-sigs findings']);
  });
});

describe('scanSigs keeps an open finding open once the pair has a coverage row', () => {
  const T1 = '2026-11-10T10:00:00.000Z';
  const T2 = '2026-11-18T10:00:00.000Z';
  const seed = (db: Db, matched: string) => {
    db.insertFinding({ tool: 'content-sigs', target: 'a.example', category: 'exposure-.env', severity: 'high', title: 'F', matched_at: matched, meta: {} }, T1, null);
    db.recordCoverage('content-sigs', ['a.example'], T1, null);
  };
  const state = (db: Db) => ({
    f: (db.raw.prepare(currentFindingsSelect(findingsRuleOpts(db.raw))).all() as { title: string; resolved: number }[]).find((r) => r.title === 'F')?.resolved,
    cov: (db.raw.prepare('SELECT seen_at FROM tool_coverage').all() as { seen_at: string }[]).map((r) => r.seen_at),
  });

  it('leaves F open when the run probed only another origin', async () => {
    const db = openDb(':memory:');
    seed(db, 'http://a.example:8080/.env');
    await scan(db, [A], probes((_s, p) => (p === '.git/HEAD' ? gitHead : miss)), true, undefined, T2);
    expect(state(db)).toEqual({ f: 0, cov: [T1] });
  });

  it('resolves F when the run probed its origin and did not report it', async () => {
    const db = openDb(':memory:');
    seed(db, 'https://a.example/.env');
    await scan(db, [A], probes((_s, p) => (p === '.git/HEAD' ? gitHead : miss)), true, undefined, T2);
    expect(state(db)).toEqual({ f: 1, cov: [T2] });
  });
});

describe('scanSigs marks the run partial for a host with rows and no coverage', () => {
  const T1 = '2026-11-10T10:00:00.000Z';
  const T2 = '2026-11-18T10:00:00.000Z';
  const F = (db: Db, withCoverage = false) => {
    db.insertFinding({ tool: 'content-sigs', target: 'a.example', category: 'exposure-.env', severity: 'high', title: 'F', matched_at: 'https://a.example/.env', meta: {} }, T1, null);
    if (withCoverage) db.recordCoverage('content-sigs', ['a.example'], T1, null);
  };
  async function runAndFinish(db: Db, live: LiveUrl[], probeFn: ProbeFn) {
    const runId = db.startRun('content-sigs', {}, T2);
    const notes: string[] = [];
    const stats = { incomplete: 0 };
    const n = await scanSigs(db, live, { now: T2, runId, timeoutSec: 2, maxKb: 8, concurrency: 2, hostConcurrency: 4, write: () => {}, probeFn, notes, stats });
    finishSigsRun(db, runId, live.length, n, stats, T2, notes);
    return {
      notes: (db.raw.prepare('SELECT notes FROM runs WHERE id = ?').get(runId) as { notes: string | null }).notes,
      marks: db.raw.prepare('SELECT run_id FROM partial_stamps').all().length,
      f: (db.raw.prepare(currentFindingsSelect(findingsRuleOpts(db.raw))).all() as { title: string; resolved: number }[]).find((r) => r.title === 'F')?.resolved,
    };
  }

  it('keeps F open when the .env probe failed and .git/HEAD hit (case A)', async () => {
    const db = openDb(':memory:');
    F(db);
    const r = await runAndFinish(db, [A], probes((_s, p) => (p === '.env' ? null : p === '.git/HEAD' ? gitHead : miss)));
    expect(r).toEqual({ notes: 'partial run: 1 host(s) incomplete', marks: 1, f: 0 });
  });

  it('closes F through coverage for a covered host, and the run is not partial', async () => {
    const db = openDb(':memory:');
    F(db, true);
    const r = await runAndFinish(db, [A], probes((_s, p) => (p === '.git/HEAD' ? gitHead : miss)));
    expect(r).toEqual({ notes: null, marks: 0, f: 1 });
  });

  it('is not partial when every host with rows is covered', async () => {
    const db = openDb(':memory:');
    const r = await runAndFinish(db, [A, B], probes((_s, p) => (p === '.git/HEAD' ? gitHead : miss)));
    expect(r.notes).toBeNull();
    expect(r.marks).toBe(0);
  });

  it('is not partial for a host with no rows and no coverage', async () => {
    const db = openDb(':memory:');
    const r = await runAndFinish(db, [A], probes(() => null));
    expect(r.notes).toBeNull();
    expect(r.marks).toBe(0);
  });
});
