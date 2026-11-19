import { describe, it, expect } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { currentFindingsSelect, findingsRuleOpts } from '../src/lib/current-findings.js';
import { auditUrls, finishHeadersRun, type LiveUrl } from '../src/headers.js';

const AT = '2026-11-18T10:00:00.000Z';
const URL_A: LiveUrl = { target: 'a.example', url: 'https://a.example/', scheme: 'https' };

function fetchReturning(status: number, headers: Record<string, string> = {}): typeof fetch {
  return (async () => new Response(null, { status, headers })) as unknown as typeof fetch;
}
const failing: typeof fetch = (async () => { throw new TypeError('fetch failed'); }) as unknown as typeof fetch;

async function audit(db: Db, urls: LiveUrl[], fetchFn: typeof fetch, withRun = true, notes?: string[], now = AT) {
  const runId = withRun ? db.startRun('headers', {}, now) : null;
  return auditUrls(db, urls, { now, runId, timeoutSec: 2, concurrency: 2, write: () => {}, fetchFn, ...(notes ? { notes } : {}) });
}
const cov = (db: Db) => db.raw.prepare('SELECT target, tool, seen_at, run_id FROM tool_coverage ORDER BY target').all();

describe('auditUrls coverage', () => {
  it('covers a target whose response carried no findings, at the findings stamp', async () => {
    const db = openDb(':memory:');
    const good = {
      'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
      'permissions-policy': 'geolocation=()', 'cross-origin-opener-policy': 'same-origin',
      'cross-origin-embedder-policy': 'require-corp',
    };
    expect(await audit(db, [URL_A], fetchReturning(200, good))).toBe(0);
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'headers', seen_at: AT, run_id: 1 }]);
  });

  it('records coverage with the stamp and target the findings carry', async () => {
    const db = openDb(':memory:');
    expect(await audit(db, [URL_A], fetchReturning(200))).toBeGreaterThan(0);
    const f = db.raw.prepare("SELECT DISTINCT target, seen_at FROM findings WHERE tool='headers'").all();
    expect(f).toEqual([{ target: 'a.example', seen_at: AT }]);
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'headers', seen_at: AT, run_id: 1 }]);
  });

  it('does not cover a target whose fetch failed', async () => {
    const db = openDb(':memory:');
    await audit(db, [URL_A], failing);
    expect(cov(db)).toEqual([]);
  });

  it('covers only the targets that answered', async () => {
    const db = openDb(':memory:');
    const b: LiveUrl = { target: 'b.example', url: 'https://b.example/', scheme: 'https' };
    const mixed = (async (u: string) => {
      if (u.includes('b.example')) throw new TypeError('fetch failed');
      return new Response(null, { status: 200, headers: { 'x-a': '1' } });
    }) as unknown as typeof fetch;
    await audit(db, [URL_A, b], mixed);
    expect((cov(db) as Array<{ target: string }>).map((r) => r.target)).toEqual(['a.example']);
  });

  it.each([401, 403, 404, 429, 500, 502, 503])('does not cover a %i response', async (status) => {
    const db = openDb(':memory:');
    await audit(db, [URL_A], fetchReturning(status, { 'x-a': '1' }));
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a challenge page marked by cf-mitigated', async () => {
    const db = openDb(':memory:');
    await audit(db, [URL_A], fetchReturning(200, { 'cf-mitigated': 'challenge' }));
    expect(cov(db)).toEqual([]);
  });

  it.each([200, 204, 301, 304])('covers a %i response', async (status) => {
    const db = openDb(':memory:');
    await audit(db, [URL_A], fetchReturning(status, { 'x-a': '1' }));
    expect(cov(db)).toHaveLength(1);
  });

  it('records nothing for a null runId', async () => {
    const db = openDb(':memory:');
    await audit(db, [URL_A], fetchReturning(200), false);
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a redirect that ended on another host', async () => {
    const db = openDb(':memory:');
    const moved = (async () => {
      const r = new Response(null, { status: 200, headers: { 'x-a': '1' } });
      Object.defineProperty(r, 'url', { value: 'https://b.example/' });
      return r;
    }) as unknown as typeof fetch;
    await audit(db, [URL_A], moved);
    expect(cov(db)).toEqual([]);
  });

  it('covers a redirect that stayed on the same host', async () => {
    const db = openDb(':memory:');
    const same = (async () => {
      const r = new Response(null, { status: 200, headers: { 'x-a': '1' } });
      Object.defineProperty(r, 'url', { value: 'https://a.example/home' });
      return r;
    }) as unknown as typeof fetch;
    await audit(db, [URL_A], same);
    expect(cov(db)).toHaveLength(1);
  });

  it('does not cover a target whose findings insert failed', async () => {
    const db = openDb(':memory:');
    db.raw.exec("CREATE TRIGGER t BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT,'database is locked'); END");
    await audit(db, [URL_A], fetchReturning(200));
    expect(cov(db)).toEqual([]);
  });
});

describe('auditUrls coverage and the origin of open findings', () => {
  const open = (db: Db, matched: string) => db.insertFinding({
    tool: 'headers', target: 'a.example', category: 'hsts', severity: 'low', title: 'HSTS missing', matched_at: matched, meta: {},
  }, '2026-11-10T10:00:00.000Z', null);

  it('does not cover a target with an open finding from another origin, and says so', async () => {
    const db = openDb(':memory:');
    open(db, 'http://a.example:8080/');
    const notes: string[] = [];
    await audit(db, [URL_A], fetchReturning(200), true, notes);
    expect(cov(db)).toEqual([]);
    expect(notes).toEqual(['1 target(s) not covered: an open finding came from an origin outside this run']);
  });

  const URL_PATH: LiveUrl = { target: 'a.example', url: 'https://a.example/app', scheme: 'https' };

  it('does not cover a target whose open finding came from another url on the origin', async () => {
    for (const [matched, seed] of [['https://a.example/app/', URL_A], ['https://a.example/', URL_PATH]] as const) {
      const db = openDb(':memory:');
      open(db, matched);
      await audit(db, [seed], fetchReturning(200), true, []);
      expect(cov(db), `${matched} vs ${seed.url}`).toEqual([]);
    }
  });

  it('covers a target whose open findings all came from the audited origin', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/');
    const notes: string[] = [];
    await audit(db, [URL_A], fetchReturning(200), true, notes);
    expect(cov(db)).toHaveLength(1);
    expect(notes).toEqual([]);
  });

  it('records no coverage and says so when the open findings cannot be read', async () => {
    const db = openDb(':memory:');
    db.raw.exec('DROP TABLE findings');
    const notes: string[] = [];
    await audit(db, [URL_A], fetchReturning(200, { 'x-a': '1' }), true, notes).catch(() => 0);
    expect(cov(db)).toEqual([]);
    expect(notes).toEqual(['coverage skipped: cannot read open headers findings']);
  });
});

describe('auditUrls keeps an open finding open once the pair has a coverage row', () => {
  const T1 = '2026-11-10T10:00:00.000Z';
  const T2 = '2026-11-18T10:00:00.000Z';
  const seed = (db: Db, matched: string) => {
    db.insertFinding({ tool: 'headers', target: 'a.example', category: 'hsts', severity: 'low', title: 'F', matched_at: matched, meta: {} }, T1, null);
    db.recordCoverage('headers', ['a.example'], T1, null);
  };
  const state = (db: Db) => ({
    f: (db.raw.prepare(currentFindingsSelect(findingsRuleOpts(db.raw))).all() as { title: string; resolved: number }[]).find((r) => r.title === 'F')?.resolved,
    cov: (db.raw.prepare('SELECT seen_at FROM tool_coverage').all() as { seen_at: string }[]).map((r) => r.seen_at),
  });

  it('leaves F open when the run audited only another origin', async () => {
    const db = openDb(':memory:');
    seed(db, 'http://a.example:8080/');
    await audit(db, [URL_A], fetchReturning(200), true, undefined, T2);
    expect(state(db)).toEqual({ f: 0, cov: [T1] });
  });

  it('resolves F when the run audited its origin and did not report it', async () => {
    const db = openDb(':memory:');
    seed(db, 'https://a.example/');
    await audit(db, [URL_A], fetchReturning(200), true, undefined, T2);
    expect(state(db)).toEqual({ f: 1, cov: [T2] });
  });
});

describe('auditUrls marks the run partial for a target with rows and no coverage', () => {
  const T1 = '2026-11-10T10:00:00.000Z';
  const T2 = '2026-11-18T10:00:00.000Z';
  const F = (db: Db, withCoverage = false) => {
    db.insertFinding({ tool: 'headers', target: 'a.example', category: 'hsts', severity: 'low', title: 'F', matched_at: 'https://a.example/', meta: {} }, T1, null);
    if (withCoverage) db.recordCoverage('headers', ['a.example'], T1, null);
  };
  async function runAndFinish(db: Db, urls: LiveUrl[], fetchFn: typeof fetch) {
    const runId = db.startRun('headers', {}, T2);
    const notes: string[] = [];
    const stats = { incomplete: 0 };
    const n = await auditUrls(db, urls, { now: T2, runId, timeoutSec: 2, concurrency: 2, write: () => {}, fetchFn, notes, stats });
    finishHeadersRun(db, runId, urls.length, n, stats, T2, notes);
    return {
      notes: (db.raw.prepare('SELECT notes FROM runs WHERE id = ?').get(runId) as { notes: string | null }).notes,
      marks: db.raw.prepare('SELECT run_id FROM partial_stamps').all().length,
      f: (db.raw.prepare(currentFindingsSelect(findingsRuleOpts(db.raw))).all() as { title: string; resolved: number }[]).find((r) => r.title === 'F')?.resolved,
    };
  }
  const GOOD = {
    'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
    'permissions-policy': 'geolocation=()', 'cross-origin-opener-policy': 'same-origin',
    'cross-origin-embedder-policy': 'require-corp',
  };

  it('keeps F open when the seed answered 404 but its missing headers were stored', async () => {
    const db = openDb(':memory:');
    F(db);
    const r = await runAndFinish(db, [URL_A], fetchReturning(404, { server: 'x' }));
    expect(r).toEqual({ notes: 'partial run: 1 host(s) incomplete', marks: 1, f: 0 });
  });

  it('closes F through coverage for a covered target, and the run is not partial', async () => {
    const db = openDb(':memory:');
    F(db, true);
    const r = await runAndFinish(db, [URL_A], fetchReturning(200, GOOD));
    expect(r).toEqual({ notes: null, marks: 0, f: 1 });
  });

  it('is not partial when every target with rows is covered', async () => {
    const db = openDb(':memory:');
    const r = await runAndFinish(db, [URL_A], fetchReturning(200, { server: 'x' }));
    expect(r.notes).toBeNull();
    expect(r.marks).toBe(0);
  });

  it('is not partial for a target with no rows and no coverage', async () => {
    const db = openDb(':memory:');
    const r = await runAndFinish(db, [URL_A], failing);
    expect(r.notes).toBeNull();
    expect(r.marks).toBe(0);
  });
});
