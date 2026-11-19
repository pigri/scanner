import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { openDb, type Db } from '../src/lib/db.js';
import { currentFindingsSelect, findingsRuleOpts } from '../src/lib/current-findings.js';
import { ffufHosts, finishFfufRun, type FfufDeps, type LiveUrl } from '../src/ffuf.js';

const AT = '2026-11-18T10:00:00.000Z';
const HOST: LiveUrl = { target: 'a.example', seed: 'https://a.example' };
const CANARY = { url: 'https://a.example/gen0sec-canary-x', status: 404, size: 9, body: 'not found', hash: 'h' };
const ONE_HIT = JSON.stringify({ results: [{ url: 'https://a.example/admin/', input: { FUZZ: 'admin/' }, status: 200, length: 4000 }] });

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

interface Scenario { canary?: (typeof CANARY & { mitigated?: boolean }) | null; code?: number; stderr?: string; report?: string | null }

function deps(sc: Scenario): FfufDeps {
  return {
    fetchCanary: async () => (sc.canary === undefined ? CANARY : sc.canary),
    probeUrl: async () => null,
    run: async (_cmd: string, args: string[]) => {
      const out = args[args.indexOf('-o') + 1]!;
      if (sc.report !== null) writeFileSync(out, sc.report ?? '{"results":[]}');
      return { code: sc.code ?? 0, stdout: '', stderr: sc.stderr ?? '' };
    },
  };
}

async function scan(db: Db, sc: Scenario, withRun = true, notes?: string[], now = AT, host: LiveUrl = HOST, words: string[] | null = ['admin/'], passthrough: string[] = []) {
  const dir = join(tmpdir(), `ffuf-test-${randomBytes(6).toString('hex')}`);
  mkdirSync(dir, { recursive: true });
  dirs.push(dir);
  const runId = withRun ? db.startRun('ffuf', {}, now) : null;
  if (words) writeFileSync(join(dir, 'wl.txt'), words.join('\n') + '\n');
  return ffufHosts(db, [host], {
    now, runId, wl: join(dir, 'wl.txt'), threads: 1, timeoutSec: 2, hostTimeoutSec: 5, passthrough,
    outPath: (t) => join(dir, `${t}.json`), deps: deps(sc), ...(notes ? { notes } : {}),
  });
}
const cov = (db: Db) => db.raw.prepare('SELECT target, tool, seen_at FROM tool_coverage').all();

describe('ffufHosts coverage', () => {
  it('covers a host whose complete report had zero hits', async () => {
    const db = openDb(':memory:');
    expect((await scan(db, {})).findings).toBe(0);
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'ffuf', seen_at: AT }]);
  });

  it('records coverage with the stamp and target the findings carry', async () => {
    const db = openDb(':memory:');
    expect((await scan(db, { report: ONE_HIT })).findings).toBe(1);
    expect(db.raw.prepare("SELECT target, seen_at FROM findings WHERE tool='ffuf'").all())
      .toEqual([{ target: 'a.example', seen_at: AT }]);
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'ffuf', seen_at: AT }]);
  });

  it('does not cover a host with no canary, even with a clean exit', async () => {
    const db = openDb(':memory:');
    await scan(db, { canary: null });
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a non-zero exit, even with a report on disk', async () => {
    const db = openDb(':memory:');
    await scan(db, { code: 1, report: ONE_HIT });
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a job that hit -maxtime-job, which exits 0 with a partial report', async () => {
    const db = openDb(':memory:');
    await scan(db, { code: 0, report: ONE_HIT, stderr: 'Maximum running time for this job reached, continuing with next job if one exists.' });
    expect(cov(db)).toEqual([]);
  });

  it.each([
    ['no report', { report: null }],
    ['an empty report', { report: '' }],
    ['an unparseable report', { report: '{"results": [' }],
  ] as Array<[string, Scenario]>)('does not cover %s', async (_n, sc) => {
    const db = openDb(':memory:');
    await scan(db, sc);
    expect(cov(db)).toEqual([]);
  });

  it('records nothing for a null runId', async () => {
    const db = openDb(':memory:');
    await scan(db, {}, false);
    expect(cov(db)).toEqual([]);
  });

  it.each([401, 403, 429, 500, 503])('does not cover a host whose canary got %i', async (status) => {
    const db = openDb(':memory:');
    await scan(db, { canary: { ...CANARY, status } });
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a host whose canary carried cf-mitigated', async () => {
    const db = openDb(':memory:');
    await scan(db, { canary: { ...CANARY, mitigated: true } });
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a 403 canary whose all-403 report was dropped as WAF-uniform', async () => {
    const db = openDb(':memory:');
    const all403 = JSON.stringify({ results: Array.from({ length: 5 }, (_, i) => ({ url: `https://a.example/p${i}`, input: { FUZZ: `p${i}` }, status: 403, length: 100 })) });
    await scan(db, { canary: { ...CANARY, status: 403 }, report: all403 });
    expect(cov(db)).toEqual([]);
  });

  it.each([
    'Receiving spurious errors (ratio 0.5)',
    'Getting an unusual amount of 403 responses, exiting.',
  ])('does not cover a job that stopped on %s', async (stderr) => {
    const db = openDb(':memory:');
    await scan(db, { report: ONE_HIT, stderr });
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a host whose findings insert failed', async () => {
    const db = openDb(':memory:');
    db.raw.exec("CREATE TRIGGER t BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT,'database is locked'); END");
    await scan(db, { report: ONE_HIT });
    expect(cov(db)).toEqual([]);
  });
});

describe('ffufHosts coverage and the origin of open findings', () => {
  const EARLIER = '2026-11-10T10:00:00.000Z';
  const open = (db: Db, matched: string) => db.insertFinding({
    tool: 'ffuf', target: 'a.example', category: 'path-200', severity: 'medium', title: `200 ${matched}`, matched_at: matched, meta: {},
  }, EARLIER, null);

  it('does not cover a host with an open finding from another origin, and says so', async () => {
    const db = openDb(':memory:');
    open(db, 'http://a.example:8080/admin/');
    const notes: string[] = [];
    await scan(db, {}, true, notes);
    expect(cov(db)).toEqual([]);
    expect(notes).toEqual(['1 target(s) not covered: an open finding came from an origin outside this run']);
  });

  const PATH_SEED: LiveUrl = { target: 'a.example', seed: 'https://a.example/app' };

  it('does not cover a host whose seed moved from a path to the root', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/app/.env');
    await scan(db, {}, true, [], AT, HOST, ['.env', 'app']);
    expect(cov(db)).toEqual([]);
  });

  it('does not cover a host whose seed moved from the root to a path', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/.env');
    await scan(db, {}, true, [], AT, PATH_SEED, ['.env']);
    expect(cov(db)).toEqual([]);
  });

  it('covers a host whose open finding is the seed plus a wordlist entry, even one with a slash', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/app/admin/login');
    await scan(db, {}, true, [], AT, PATH_SEED, ['admin/login']);
    expect(cov(db)).toHaveLength(1);
  });

  it('does not cover a host whose open finding is on a word removed from the wordlist', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/old');
    await scan(db, {}, true, [], AT, HOST, ['new']);
    expect(cov(db)).toEqual([]);
  });

  it('counts a word plus an -e extension as requested', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/backup.zip');
    await scan(db, {}, true, [], AT, HOST, ['backup'], ['-e', '.zip']);
    expect(cov(db)).toHaveLength(1);
  });

  it('records no coverage, and says so, when the wordlist cannot be read', async () => {
    const db = openDb(':memory:');
    const notes: string[] = [];
    await scan(db, {}, true, notes, AT, HOST, null);
    expect(cov(db)).toEqual([]);
    expect(notes.join(';')).toContain('coverage skipped: cannot tell which paths ffuf requests');
  });

  it('records no coverage under -recursion', async () => {
    const db = openDb(':memory:');
    await scan(db, {}, true, [], AT, HOST, ['admin/'], ['-recursion']);
    expect(cov(db)).toEqual([]);
  });

  for (const flags of [['-u', 'https://b.example/FUZZ'], ['-x', 'http://127.0.0.1:8080'], ['--recursion=true'], ['-recursion=true'], ['-w=other.txt'], ['-request', 'req.txt'], ['-x-unknown'], ['-e=.zip', '-mc', '200']]) {
    it(`records no coverage, and says so, under the passthrough ${flags.join(' ')}`, async () => {
      const db = openDb(':memory:');
      const notes: string[] = [];
      await scan(db, {}, true, notes, AT, HOST, ['admin/'], flags);
      expect(cov(db)).toEqual([]);
      expect(notes.join(';')).toContain('coverage skipped: cannot tell which paths ffuf requests');
    });
  }

  for (const flags of [['-rate', '10'], ['-rate=10', '-v'], ['-p', '0.1-2.0', '-maxtime', '60'], ['-replay-proxy', 'http://127.0.0.1:8080', '-c']]) {
    it(`still covers under the allowlisted passthrough ${flags.join(' ')}`, async () => {
      const db = openDb(':memory:');
      await scan(db, {}, true, [], AT, HOST, ['admin/'], flags);
      expect(cov(db)).toHaveLength(1);
    });
  }

  it('counts a word plus an -e=ext extension as requested', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/backup.zip');
    await scan(db, {}, true, [], AT, HOST, ['backup'], ['-e=.zip']);
    expect(cov(db)).toHaveLength(1);
  });

  it('covers a host whose open findings all came from the seed origin', async () => {
    const db = openDb(':memory:');
    open(db, 'https://a.example/admin/');
    const notes: string[] = [];
    await scan(db, {}, true, notes);
    expect(cov(db)).toEqual([{ target: 'a.example', tool: 'ffuf', seen_at: AT }]);
    expect(notes).toEqual([]);
  });

  it('judges the open findings as they were before this run stored its own', async () => {
    const db = openDb(':memory:');
    open(db, 'http://a.example:8080/admin/');
    await scan(db, { report: ONE_HIT });
    expect(cov(db)).toEqual([]);
  });

  it('records no coverage and says so when the open findings cannot be read', async () => {
    const db = openDb(':memory:');
    db.raw.exec('DROP TABLE findings');
    const notes: string[] = [];
    await scan(db, {}, true, notes);
    expect(cov(db)).toEqual([]);
    expect(notes).toEqual(['coverage skipped: cannot read open ffuf findings']);
  });
});

describe('ffufHosts keeps an open finding open once the pair has a coverage row', () => {
  const T1 = '2026-11-10T10:00:00.000Z';
  const T2 = '2026-11-18T10:00:00.000Z';
  const seed = (db: Db) => {
    db.insertFinding({ tool: 'ffuf', target: 'a.example', category: 'path-200', severity: 'medium', title: 'F', matched_at: 'http://a.example:8080/admin/', meta: {} }, T1, null);
    db.recordCoverage('ffuf', ['a.example'], T1, null);
  };
  const state = (db: Db) => ({
    f: (db.raw.prepare(currentFindingsSelect(findingsRuleOpts(db.raw))).all() as { title: string; resolved: number }[]).find((r) => r.title === 'F')?.resolved,
    cov: (db.raw.prepare('SELECT seen_at FROM tool_coverage').all() as { seen_at: string }[]).map((r) => r.seen_at),
  });

  it('leaves F open when the run fetched only another origin', async () => {
    const db = openDb(':memory:');
    seed(db);
    await scan(db, { report: ONE_HIT }, true, undefined, T2);
    expect(state(db)).toEqual({ f: 0, cov: [T1] });
  });

  it('resolves F when the run fetched its origin and did not report it', async () => {
    const db = openDb(':memory:');
    db.insertFinding({ tool: 'ffuf', target: 'a.example', category: 'path-200', severity: 'medium', title: 'F', matched_at: 'https://a.example/old/', meta: {} }, T1, null);
    db.recordCoverage('ffuf', ['a.example'], T1, null);
    await scan(db, { report: ONE_HIT }, true, undefined, T2, HOST, ['admin/', 'old/']);
    expect(state(db)).toEqual({ f: 1, cov: [T2] });
  });
});

describe('ffuf partial runs', () => {
  const T0 = '2026-11-17T10:00:00.000Z';
  const ENV_HIT = JSON.stringify({ results: [{ url: 'https://a.example/.env', input: { FUZZ: '.env' }, status: 200, length: 90 }] });
  const OPEN = { coverage: true, partial: true } as const;

  async function runAt(db: Db, sc: Scenario, at: string) {
    const dir = join(tmpdir(), `ffuf-test-${randomBytes(6).toString('hex')}`);
    mkdirSync(dir, { recursive: true });
    dirs.push(dir);
    writeFileSync(join(dir, 'wl.txt'), 'admin/\n.env\n');
    const runId = db.startRun('ffuf', {}, at);
    const res = await ffufHosts(db, [HOST], {
      now: at, runId, wl: join(dir, 'wl.txt'), threads: 1, timeoutSec: 2, hostTimeoutSec: 5, passthrough: [],
      outPath: (t) => join(dir, `${t}.json`), deps: deps(sc),
    });
    finishFfufRun(db, runId, 1, res, at);
    return runId;
  }
  const resolved = (db: Db) => (db.raw.prepare(currentFindingsSelect(OPEN)).all() as Array<{ title: string; resolved: number }>)
    .map((r) => [r.title.includes('.env') ? '.env' : 'admin', r.resolved] as [string, number])
    .sort();
  const note = (db: Db, id: number) => (db.raw.prepare('SELECT notes, finished_at FROM runs WHERE id = ?').get(id) as { notes: string | null; finished_at: string | null });

  it.each([
    ['a non-zero exit with a report', { code: 1, report: ENV_HIT }],
    ['a job that stopped early', { report: ENV_HIT, stderr: 'Maximum running time for this job reached' }],
    ['a blocked canary', { report: ENV_HIT, canary: { ...CANARY, status: 429 } }],
  ] as Array<[string, Scenario]>)('keeps an older finding open after %s', async (_n, sc) => {
    const db = openDb(':memory:');
    await runAt(db, { report: ONE_HIT, canary: { ...CANARY, status: 429 } }, T0);
    const id = await runAt(db, sc, AT);
    expect(resolved(db)).toEqual([['.env', 0], ['admin', 0]]);
    expect(note(db, id).notes).toContain('partial run: 1 host(s) incomplete');
  });

  it('a clean run still closes an older finding', async () => {
    const db = openDb(':memory:');
    await runAt(db, { report: ONE_HIT, canary: { ...CANARY, status: 429 } }, T0);
    const id = await runAt(db, { report: ENV_HIT }, AT);
    expect(resolved(db)).toEqual([['.env', 0], ['admin', 1]]);
    expect(note(db, id).notes ?? '').not.toContain('partial');
  });

  it('a clean run with no hits is complete, not partial', async () => {
    const db = openDb(':memory:');
    const id = await runAt(db, {}, AT);
    expect(note(db, id).notes ?? '').not.toContain('partial');
  });

  it('a failure that wrote no rows is not partial', async () => {
    const db = openDb(':memory:');
    const id = await runAt(db, { code: 1, report: null }, AT);
    expect(note(db, id).notes ?? '').not.toContain('partial');
  });
});
