import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { openDb, type Db } from '../src/lib/db.js';
import { ffufHosts, type FfufDeps, type LiveUrl } from '../src/ffuf.js';

const AT = '2026-11-18T10:00:00.000Z';
const HOST: LiveUrl = { target: 'a.example', seed: 'https://a.example' };
const CANARY = { url: 'https://a.example/gen0sec-canary-x', status: 404, size: 9, body: 'not found', hash: 'h' };
const ONE_HIT = JSON.stringify({ results: [{ url: 'https://a.example/admin/', input: { FUZZ: 'admin/' }, status: 200, length: 4000 }] });

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

interface Scenario { canary?: typeof CANARY | null; code?: number; stderr?: string; report?: string | null }

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

async function scan(db: Db, sc: Scenario, withRun = true) {
  const dir = join(tmpdir(), `ffuf-test-${randomBytes(6).toString('hex')}`);
  mkdirSync(dir, { recursive: true });
  dirs.push(dir);
  const runId = withRun ? db.startRun('ffuf', {}, AT) : null;
  return ffufHosts(db, [HOST], {
    now: AT, runId, wl: join(dir, 'wl.txt'), threads: 1, timeoutSec: 2, hostTimeoutSec: 5, passthrough: [],
    outPath: (t) => join(dir, `${t}.json`), deps: deps(sc),
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
});
