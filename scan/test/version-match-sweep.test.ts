import { describe, it, expect, afterEach, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdirSync, rmSync } from 'node:fs';
import { openDb, type Db } from '../src/lib/db.js';
import { NvdWriter } from '../src/lib/nvd-db.js';
import { runVersionMatch, selectSweepTargets, SWEEP_TOOL } from '../src/version-match.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

const NOW = new Date('2026-11-03T00:00:00.000Z');

function buildNvd(snapshotAt: string, cves: string[] = ['CVE-2017-9798']): string {
  const d = join(tmpdir(), `vm-sweep-test-${randomBytes(6).toString('hex')}`);
  mkdirSync(d, { recursive: true });
  dirs.push(d);
  const path = join(d, 'nvd.db');
  const w = new NvdWriter(path);
  for (const cve of cves) {
    w.insertCve(cve, { cvss: 7.5, cvss_version: '3.1', published: null, last_modified: null });
    w.insertMatches([{ cve_id: cve, vendor: 'apache', product: 'http_server', version: '2.4.6', update_: '*', start_incl: null, start_excl: null, end_incl: null, end_excl: null }]);
  }
  w.setMeta('snapshot_at', snapshotAt);
  w.commit();
  return path;
}

function seed(db: Db): void {
  const apache = { web_server: 'Apache/2.4.6 (CentOS)', tech: ['Apache HTTP Server:2.4.6'] };
  db.insertHttpProbe({ target: 'recent.example', url: 'https://recent.example/', ...apache }, '2026-10-30T00:00:00Z', null);
  db.insertHttpProbe({ target: 'old.example', url: 'https://old.example/', ...apache }, '2026-08-01T00:00:00Z', null);
  db.insertPort({ target: 'port.example', port: 8080, protocol: 'tcp', product: 'Apache httpd', version: '2.4.6', extrainfo: '(CentOS)' }, '2026-10-20T00:00:00Z', null);
}

const findings = (db: Db) => db.raw.prepare("SELECT target, cve FROM findings WHERE tool='version-match' ORDER BY target, cve").all() as { target: string; cve: string }[];
const base = (db: Db, nvdDb: string, rollup = vi.fn(async () => true)) =>
  ({ db, targets: [], nvdDb, maxAgeDays: 14, dryRun: false, now: NOW, all: true, windowDays: 30, rollup, log: () => {} });

describe('version-match --all sweep', () => {
  it('selects targets with http or port evidence inside the window only', () => {
    const db = openDb(':memory:');
    seed(db);
    expect(selectSweepTargets(db, 30, NOW)).toEqual(['port.example', 'recent.example']);
    expect(selectSweepTargets(db, 120, NOW)).toEqual(['old.example', 'port.example', 'recent.example']);
  });

  it('matches recent targets, ignores old and the passed targets list', async () => {
    const db = openDb(':memory:');
    seed(db);
    const rollup = vi.fn(async () => true);
    const r = await runVersionMatch({ ...base(db, buildNvd('2026-11-02T00:00:00.000Z'), rollup), targets: ['old.example'] });
    expect(r.exitCode).toBe(0);
    expect(findings(db)).toEqual([
      { target: 'port.example', cve: 'CVE-2017-9798' },
      { target: 'recent.example', cve: 'CVE-2017-9798' },
    ]);
    expect(rollup).toHaveBeenCalledTimes(1);
  });

  it('is a no-op on the same snapshot, re-matches on a new one', async () => {
    const db = openDb(':memory:');
    seed(db);
    const rollup = vi.fn(async () => true);
    const snap1 = buildNvd('2026-11-02T00:00:00.000Z');
    await runVersionMatch(base(db, snap1, rollup));
    const markers = () => db.raw.prepare('SELECT id, finished_at, args_json FROM runs WHERE tool = ?').all(SWEEP_TOOL);
    const before = markers();
    expect(before).toHaveLength(1);
    expect(findings(db)).toHaveLength(2);

    const r2 = await runVersionMatch(base(db, snap1, rollup));
    expect(r2.noop).toBe(true);
    expect(r2.exitCode).toBe(0);
    expect(findings(db)).toHaveLength(2);
    expect(markers()).toEqual(before);
    expect(rollup).toHaveBeenCalledTimes(1);

    const snap2 = buildNvd('2026-11-03T00:00:00.000Z', ['CVE-2017-9798', 'CVE-2099-0001']);
    const r3 = await runVersionMatch(base(db, snap2, rollup));
    expect(r3.noop).toBeFalsy();
    expect(findings(db).filter((f) => f.cve === 'CVE-2099-0001')).toHaveLength(2);
    expect(markers()).toHaveLength(2);
    expect(rollup).toHaveBeenCalledTimes(2);
  });

  it('retries only the rollup when it failed after matching', async () => {
    const db = openDb(':memory:');
    seed(db);
    const snap = buildNvd('2026-11-02T00:00:00.000Z');
    const failing = vi.fn(async () => false);
    const r1 = await runVersionMatch(base(db, snap, failing));
    expect(r1.exitCode).toBe(1);
    const ok = vi.fn(async () => true);
    const r2 = await runVersionMatch(base(db, snap, ok));
    expect(r2.exitCode).toBe(0);
    expect(ok).toHaveBeenCalledTimes(1);
    expect(findings(db)).toHaveLength(2);
    const r3 = await runVersionMatch(base(db, snap, ok));
    expect(r3.noop).toBe(true);
    expect(ok).toHaveBeenCalledTimes(1);
  });

  it('missing nvd.db: exits 0, inserts nothing, no marker, no rollup', async () => {
    const db = openDb(':memory:');
    seed(db);
    const rollup = vi.fn(async () => true);
    const r = await runVersionMatch(base(db, '/nonexistent/nvd.db', rollup));
    expect(r.exitCode).toBe(0);
    expect(findings(db)).toHaveLength(0);
    expect(db.raw.prepare('SELECT 1 FROM runs WHERE tool = ?').all(SWEEP_TOOL)).toHaveLength(0);
    expect(rollup).not.toHaveBeenCalled();
  });

  it('dry-run writes no findings, marker or rollup', async () => {
    const db = openDb(':memory:');
    seed(db);
    const rollup = vi.fn(async () => true);
    await runVersionMatch({ ...base(db, buildNvd('2026-11-02T00:00:00.000Z'), rollup), dryRun: true });
    expect(findings(db)).toHaveLength(0);
    expect(db.raw.prepare('SELECT 1 FROM runs WHERE tool = ?').all(SWEEP_TOOL)).toHaveLength(0);
    expect(rollup).not.toHaveBeenCalled();
  });
});
