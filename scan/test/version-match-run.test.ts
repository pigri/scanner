import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdirSync, rmSync } from 'node:fs';
import { openDb, type Db } from '../src/lib/db.js';
import { NvdWriter, type VulnLookup } from '../src/lib/nvd-db.js';
import { runVersionMatch } from '../src/version-match.js';
import { currentFindingsSelect } from '../src/lib/current-findings.js';

const dirs: string[] = [];
function tmpDir(): string {
  const d = join(tmpdir(), `vm-run-test-${randomBytes(6).toString('hex')}`);
  mkdirSync(d, { recursive: true });
  dirs.push(d);
  return d;
}
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

const NOW = new Date('2026-11-03T00:00:00.000Z');

function buildNvd(snapshotAt: string): string {
  const path = join(tmpDir(), 'nvd.db');
  const w = new NvdWriter(path);
  const rows = (cve: string, vendor: string, product: string, version: string, extra: Record<string, string | null> = {}) =>
    w.insertMatches([{ cve_id: cve, vendor, product, version, update_: '*', start_incl: null, start_excl: null, end_incl: null, end_excl: null, ...extra }]);
  w.insertCve('CVE-2017-9798', { cvss: 7.5, cvss_version: '3.1', published: null, last_modified: null });
  rows('CVE-2017-9798', 'apache', 'http_server', '2.4.6');
  w.insertCve('CVE-2016-2107', { cvss: 5.9, cvss_version: '3.1', published: null, last_modified: null });
  rows('CVE-2016-2107', 'openssl', 'openssl', '*', { start_incl: '1.0.2', end_excl: '1.0.2m' });
  w.insertCve('CVE-2022-31629', { cvss: 9.8, cvss_version: '3.1', published: null, last_modified: null });
  rows('CVE-2022-31629', 'php', 'php', '*', { end_excl: '8.0.31' });
  w.setMeta('snapshot_at', snapshotAt);
  w.commit();
  return path;
}

function seed(db: Db): void {
  db.insertHttpProbe({ target: 'a.example', url: 'https://a.example/', web_server: 'Apache/2.4.7', tech: ['Apache HTTP Server:2.4.7'] }, '2026-10-01T00:00:00Z', null);
  db.insertHttpProbe({
    target: 'a.example', url: 'https://a.example/',
    web_server: 'Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/8.0.30',
    tech: ['Apache HTTP Server:2.4.6', 'OpenSSL:1.0.2k', 'PHP:8.0.30'],
  }, '2026-11-01T00:00:00Z', null);
  db.insertHttpProbe({
    target: 'a.example', url: 'https://www.a.example/',
    web_server: 'Apache/2.4.6 (CentOS)', tech: ['Apache HTTP Server:2.4.6'],
  }, '2026-11-01T00:00:00Z', null);
}

const findings = (db: Db) => db.raw.prepare("SELECT * FROM findings WHERE tool='version-match' ORDER BY cve, matched_at").all() as Array<Record<string, any>>;

describe('runVersionMatch', () => {
  it('inserts findings with the contract shape, deduped per (target,vendor,product,version)', async () => {
    const db = openDb(':memory:');
    seed(db);
    const r = await runVersionMatch({ db, targets: ['a.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(r.exitCode).toBe(0);
    const f = findings(db);
    expect(f.map((x) => x.cve)).toEqual(['CVE-2016-2107', 'CVE-2017-9798', 'CVE-2022-31629']);
    const ap = f.find((x) => x.cve === 'CVE-2017-9798')!;
    expect(ap).toMatchObject({
      tool: 'version-match', target: 'a.example', category: 'cve', severity: 'high',
      title: 'CVE-2017-9798 on Apache httpd 2.4.6 (version match)', needs_review: 0,
      matched_at: 'https://a.example/',
    });
    const meta = JSON.parse(ap.meta_json);
    expect(meta).toMatchObject({
      cvss: 7.5, cvss_version: '3.1', confidence: 'version-match-distro',
      evidence: expect.stringContaining('Apache/2.4.6'), cpe: 'cpe:2.3:a:apache:http_server:2.4.6',
      matched_rule: 'exact', nvd_snapshot_at: '2026-11-01T00:00:00.000Z',
    });
    expect(meta.nvd_stale).toBeUndefined();
    expect(typeof meta.cvss).toBe('number');
    // 2.4.6 seen on two URLs, still one finding
    expect(f.filter((x) => x.cve === 'CVE-2017-9798')).toHaveLength(1);
  });

  it('uses only the latest evidence per URL', async () => {
    const db = openDb(':memory:');
    seed(db);
    await runVersionMatch({ db, targets: ['a.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(findings(db).some((x) => x.title.includes('2.4.7'))).toBe(false);
  });

  it('reads port evidence', async () => {
    const db = openDb(':memory:');
    db.insertPort({ target: 'b.example', port: 8080, protocol: 'tcp', product: 'Apache httpd', version: '2.4.6', extrainfo: '(CentOS)' }, '2026-11-01T00:00:00Z', null);
    await runVersionMatch({ db, targets: ['b.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    const f = findings(db);
    expect(f).toHaveLength(1);
    expect(f[0]!.matched_at).toBe('b.example:8080');
  });

  it('dry-run inserts nothing', async () => {
    const db = openDb(':memory:');
    seed(db);
    const r = await runVersionMatch({ db, targets: ['a.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: true, now: NOW, log: () => {} });
    expect(r.exitCode).toBe(0);
    expect(r.matched).toBe(3);
    expect(findings(db)).toHaveLength(0);
  });

  it('missing nvd.db: inserts nothing, notes the run, exits 0', async () => {
    const db = openDb(':memory:');
    seed(db);
    const r = await runVersionMatch({ db, targets: ['a.example'], nvdDb: '/nonexistent/nvd.db', maxAgeDays: 14, dryRun: false, now: NOW });
    expect(r.exitCode).toBe(0);
    expect(findings(db)).toHaveLength(0);
    const run = db.raw.prepare("SELECT notes FROM runs WHERE tool='version-match'").get() as { notes: string };
    expect(run.notes).toMatch(/nvd\.db/);
  });

  it('stale nvd.db still matches but marks meta.nvd_stale', async () => {
    const db = openDb(':memory:');
    seed(db);
    const r = await runVersionMatch({ db, targets: ['a.example'], nvdDb: buildNvd('2026-09-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(r.exitCode).toBe(0);
    const f = findings(db);
    expect(f.length).toBeGreaterThan(0);
    expect(JSON.parse(f[0]!.meta_json).nvd_stale).toBe(true);
  });

  it('isolates a per-target failure', async () => {
    const db = openDb(':memory:');
    seed(db);
    db.insertHttpProbe({ target: 'bad.example', url: 'https://bad.example/', web_server: 'nginx/1.18.0' }, '2026-11-01T00:00:00Z', null);
    const inner = buildNvd('2026-11-01T00:00:00.000Z');
    const { openNvdLookup } = await import('../src/lib/nvd-db.js');
    const real = openNvdLookup(inner)!;
    const lookup: VulnLookup = {
      snapshotAt: real.snapshotAt,
      cpeMatches: (v, p) => { if (p === 'nginx') throw new Error('boom'); return real.cpeMatches(v, p); },
      cveMeta: (ids) => real.cveMeta(ids),
    };
    const r = await runVersionMatch({ db, targets: ['bad.example', 'a.example'], nvdDb: inner, lookup, maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
    expect(r.exitCode).toBe(0);
    expect(r.failedTargets).toBe(1);
    expect(findings(db).every((x) => x.target === 'a.example')).toBe(true);
    expect(findings(db).length).toBe(3);
  });

  describe('tool coverage', () => {
    const cov = (db: Db) =>
      db.raw.prepare('SELECT target, tool, seen_at, run_id FROM tool_coverage ORDER BY target').all();
    const AT = NOW.toISOString();

    it('covers a target that matched, with the same at and target as its findings', async () => {
      const db = openDb(':memory:');
      seed(db);
      await runVersionMatch({ db, targets: ['a.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
      const runId = (db.raw.prepare("SELECT id FROM runs WHERE tool='version-match'").get() as { id: number }).id;
      expect(cov(db)).toEqual([{ target: 'a.example', tool: 'version-match', seen_at: AT, run_id: runId }]);
      expect(findings(db).length).toBeGreaterThan(0);
      expect(findings(db).every((f) => f.target === 'a.example' && f.seen_at === AT)).toBe(true);
    });

    it('covers a target with evidence but no CVE match', async () => {
      const db = openDb(':memory:');
      db.insertHttpProbe({ target: 'c.example', url: 'https://c.example/', web_server: 'nginx/1.25.3' }, '2026-11-01T00:00:00.000Z', null);
      await runVersionMatch({ db, targets: ['c.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
      expect(findings(db)).toHaveLength(0);
      expect(cov(db).map((r: any) => r.target)).toEqual(['c.example']);
    });

    it('records nothing on a dry run', async () => {
      const db = openDb(':memory:');
      seed(db);
      await runVersionMatch({ db, targets: ['a.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: true, now: NOW, log: () => {} });
      expect(cov(db)).toEqual([]);
    });

    it('records nothing when the NVD lookup is unavailable', async () => {
      const db = openDb(':memory:');
      seed(db);
      await runVersionMatch({ db, targets: ['a.example'], nvdDb: '/nonexistent/nvd.db', maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
      expect(cov(db)).toEqual([]);
    });

    it('does not cover a target whose lookup throws, but covers the others', async () => {
      const db = openDb(':memory:');
      seed(db);
      db.insertHttpProbe({ target: 'bad.example', url: 'https://bad.example/', web_server: 'nginx/1.18.0' }, '2026-11-01T00:00:00.000Z', null);
      const inner = buildNvd('2026-11-01T00:00:00.000Z');
      const { openNvdLookup } = await import('../src/lib/nvd-db.js');
      const real = openNvdLookup(inner)!;
      const lookup: VulnLookup = {
        snapshotAt: real.snapshotAt,
        cpeMatches: (v, p) => { if (p === 'nginx') throw new Error('boom'); return real.cpeMatches(v, p); },
        cveMeta: (ids) => real.cveMeta(ids),
      };
      await runVersionMatch({ db, targets: ['bad.example', 'a.example'], nvdDb: inner, lookup, maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
      expect(cov(db).map((r: any) => r.target)).toEqual(['a.example']);
    });

    it('does not cover a target whose insert was skipped as busy', async () => {
      const db = openDb(':memory:');
      seed(db);
      const real = db.insertFinding.bind(db);
      db.insertFinding = () => { throw Object.assign(new Error('locked'), { code: 'SQLITE_BUSY' }); };
      const r = await runVersionMatch({ db, targets: ['a.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
      db.insertFinding = real;
      expect(r.busySkipped).toBeGreaterThan(0);
      expect(cov(db)).toEqual([]);
    });
  });

  it('a newer banner-less http probe does not hide the older banner, and the target is covered', async () => {
    const db = openDb(':memory:');
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: 'Apache/2.4.6 (CentOS)', tech: ['Apache HTTP Server:2.4.6'] }, '2026-11-01T00:00:00.000Z', null);
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: null, tech: [] }, '2026-11-02T00:00:00.000Z', null);
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: '' }, '2026-11-02T01:00:00.000Z', null);
    await runVersionMatch({ db, targets: ['h.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(findings(db).map((f) => f.cve)).toEqual(['CVE-2017-9798']);
    expect(db.raw.prepare('SELECT target FROM tool_coverage').all()).toEqual([{ target: 'h.example' }]);
  });

  it('a newer header-less probe with only unrelated tech does not hide the older header', async () => {
    const db = openDb(':memory:');
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: 'Apache/2.4.6 (CentOS)' }, '2026-11-01T00:00:00.000Z', null);
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: null, tech: ['HSTS'] }, '2026-11-02T00:00:00.000Z', null);
    await runVersionMatch({ db, targets: ['h.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(findings(db).map((f) => f.cve)).toEqual(['CVE-2017-9798']);
    expect(db.raw.prepare('SELECT target FROM tool_coverage').all()).toEqual([{ target: 'h.example' }]);
  });

  it('takes a version from a newer header-less probe whose tech carries it', async () => {
    const db = openDb(':memory:');
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: 'Apache' }, '2026-11-01T00:00:00.000Z', null);
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: null, tech: ['Apache HTTP Server:2.4.6'] }, '2026-11-02T00:00:00.000Z', null);
    await runVersionMatch({ db, targets: ['h.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(findings(db).map((f) => f.cve)).toEqual(['CVE-2017-9798']);
  });

  for (const [label, tech] of [['NULL tech', undefined], ['empty tech', [] as string[]]] as const) {
    it(`a newer probe with ${label} does not hide the older tech version`, async () => {
      const db = openDb(':memory:');
      db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: 'Apache', tech: ['Apache HTTP Server:2.4.6'] }, '2026-11-01T00:00:00.000Z', null);
      db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: 'Apache', ...(tech ? { tech } : {}) }, '2026-11-02T00:00:00.000Z', null);
      await runVersionMatch({ db, targets: ['h.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
      expect(findings(db).map((f) => f.cve)).toEqual(['CVE-2017-9798']);
      expect(db.raw.prepare('SELECT target FROM tool_coverage').all()).toEqual([{ target: 'h.example' }]);
    });
  }

  it('applies the distro hint of the header row to tech-only evidence', async () => {
    const db = openDb(':memory:');
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: 'nginx/1.18.0 (CentOS)', tech: ['Apache HTTP Server:2.4.6'] }, '2026-11-01T00:00:00.000Z', null);
    await runVersionMatch({ db, targets: ['h.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    const f = findings(db);
    expect(f).toHaveLength(1);
    expect(JSON.parse(f[0]!.meta_json).confidence).toBe('version-match-distro');
  });

  it('a newer bare-product banner is a real change: no findings, still covered', async () => {
    const db = openDb(':memory:');
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: 'Apache/2.4.6 (CentOS)' }, '2026-11-01T00:00:00.000Z', null);
    db.insertHttpProbe({ target: 'h.example', url: 'https://h.example/', web_server: 'Apache' }, '2026-11-02T00:00:00.000Z', null);
    await runVersionMatch({ db, targets: ['h.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(findings(db)).toHaveLength(0);
    expect(db.raw.prepare('SELECT target FROM tool_coverage').all()).toEqual([{ target: 'h.example' }]);
  });

  it('a newer banner-less ports row does not hide the evidence', async () => {
    const db = openDb(':memory:');
    db.insertPort({ target: 'b.example', port: 8080, protocol: 'tcp', product: 'Apache httpd', version: '2.4.6', extrainfo: '(CentOS)' }, '2026-11-01T00:00:00.000Z', null);
    db.insertPort({ target: 'b.example', port: 8080, protocol: 'tcp', service: 'http-alt' }, '2026-11-02T00:00:00.000Z', null);
    await runVersionMatch({ db, targets: ['b.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(findings(db).map((f) => f.matched_at)).toEqual(['b.example:8080']);
  });

  it('takes port evidence from the latest row that has a product', async () => {
    const db = openDb(':memory:');
    db.insertPort({ target: 'b.example', port: 8080, protocol: 'tcp', product: 'Apache httpd', version: '2.4.7' }, '2026-10-01T00:00:00.000Z', null);
    db.insertPort({ target: 'b.example', port: 8080, protocol: 'tcp', product: 'Apache httpd', version: '2.4.6', extrainfo: '(CentOS)' }, '2026-11-01T00:00:00.000Z', null);
    db.insertPort({ target: 'b.example', port: 8080, protocol: 'tcp' }, '2026-11-02T00:00:00.000Z', null);
    await runVersionMatch({ db, targets: ['b.example'], nvdDb: buildNvd('2026-11-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW });
    expect(findings(db).some((f) => f.title.includes('2.4.7'))).toBe(false);
    expect(findings(db)).toHaveLength(1);
  });
});

describe('runVersionMatch partial runs', () => {
  const T0 = '2026-10-20T00:00:00.000Z';
  const OLD = 'CVE-2010-0001';
  const OPEN = { coverage: true, partial: true } as const;
  const oldResolved = (db: Db) =>
    (db.raw.prepare(currentFindingsSelect(OPEN)).all() as Array<{ title: string; resolved: number }>)
      .filter((r) => r.title.startsWith(OLD)).map((r) => r.resolved);
  const lastNotes = (db: Db) => (db.raw.prepare("SELECT notes FROM runs WHERE tool = 'version-match' ORDER BY id DESC LIMIT 1").get() as { notes: string | null }).notes ?? '';
  const withOld = () => {
    const db = openDb(':memory:');
    seed(db);
    db.insertFinding({ tool: 'version-match', target: 'a.example', category: 'cve', severity: 'high', title: `${OLD} on Old 1.0 (version match)`, cve: OLD }, T0, null);
    return db;
  };
  const nvd = () => buildNvd('2026-11-01T00:00:00.000Z');
  const flaky = async () => {
    const { openNvdLookup } = await import('../src/lib/nvd-db.js');
    const real = openNvdLookup(nvd())!;
    const lookup: VulnLookup = {
      snapshotAt: real.snapshotAt,
      cpeMatches: (v, p) => { if (p === 'openssl') throw new Error('boom'); return real.cpeMatches(v, p); },
      cveMeta: (ids) => real.cveMeta(ids),
    };
    return lookup;
  };

  it('keeps an older finding open after a target failed midway', async () => {
    const db = withOld();
    await runVersionMatch({ db, targets: ['a.example'], nvdDb: nvd(), lookup: await flaky(), maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
    expect(findings(db).length).toBeGreaterThan(0);
    expect(oldResolved(db)).toEqual([0]);
    expect(lastNotes(db)).toContain('partial run: 1 target(s) failed');
  });

  it('keeps an older finding open after a finding was skipped as busy', async () => {
    const db = withOld();
    const real = db.insertFinding.bind(db);
    let n = 0;
    db.insertFinding = (row, at, id) => { if (++n === 2) throw Object.assign(new Error('locked'), { code: 'SQLITE_BUSY' }); return real(row, at, id); };
    await runVersionMatch({ db, targets: ['a.example'], nvdDb: nvd(), maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
    db.insertFinding = real;
    expect(oldResolved(db)).toEqual([0]);
    expect(lastNotes(db)).toContain('partial run: 1 finding(s) skipped: scan.db busy');
  });

  it('notes an unavailable nvd.db as a partial run', async () => {
    const db = withOld();
    await runVersionMatch({ db, targets: ['a.example'], nvdDb: '/nonexistent/nvd.db', maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
    expect(lastNotes(db)).toContain('partial run: nvd.db unavailable');
  });

  it('a clean run still closes an older finding', async () => {
    const db = withOld();
    await runVersionMatch({ db, targets: ['a.example'], nvdDb: nvd(), maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
    expect(oldResolved(db)).toEqual([1]);
    expect(lastNotes(db)).not.toContain('partial');
  });

  it('a stale snapshot alone is not partial', async () => {
    const db = withOld();
    await runVersionMatch({ db, targets: ['a.example'], nvdDb: buildNvd('2026-01-01T00:00:00.000Z'), maxAgeDays: 14, dryRun: false, now: NOW, log: () => {} });
    expect(lastNotes(db)).toContain('older than');
    expect(lastNotes(db)).not.toContain('partial');
  });
});
