import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import {
  NVD_SCHEMA_VERSION,
  NvdWriter,
  cpeRowsFromCve,
  cveMetaFromCve,
  isRejected,
  openNvdLookup,
  replaceAtomically,
  type NvdCveInput,
} from '../src/lib/nvd-db.js';
import { fetchWithRetry } from '../src/nvd-sync.js';

const dirs: string[] = [];
function tmpDir(): string {
  const d = join(tmpdir(), `nvd-sync-test-${randomBytes(6).toString('hex')}`);
  mkdirSync(d, { recursive: true });
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function cveWith(
  id: string,
  cpeMatch: Array<Record<string, unknown>>,
  extra: Partial<NvdCveInput> = {},
): NvdCveInput {
  return { id, configurations: [{ nodes: [{ cpeMatch }] }], ...extra } as NvdCveInput;
}

describe('cpeRowsFromCve', () => {
  it('carries a version range (start incl + end excl)', () => {
    const rows = cpeRowsFromCve(cveWith('CVE-2020-0001', [{
      vulnerable: true,
      criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
      versionStartIncluding: '2.4.0',
      versionEndExcluding: '2.4.50',
    }]));
    expect(rows).toEqual([{
      cve_id: 'CVE-2020-0001', vendor: 'apache', product: 'http_server', version: '*', update_: '*',
      start_incl: '2.4.0', start_excl: null, end_incl: null, end_excl: '2.4.50',
    }]);
  });

  it('keeps an exact vulnerable CPE version', () => {
    const rows = cpeRowsFromCve(cveWith('CVE-2020-0002', [{
      vulnerable: true,
      criteria: 'cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*',
    }]));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      vendor: 'openssl', product: 'openssl', version: '1.0.2k', update_: '*',
      start_incl: null, end_excl: null,
    });
  });

  it('parses the update field and escaped colons', () => {
    const rows = cpeRowsFromCve(cveWith('CVE-2020-0003', [{
      vulnerable: true,
      criteria: 'cpe:2.3:a:vendor:prod\\:x:1.2:beta1:*:*:*:*:*:*',
    }]));
    expect(rows[0]).toMatchObject({ product: 'prod:x', version: '1.2', update_: 'beta1' });
  });

  it('drops vulnerable:false entries', () => {
    expect(cpeRowsFromCve(cveWith('CVE-2020-0004', [{
      vulnerable: false,
      criteria: 'cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*',
    }]))).toEqual([]);
  });

  it('drops o: and h: CPEs', () => {
    expect(cpeRowsFromCve(cveWith('CVE-2020-0005', [
      { vulnerable: true, criteria: 'cpe:2.3:o:linux:linux_kernel:4.4:*:*:*:*:*:*:*' },
      { vulnerable: true, criteria: 'cpe:2.3:h:cisco:router:1.0:*:*:*:*:*:*:*' },
    ]))).toEqual([]);
  });

  it('drops unbounded * and - versions but keeps bounded ones', () => {
    const rows = cpeRowsFromCve(cveWith('CVE-2020-0006', [
      { vulnerable: true, criteria: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*' },
      { vulnerable: true, criteria: 'cpe:2.3:a:acme:widget:-:*:*:*:*:*:*:*' },
      { vulnerable: true, criteria: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*', versionEndIncluding: '3.1' },
    ]));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ end_incl: '3.1' });
  });

  it('skips a Rejected CVE', () => {
    const cve = cveWith('CVE-2020-0007', [
      { vulnerable: true, criteria: 'cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*' },
    ], { vulnStatus: 'Rejected' });
    expect(isRejected(cve)).toBe(true);
    expect(cpeRowsFromCve(cve)).toEqual([]);
  });

  it('tolerates a CVE with no configurations', () => {
    expect(cpeRowsFromCve({ id: 'CVE-2020-0008' })).toEqual([]);
  });
});

describe('cveMetaFromCve', () => {
  const m = (v: number) => [{ cvssData: { baseScore: v } }];
  it('prefers v3.1 over v3.0 over v2', () => {
    const base = { id: 'CVE-2020-1', published: 'p', lastModified: 'l' };
    expect(cveMetaFromCve({
      ...base, metrics: { cvssMetricV31: m(9.8), cvssMetricV30: m(7.5), cvssMetricV2: m(5) },
    })).toEqual({ cvss: 9.8, cvss_version: '3.1', published: 'p', last_modified: 'l' });
    expect(cveMetaFromCve({
      ...base, metrics: { cvssMetricV30: m(7.5), cvssMetricV2: m(5) },
    })).toMatchObject({ cvss: 7.5, cvss_version: '3.0' });
    expect(cveMetaFromCve({
      ...base, metrics: { cvssMetricV2: m(5) },
    })).toMatchObject({ cvss: 5, cvss_version: '2.0' });
  });
  it('gives null cvss when there are no metrics', () => {
    expect(cveMetaFromCve({ id: 'CVE-2020-2' })).toMatchObject({ cvss: null, cvss_version: null });
  });
});

describe('writer -> reader round trip', () => {
  it('returns the matches and meta that were written', () => {
    const p = join(tmpDir(), 'nvd.db');
    const w = new NvdWriter(p);
    w.upsertCve(cveWith('CVE-2020-0001', [{
      vulnerable: true, criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
      versionStartIncluding: '2.4.0', versionEndExcluding: '2.4.50',
    }], { published: '2020-01-01T00:00:00.000', lastModified: '2020-02-01T00:00:00.000',
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }] } }));
    w.upsertCve(cveWith('CVE-2020-0002', [{
      vulnerable: true, criteria: 'cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*',
    }], { metrics: { cvssMetricV2: [{ cvssData: { baseScore: 5 } }] } }));
    w.setMeta('snapshot_at', '2026-11-03T00:00:00.000Z');
    w.setMeta('sync_cursor', '2026-11-03T00:00:00.000Z');
    w.commit();

    const lk = openNvdLookup(p);
    expect(lk).not.toBeNull();
    expect(lk!.snapshotAt).toBe('2026-11-03T00:00:00.000Z');
    const ap = lk!.cpeMatches('apache', 'http_server');
    expect(ap).toHaveLength(1);
    expect(ap[0]).toMatchObject({ cve_id: 'CVE-2020-0001', start_incl: '2.4.0', end_excl: '2.4.50' });
    expect(lk!.cpeMatches('openssl', 'openssl')[0]).toMatchObject({ version: '1.0.2k' });
    expect(lk!.cpeMatches('nope', 'nope')).toEqual([]);
    const meta = lk!.cveMeta(['CVE-2020-0001', 'CVE-2020-0002', 'CVE-9999-0000']);
    expect(meta.get('CVE-2020-0001')).toMatchObject({ cvss: 9.8, cvss_version: '3.1', published: '2020-01-01T00:00:00.000' });
    expect(meta.get('CVE-2020-0002')).toMatchObject({ cvss: 5, cvss_version: '2.0' });
    expect(meta.has('CVE-9999-0000')).toBe(false);
  });

  it('replaces the matches of a re-upserted CVE and drops a rejected one', () => {
    const p = join(tmpDir(), 'nvd.db');
    const w = new NvdWriter(p);
    const old = cveWith('CVE-2020-0001', [{ vulnerable: true, criteria: 'cpe:2.3:a:a:b:1.0:*:*:*:*:*:*:*' }]);
    w.upsertCve(old);
    w.upsertCve(cveWith('CVE-2020-0001', [{ vulnerable: true, criteria: 'cpe:2.3:a:a:b:2.0:*:*:*:*:*:*:*' }]));
    w.upsertCve(cveWith('CVE-2020-0002', [{ vulnerable: true, criteria: 'cpe:2.3:a:a:b:3.0:*:*:*:*:*:*:*' }]));
    w.upsertCve(cveWith('CVE-2020-0002', [], { vulnStatus: 'Rejected' }));
    w.commit();
    const lk = openNvdLookup(p)!;
    expect(lk.cpeMatches('a', 'b').map((r) => r.version)).toEqual(['2.0']);
    expect(lk.cveMeta(['CVE-2020-0002']).size).toBe(0);
  });
});

describe('openNvdLookup', () => {
  it('returns null for a missing file', () => {
    expect(openNvdLookup(join(tmpDir(), 'absent.db'))).toBeNull();
  });
  it('returns null for an unreadable (non-sqlite) file', () => {
    const p = join(tmpDir(), 'junk.db');
    writeFileSync(p, 'not a database');
    expect(openNvdLookup(p)).toBeNull();
  });
  it('returns null on a schema_version mismatch', () => {
    const p = join(tmpDir(), 'nvd.db');
    const w = new NvdWriter(p);
    w.setMeta('schema_version', String(NVD_SCHEMA_VERSION + 1));
    w.commit();
    expect(openNvdLookup(p)).toBeNull();
  });
});

describe('replaceAtomically', () => {
  it('swaps in the built file on success', async () => {
    const final = join(tmpDir(), 'nvd.db');
    writeFileSync(final, 'old');
    await replaceAtomically(final, (tmp) => { writeFileSync(tmp, 'new'); });
    expect(readFileSync(final, 'utf8')).toBe('new');
    expect(existsSync(`${final}.tmp`)).toBe(false);
  });
  it('leaves the original intact when the build throws', async () => {
    const final = join(tmpDir(), 'nvd.db');
    writeFileSync(final, 'old');
    await expect(replaceAtomically(final, (tmp) => {
      writeFileSync(tmp, 'partial');
      throw new Error('boom');
    })).rejects.toThrow('boom');
    expect(readFileSync(final, 'utf8')).toBe('old');
    expect(existsSync(`${final}.tmp`)).toBe(false);
  });
});

describe('fetchWithRetry', () => {
  const resp = (status: number, body: unknown = {}): Response =>
    new Response(JSON.stringify(body), { status });
  it('retries on 429 and 503 then succeeds', async () => {
    const seq = [resp(429), resp(503), resp(200, { totalResults: 0 })];
    const sleeps: number[] = [];
    const out = await fetchWithRetry('http://x', {}, {
      fetchFn: async () => seq.shift()!,
      sleep: async (ms) => { sleeps.push(ms); },
    });
    expect(out).toEqual({ totalResults: 0 });
    expect(sleeps).toHaveLength(2);
    expect(sleeps[1]!).toBeGreaterThan(sleeps[0]!);
  });
  it('throws on a non-retryable status', async () => {
    await expect(fetchWithRetry('http://x', {}, {
      fetchFn: async () => resp(404), sleep: async () => {},
    })).rejects.toThrow('HTTP 404');
  });
  it('gives up after maxAttempts', async () => {
    await expect(fetchWithRetry('http://x', {}, {
      fetchFn: async () => resp(503), sleep: async () => {}, maxAttempts: 3,
    })).rejects.toThrow('HTTP 503');
  });
});
