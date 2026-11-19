import { describe, it, expect } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { liveSeeds, originOf, targetsOutsideSeedOrigin } from '../src/lib/live-seed.js';

const AT = '2026-11-18T10:00:00.000Z';
const URLS = ['http://a.example', 'https://a.example:8443/app', 'https://a.example/', 'http://a.example:8080'];

function withProbes(urls: readonly string[]): Db {
  const db = openDb(':memory:');
  for (const url of urls) {
    db.insertHttpProbe({ target: 'a.example', url, status_code: 200 }, AT, null);
  }
  return db;
}

describe('liveSeeds', () => {
  it('picks the same seed whichever order the probes were inserted in', () => {
    const fwd = liveSeeds(withProbes(URLS), ['a.example']);
    const rev = liveSeeds(withProbes([...URLS].reverse()), ['a.example']);
    expect(fwd).toEqual(rev);
    expect(fwd).toEqual([{ target: 'a.example', url: 'https://a.example/' }]);
  });

  it('prefers https, then the default port, over a lower url', () => {
    expect(liveSeeds(withProbes(['http://a.example', 'https://a.example:8443']), ['a.example'])[0]!.url).toBe('https://a.example:8443');
    expect(liveSeeds(withProbes(['https://a.example:444', 'https://a.example']), ['a.example'])[0]!.url).toBe('https://a.example');
  });

  it('falls back to http when that is all there is', () => {
    expect(liveSeeds(withProbes(['http://a.example:8080', 'http://a.example']), ['a.example'])[0]!.url).toBe('http://a.example');
  });

  it('returns nothing for no targets', () => {
    expect(liveSeeds(withProbes(URLS), [])).toEqual([]);
  });
});

describe('originOf', () => {
  it('keeps the scheme and a non-default port, drops path and default port', () => {
    expect(originOf('https://A.example:443/x?y=1')).toBe('https://a.example');
    expect(originOf('http://a.example:80')).toBe('http://a.example');
    expect(originOf('https://a.example:8443/app')).toBe('https://a.example:8443');
    expect(originOf('not a url')).toBe('');
    expect(originOf(null)).toBe('');
  });
});

describe('targetsOutsideSeedOrigin', () => {
  const seeds = [{ target: 'a.example', url: 'https://a.example' }];
  const put = (db: Db, tool: string, matched: string | null, at = AT) =>
    db.insertFinding({ tool, target: 'a.example', category: 'c', severity: 'low', title: matched ?? 'null', matched_at: matched, meta: {} }, at, null);

  it('is empty when every open finding came from the seed origin', () => {
    const db = openDb(':memory:');
    put(db, 'ffuf', 'https://a.example/admin/');
    expect([...targetsOutsideSeedOrigin(db, 'ffuf', seeds)!]).toEqual([]);
  });

  it('names a target with an open finding from another origin', () => {
    const db = openDb(':memory:');
    put(db, 'ffuf', 'https://a.example/admin/');
    put(db, 'ffuf', 'http://a.example:8080/admin/');
    expect([...targetsOutsideSeedOrigin(db, 'ffuf', seeds)!]).toEqual(['a.example']);
  });

  it('counts a finding with no matched_at as outside', () => {
    const db = openDb(':memory:');
    put(db, 'ffuf', null);
    expect([...targetsOutsideSeedOrigin(db, 'ffuf', seeds)!]).toEqual(['a.example']);
  });

  it('ignores findings of another tool and findings already closed', () => {
    const db = openDb(':memory:');
    put(db, 'headers', 'http://a.example:8080/');
    put(db, 'ffuf', 'http://a.example:8080/old', '2026-11-01T00:00:00.000Z');
    db.recordCoverage('ffuf', ['a.example'], AT, null);
    put(db, 'ffuf', 'https://a.example/new');
    expect([...targetsOutsideSeedOrigin(db, 'ffuf', seeds)!]).toEqual([]);
  });

  it('returns null when the findings cannot be read', () => {
    const db = openDb(':memory:');
    db.raw.exec('DROP TABLE findings');
    expect(targetsOutsideSeedOrigin(db, 'ffuf', seeds)).toBeNull();
  });
});
