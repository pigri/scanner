import { describe, it, expect, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { openGeo, toGeoRow, wrapReader, DEFAULT_MMDB, MMDB_STALE_DAYS } from '../src/lib/geoip.js';

const dirs: string[] = [];
function tmpDir(): string {
  const d = join(tmpdir(), `geoip-test-${randomBytes(6).toString('hex')}`);
  mkdirSync(d, { recursive: true });
  dirs.push(d);
  return d;
}
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

describe('constants', () => {
  it('has the documented defaults', () => {
    expect(DEFAULT_MMDB).toBe('../discovery/ipinfo_lite.mmdb');
    expect(MMDB_STALE_DAYS).toBe(7);
  });
});

describe('openGeo', () => {
  it('returns null for a missing file', async () => {
    expect(await openGeo(join(tmpDir(), 'missing.mmdb'))).toBeNull();
  });

  it('returns null for a file that is not an mmdb', async () => {
    const f = join(tmpDir(), 'garbage.mmdb');
    writeFileSync(f, 'this is not a database\n'.repeat(100));
    expect(await openGeo(f)).toBeNull();
  });

  it('returns null for an empty file', async () => {
    const f = join(tmpDir(), 'empty.mmdb');
    writeFileSync(f, '');
    expect(await openGeo(f)).toBeNull();
  });
});

describe('toGeoRow', () => {
  it('keeps only the known string fields', () => {
    expect(toGeoRow({ asn: 'AS64496', as_name: 'Example Net', as_domain: 'example.net', country_code: 'XX', country: 'Exampleland', continent: 'EX' }))
      .toEqual({ asn: 'AS64496', as_name: 'Example Net', as_domain: 'example.net', country_code: 'XX', country: 'Exampleland' });
  });

  it('drops non-string fields', () => {
    expect(toGeoRow({ asn: 64496, as_name: { en: 'x' }, as_domain: ['a'], country_code: null, country: 'Exampleland' }))
      .toEqual({ country: 'Exampleland' });
  });

  it('trims and caps at 200 characters', () => {
    const row = toGeoRow({ as_name: `  ${'a'.repeat(300)}  `, asn: '  AS64496 ' });
    expect(row?.as_name).toBe('a'.repeat(200));
    expect(row?.asn).toBe('AS64496');
  });

  it('drops strings that are empty after trimming', () => {
    expect(toGeoRow({ asn: '   ', country: 'Exampleland' })).toEqual({ country: 'Exampleland' });
  });

  it('returns null when nothing usable is left, or for a non-object', () => {
    expect(toGeoRow({ asn: 1 })).toBeNull();
    expect(toGeoRow(null)).toBeNull();
    expect(toGeoRow('x')).toBeNull();
  });
});

describe('wrapReader', () => {
  const reader = {
    metadata: { buildEpoch: new Date('2026-11-01T00:00:00.000Z') },
    get(ip: string): unknown {
      if (ip === '192.0.2.1') return { asn: 'AS64496', country_code: 'XX' };
      if (ip === 'boom') throw new Error('bad ip');
      return null;
    },
  };

  it('maps records and misses, and never throws', () => {
    const g = wrapReader(reader);
    expect(g.get('192.0.2.1')).toEqual({ asn: 'AS64496', country_code: 'XX' });
    expect(g.get('198.51.100.1')).toBeNull();
    expect(g.get('boom')).toBeNull();
  });

  it('reports the build time as ISO text, or null when unusable', () => {
    expect(wrapReader(reader).buildAt).toBe('2026-11-01T00:00:00.000Z');
    expect(wrapReader({ ...reader, metadata: { buildEpoch: new Date(NaN) } }).buildAt).toBeNull();
    expect(wrapReader({ ...reader, metadata: {} as never }).buildAt).toBeNull();
  });
});
