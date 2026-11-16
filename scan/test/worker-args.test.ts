import { describe, it, expect } from 'vitest';
import { DEFAULT_MMDB } from '../src/lib/geoip.js';
import { parseArgs } from '../src/worker.js';

const base = ['node', 'worker.ts'];

describe('worker parseArgs mmdb', () => {
  it('uses GEOIP_MMDB as the default', () => {
    expect(parseArgs(base, { GEOIP_MMDB: '/data/geo/example.mmdb' }).mmdb).toBe('/data/geo/example.mmdb');
  });

  it('keeps the built-in default when GEOIP_MMDB is unset or empty', () => {
    expect(parseArgs(base, {}).mmdb).toBe(DEFAULT_MMDB);
    expect(parseArgs(base, { GEOIP_MMDB: '' }).mmdb).toBe(DEFAULT_MMDB);
  });

  it('lets --mmdb override GEOIP_MMDB', () => {
    const opts = parseArgs([...base, '--mmdb', '/data/geo/other.mmdb'], { GEOIP_MMDB: '/data/geo/example.mmdb' });
    expect(opts.mmdb).toBe('/data/geo/other.mmdb');
  });
});
