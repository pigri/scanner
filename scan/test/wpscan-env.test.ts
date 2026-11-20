import { describe, it, expect } from 'vitest';
import { wpscanEnv } from '../src/lib/wpscan-env.js';

describe('wpscanEnv', () => {
  it('drops an empty or blank token', () => {
    for (const v of ['', '   ']) {
      const out = wpscanEnv({ PATH: '/bin', WPSCAN_API_TOKEN: v });
      expect('WPSCAN_API_TOKEN' in out).toBe(false);
      expect(out['PATH']).toBe('/bin');
    }
  });

  it('keeps a real token', () => {
    expect(wpscanEnv({ WPSCAN_API_TOKEN: 'tok123' })['WPSCAN_API_TOKEN']).toBe('tok123');
  });

  it('leaves an unset token unset', () => {
    expect('WPSCAN_API_TOKEN' in wpscanEnv({ PATH: '/bin' })).toBe(false);
  });

  it('does not change its input', () => {
    const env = { WPSCAN_API_TOKEN: '' };
    wpscanEnv(env);
    expect(env).toEqual({ WPSCAN_API_TOKEN: '' });
  });
});
