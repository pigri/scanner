import { describe, it, expect } from 'vitest';
import { parseRunIds, parseExpect } from '../src/prune-runs.js';

describe('parseRunIds', () => {
  it('parses a comma-separated list', () => {
    expect(parseRunIds('21,22')).toEqual([21, 22]);
  });
  it('accepts whitespace separators and dedupes + sorts', () => {
    expect(parseRunIds('22 21  21,3')).toEqual([3, 21, 22]);
  });
  it('rejects non-positive / non-integer ids', () => {
    expect(() => parseRunIds('21,abc')).toThrow(/invalid run id/);
    expect(() => parseRunIds('0')).toThrow(/invalid run id/);
    expect(() => parseRunIds('-5')).toThrow(/invalid run id/);
  });
});

describe('parseExpect', () => {
  it('maps id:tool pairs', () => {
    const m = parseExpect(['21:synthesize-eol', '22:risk']);
    expect(m.get(21)).toBe('synthesize-eol');
    expect(m.get(22)).toBe('risk');
  });
  it('rejects malformed pairs', () => {
    expect(() => parseExpect(['21'])).toThrow(/invalid --expect/);
    expect(() => parseExpect(['x:risk'])).toThrow(/invalid --expect/);
  });
});
