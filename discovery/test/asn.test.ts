import { describe, it, expect } from 'vitest';
import {
  extractPrefixes,
  dedupePrefixes,
  familyOf,
  normalizeAsn,
} from '../src/lib/asn.js';

describe('normalizeAsn', () => {
  it('accepts numeric strings', () => {
    expect(normalizeAsn('31581')).toBe('AS31581');
  });
  it('preserves AS prefix', () => {
    expect(normalizeAsn('AS31581')).toBe('AS31581');
  });
  it('accepts lowercase', () => {
    expect(normalizeAsn('as1955')).toBe('AS1955');
  });
  it('trims whitespace', () => {
    expect(normalizeAsn('  AS1955  ')).toBe('AS1955');
  });
  it('rejects non-numeric', () => {
    expect(() => normalizeAsn('ASxyz')).toThrow();
    expect(() => normalizeAsn('')).toThrow();
  });
});

describe('extractPrefixes', () => {
  it('pulls prefix strings out of the RIPE Stat announced-prefixes response', () => {
    const response = {
      data: {
        prefixes: [
          { prefix: '84.206.32.0/19', timelines: [] },
          { prefix: '193.6.10.0/24', timelines: [] },
          { prefix: '2001:738::/32', timelines: [] },
        ],
      },
    };
    expect(extractPrefixes(response)).toEqual([
      '84.206.32.0/19',
      '193.6.10.0/24',
      '2001:738::/32',
    ]);
  });

  it('returns [] for empty data', () => {
    expect(extractPrefixes({ data: { prefixes: [] } })).toEqual([]);
  });

  it('returns [] for malformed input', () => {
    expect(extractPrefixes({})).toEqual([]);
    expect(extractPrefixes(null)).toEqual([]);
    expect(extractPrefixes(undefined)).toEqual([]);
    expect(extractPrefixes('nope')).toEqual([]);
  });

  it('skips entries without a prefix field', () => {
    const response = {
      data: {
        prefixes: [
          { prefix: '1.2.3.0/24' },
          { timelines: [] },
          { prefix: null },
          { prefix: '5.6.7.0/24' },
        ],
      },
    };
    expect(extractPrefixes(response)).toEqual(['1.2.3.0/24', '5.6.7.0/24']);
  });
});

describe('familyOf', () => {
  it('classifies IPv4 CIDRs', () => {
    expect(familyOf('84.206.32.0/19')).toBe(4);
    expect(familyOf('0.0.0.0/0')).toBe(4);
  });
  it('classifies IPv6 CIDRs', () => {
    expect(familyOf('2001:738::/32')).toBe(6);
    expect(familyOf('::/0')).toBe(6);
  });
  it('returns null for garbage', () => {
    expect(familyOf('nope')).toBeNull();
  });
});

describe('dedupePrefixes', () => {
  it('removes duplicates while preserving first-seen order', () => {
    expect(dedupePrefixes(['1.2.3.0/24', '1.2.3.0/24', '5.6.0.0/16'])).toEqual([
      '1.2.3.0/24',
      '5.6.0.0/16',
    ]);
  });

  it('sorts within family when sort=true', () => {
    const input = [
      '10.0.0.0/8',
      '2001:738::/32',
      '1.2.3.0/24',
      '2606:4700::/32',
    ];
    expect(dedupePrefixes(input, { sort: true })).toEqual([
      '1.2.3.0/24',
      '10.0.0.0/8',
      '2001:738::/32',
      '2606:4700::/32',
    ]);
  });
});
