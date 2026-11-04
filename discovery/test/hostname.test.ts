import { describe, it, expect } from 'vitest';
import { zoneOf, tokenize } from '../src/lib/hostname.js';

describe('zoneOf', () => {
  it('uses gov.hu as a multi-label suffix', () => {
    expect(zoneOf('a.b.okfo.gov.hu')).toBe('okfo.gov.hu');
    expect(zoneOf('efet.okfo.gov.hu')).toBe('okfo.gov.hu');
  });
  it('returns a bare registrable zone unchanged', () => {
    expect(zoneOf('okfo.gov.hu')).toBe('okfo.gov.hu');
    expect(zoneOf('example.com')).toBe('example.com');
  });
  it('falls back to the last two labels', () => {
    expect(zoneOf('x.example.com')).toBe('example.com');
    expect(zoneOf('a.b.mav.hu')).toBe('mav.hu');
  });
  it('lowercases and strips a trailing dot', () => {
    expect(zoneOf('WWW.Example.COM.')).toBe('example.com');
  });
  it('returns the input when it has too few labels', () => {
    expect(zoneOf('localhost')).toBe('localhost');
    expect(zoneOf('gov.hu')).toBe('gov.hu');
  });
});

describe('tokenize', () => {
  it('splits on hyphens and letter/digit boundaries', () => {
    expect(tokenize('efet-test2')).toEqual([
      { text: 'efet', kind: 'word' },
      { text: 'test', kind: 'word' },
      { text: '2', kind: 'num' },
    ]);
  });
  it('lowercases', () => {
    expect(tokenize('Web01')).toEqual([
      { text: 'web', kind: 'word' },
      { text: '01', kind: 'num' },
    ]);
  });
  it('splits digit-to-letter boundaries and drops empty tokens', () => {
    expect(tokenize('--ns1a--')).toEqual([
      { text: 'ns', kind: 'word' },
      { text: '1', kind: 'num' },
      { text: 'a', kind: 'word' },
    ]);
    expect(tokenize('')).toEqual([]);
  });
});
