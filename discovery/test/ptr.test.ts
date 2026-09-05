import { describe, it, expect } from 'vitest';
import { expandCidr, cidrSize, extractHostsFromResults } from '../src/lib/ptr.js';

describe('cidrSize', () => {
  it('counts IPv4 addresses in a CIDR', () => {
    expect(cidrSize('10.0.0.0/24')).toBe(256);
    expect(cidrSize('10.0.0.0/16')).toBe(65536);
    expect(cidrSize('10.0.0.0/32')).toBe(1);
    expect(cidrSize('10.0.0.0/30')).toBe(4);
  });
  it('returns 0 for garbage', () => {
    expect(cidrSize('nope')).toBe(0);
    expect(cidrSize('10.0.0.0/99')).toBe(0);
  });
});

describe('expandCidr', () => {
  it('expands a /30 (4 addresses)', () => {
    expect(Array.from(expandCidr('10.0.0.0/30'))).toEqual([
      '10.0.0.0', '10.0.0.1', '10.0.0.2', '10.0.0.3',
    ]);
  });

  it('expands a /24 aligned to the network', () => {
    const ips = Array.from(expandCidr('192.168.1.0/24'));
    expect(ips.length).toBe(256);
    expect(ips[0]).toBe('192.168.1.0');
    expect(ips[255]).toBe('192.168.1.255');
  });

  it('normalizes unaligned network address', () => {
    // 10.0.0.5/24 should be treated as 10.0.0.0/24
    const ips = Array.from(expandCidr('10.0.0.5/24'));
    expect(ips[0]).toBe('10.0.0.0');
  });

  it('yields a single IP for /32', () => {
    expect(Array.from(expandCidr('1.2.3.4/32'))).toEqual(['1.2.3.4']);
  });

  it('skips IPv6 CIDRs (returns empty)', () => {
    expect(Array.from(expandCidr('2001:738::/32'))).toEqual([]);
  });
});

describe('extractHostsFromResults', () => {
  it('extracts unique FQDNs matching suffix', () => {
    const results = [
      { ip: '1.1.1.1', ptr: 'one.example.com' },
      { ip: '1.1.1.2', ptr: 'two.example.com' },
      { ip: '1.1.1.3', ptr: 'one.example.com' }, // dup
      { ip: '1.1.1.4', ptr: 'other.tld' },
      { ip: '1.1.1.5', ptr: null },
    ];
    expect(extractHostsFromResults(results, 'example.com').sort()).toEqual([
      'one.example.com',
      'two.example.com',
    ]);
  });

  it('lowercases and strips trailing dot', () => {
    const results = [{ ip: '1.1.1.1', ptr: 'FOO.example.com.' }];
    expect(extractHostsFromResults(results, 'example.com')).toEqual(['foo.example.com']);
  });

  it('rejects near-match suffixes', () => {
    const results = [
      { ip: '1.1.1.1', ptr: 'foo.example.com' },
      { ip: '1.1.1.2', ptr: 'evil-example.com' },
      { ip: '1.1.1.3', ptr: 'foo.lexample.com' },
    ];
    expect(extractHostsFromResults(results, 'example.com')).toEqual(['foo.example.com']);
  });

  it('handles no suffix (returns all non-null)', () => {
    const results = [
      { ip: '1.1.1.1', ptr: 'foo.a' },
      { ip: '1.1.1.2', ptr: 'bar.b' },
      { ip: '1.1.1.3', ptr: null },
    ];
    expect(extractHostsFromResults(results, null).sort()).toEqual(['bar.b', 'foo.a']);
  });
});
