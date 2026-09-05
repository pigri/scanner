import { describe, it, expect } from 'vitest';
import { reverseDnsToIp, canonicalizeTarget } from '../src/lib/target-normalize.js';

describe('reverseDnsToIp', () => {
  it('reverses an IPv4 in-addr.arpa name to its IP', () => {
    expect(reverseDnsToIp('29.102.206.84.in-addr.arpa')).toBe('84.206.102.29');
    expect(reverseDnsToIp('1.0.0.127.in-addr.arpa')).toBe('127.0.0.1');
  });

  it('is case-insensitive and tolerates a trailing dot', () => {
    expect(reverseDnsToIp('29.102.206.84.IN-ADDR.ARPA.')).toBe('84.206.102.29');
  });

  it('rejects octets outside 0-255', () => {
    expect(reverseDnsToIp('999.0.0.0.in-addr.arpa')).toBeNull();
  });

  it('reverses an IPv6 ip6.arpa name to its full address', () => {
    // 2001:db8::1 fully-expanded, nibble-reversed
    const rev =
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa';
    expect(reverseDnsToIp(rev)).toBe('2001:0db8:0000:0000:0000:0000:0000:0001');
  });

  it('returns null for plain hostnames and IPs', () => {
    for (const s of [
      'adatgyujtotest.nemzetidohany.gov.hu',
      '84.206.102.29',
      'example.arpa',
      '',
    ]) {
      expect(reverseDnsToIp(s)).toBeNull();
    }
  });
});

describe('canonicalizeTarget', () => {
  it('collapses a PTR pseudo-name onto its IP', () => {
    expect(canonicalizeTarget('29.102.206.84.in-addr.arpa')).toBe('84.206.102.29');
  });

  it('leaves forward hostnames untouched (no hostname->IP merging)', () => {
    // distinct vhosts on a shared IP must remain distinct targets
    expect(canonicalizeTarget('a.gov.hu')).toBe('a.gov.hu');
    expect(canonicalizeTarget('b.gov.hu')).toBe('b.gov.hu');
  });

  it('leaves plain IPs untouched', () => {
    expect(canonicalizeTarget('84.206.102.29')).toBe('84.206.102.29');
  });

  it('is idempotent', () => {
    const once = canonicalizeTarget('29.102.206.84.in-addr.arpa');
    expect(canonicalizeTarget(once)).toBe(once);
  });
});
