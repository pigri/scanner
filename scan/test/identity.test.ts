import { describe, it, expect } from 'vitest';
import { isIpAddress, buildTargetResolver, type TargetIpPair } from '../src/lib/identity.js';

describe('isIpAddress', () => {
  it('accepts valid IPv4', () => {
    for (const s of ['84.206.102.29', '127.0.0.1', '0.0.0.0', '255.255.255.255']) {
      expect(isIpAddress(s)).toBe(true);
    }
  });
  it('rejects out-of-range IPv4', () => {
    expect(isIpAddress('256.0.0.1')).toBe(false);
    expect(isIpAddress('1.2.3')).toBe(false);
  });
  it('accepts IPv6, rejects hostnames', () => {
    expect(isIpAddress('2001:db8::1')).toBe(true);
    expect(isIpAddress('adatgyujtotest.nemzetidohany.gov.hu')).toBe(false);
    expect(isIpAddress('a.gov.hu')).toBe(false);
  });
});

describe('buildTargetResolver', () => {
  const pairs = (arr: [string, string | null][]): TargetIpPair[] =>
    arr.map(([target, ip]) => ({ target, ip }));

  it('folds a single-hostname IP onto that hostname (prefer-hostname)', () => {
    const resolve = buildTargetResolver(pairs([['host.gov.hu', '84.206.102.29']]));
    expect(resolve('84.206.102.29')).toBe('host.gov.hu');
    expect(resolve('host.gov.hu')).toBe('host.gov.hu');
  });

  it('folds the PTR pseudo-name all the way to the hostname', () => {
    const resolve = buildTargetResolver(pairs([['host.gov.hu', '84.206.102.29']]));
    // 29.102.206.84.in-addr.arpa -> 84.206.102.29 -> host.gov.hu
    expect(resolve('29.102.206.84.in-addr.arpa')).toBe('host.gov.hu');
  });

  it('does NOT fold when multiple vhosts share the IP (ambiguous)', () => {
    const resolve = buildTargetResolver(pairs([
      ['a.gov.hu', '84.206.102.29'],
      ['b.gov.hu', '84.206.102.29'],
    ]));
    expect(resolve('84.206.102.29')).toBe('84.206.102.29'); // stays as the IP
    expect(resolve('a.gov.hu')).toBe('a.gov.hu');
    expect(resolve('b.gov.hu')).toBe('b.gov.hu');
  });

  it('ignores port rows where target is itself an IP or a PTR name', () => {
    const resolve = buildTargetResolver(pairs([
      ['84.206.102.29', '84.206.102.29'],          // IP==IP, no hostname learned
      ['29.102.206.84.in-addr.arpa', '84.206.102.29'], // PTR, not a real host
    ]));
    // nothing to fold onto -> IP stays an IP
    expect(resolve('84.206.102.29')).toBe('84.206.102.29');
  });

  it('leaves unknown IPs and hostnames untouched', () => {
    const resolve = buildTargetResolver(pairs([['host.gov.hu', '10.0.0.1']]));
    expect(resolve('203.0.113.5')).toBe('203.0.113.5'); // no mapping
    expect(resolve('other.gov.hu')).toBe('other.gov.hu');
  });

  it('skips pairs with null/invalid ip', () => {
    const resolve = buildTargetResolver(pairs([
      ['host.gov.hu', null],
      ['host2.gov.hu', 'not-an-ip'],
    ]));
    expect(resolve('host.gov.hu')).toBe('host.gov.hu');
  });
});
