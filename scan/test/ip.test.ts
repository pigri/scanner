import { describe, it, expect } from 'vitest';
import { normalizeIp, classifyIp } from '../src/lib/ip.js';

describe('normalizeIp', () => {
  it('accepts IPv4 and trims', () => {
    expect(normalizeIp(' 192.0.2.1 ')).toEqual({ ip: '192.0.2.1', version: 4 });
  });

  it('returns null for invalid input', () => {
    for (const s of ['', '   ', 'example.com', '999.1.1.1', '192.0.2.01', '192.0.2.1/24', '192.0.2.1:80', '1.2.3', '[::1', '::1]x', '2001:db8::zz']) {
      expect(normalizeIp(s), JSON.stringify(s)).toBeNull();
    }
  });

  it('canonicalises IPv6 to lower-case compressed form', () => {
    expect(normalizeIp('2001:DB8:0:0:0:0:0:1')).toEqual({ ip: '2001:db8::1', version: 6 });
    expect(normalizeIp('2001:db8:0:0:1:0:0:1')).toEqual({ ip: '2001:db8::1:0:0:1', version: 6 });
    expect(normalizeIp('0:0:0:0:0:0:0:0')).toEqual({ ip: '::', version: 6 });
  });

  it('strips brackets and a zone id', () => {
    expect(normalizeIp('[2001:db8::1]')).toEqual({ ip: '2001:db8::1', version: 6 });
    expect(normalizeIp('fe80::1%eth0')).toEqual({ ip: 'fe80::1', version: 6 });
  });

  it('turns an IPv4-mapped IPv6 address into IPv4', () => {
    expect(normalizeIp('::ffff:192.0.2.1')).toEqual({ ip: '192.0.2.1', version: 4 });
    expect(normalizeIp('::FFFF:c000:201')).toEqual({ ip: '192.0.2.1', version: 4 });
  });

  it('keeps other IPv6 addresses that embed IPv4', () => {
    expect(normalizeIp('64:ff9b::192.0.2.1')).toEqual({ ip: '64:ff9b::c000:201', version: 6 });
  });
});

describe('classifyIp', () => {
  const cases: Array<[string, string]> = [
    ['10.0.0.1', 'private'],
    ['172.15.255.255', 'public'],
    ['172.16.0.0', 'private'],
    ['172.31.255.255', 'private'],
    ['172.32.0.0', 'public'],
    ['192.168.1.1', 'private'],
    ['192.167.255.255', 'public'],
    ['100.63.255.255', 'public'],
    ['100.64.0.0', 'cgnat'],
    ['100.127.255.255', 'cgnat'],
    ['100.128.0.0', 'public'],
    ['127.0.0.1', 'loopback'],
    ['169.254.1.1', 'link-local'],
    ['0.0.0.0', 'unspecified'],
    ['0.1.2.3', 'unspecified'],
    ['224.0.0.1', 'multicast'],
    ['239.255.255.255', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['255.255.255.255', 'reserved'],
    ['192.0.2.1', 'public'],
    ['198.51.100.7', 'public'],
    ['8.8.8.8', 'public'],
    ['::', 'unspecified'],
    ['::1', 'loopback'],
    ['fc00::1', 'private'],
    ['fdff::1', 'private'],
    ['fe00::1', 'public'],
    ['fe80::1', 'link-local'],
    ['febf::1', 'link-local'],
    ['fec0::1', 'public'],
    ['ff02::1', 'multicast'],
    ['2001:db8::1', 'public'],
    ['2606:4700::1', 'public'],
  ];
  for (const [ip, cls] of cases) {
    it(`${ip} is ${cls}`, () => {
      expect(classifyIp(ip)).toBe(cls);
    });
  }
});
