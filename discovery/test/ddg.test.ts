import { describe, it, expect } from 'vitest';
import { decodeDdgUrl, hostOf, makeDomainFilter } from '../src/lib/ddg.js';

describe('decodeDdgUrl', () => {
  it('unwraps DDG /l/?uddg= redirect wrappers', () => {
    const wrapped =
      'https://duckduckgo.com/l/?uddg=' +
      encodeURIComponent('https://njt.jog.gov.hu/translations') +
      '&rut=abc';
    expect(decodeDdgUrl(wrapped)).toBe('https://njt.jog.gov.hu/translations');
  });

  it('passes through non-wrapped URLs', () => {
    expect(decodeDdgUrl('https://example.com/foo')).toBe('https://example.com/foo');
  });

  it('handles relative wrapped URLs', () => {
    const wrapped = '/l/?uddg=' + encodeURIComponent('https://example.com/x');
    expect(decodeDdgUrl(wrapped)).toBe('https://example.com/x');
  });

  it('returns input on garbage URL', () => {
    expect(decodeDdgUrl('not a url')).toBe('not a url');
  });

  it('leaves /l/ without uddg param alone', () => {
    expect(decodeDdgUrl('https://duckduckgo.com/l/?other=1')).toBe(
      'https://duckduckgo.com/l/?other=1'
    );
  });
});

describe('hostOf', () => {
  it('extracts hostname', () => {
    expect(hostOf('https://foo.example.com:8080/bar?x=1')).toBe('foo.example.com');
  });

  it('returns null for garbage', () => {
    expect(hostOf('not a url')).toBeNull();
  });

  it('handles IPv6', () => {
    expect(hostOf('https://[2001:db8::1]/foo')).toBe('[2001:db8::1]');
  });
});

describe('makeDomainFilter', () => {
  it('keeps hosts under the suffix, strips leading www.', () => {
    const keep = makeDomainFilter('gov.hu', []);
    expect(keep('www.example.gov.hu')).toBe('example.gov.hu');
    expect(keep('foo.gov.hu')).toBe('foo.gov.hu');
    expect(keep('gov.hu')).toBe('gov.hu');
  });

  it('rejects hosts outside the suffix', () => {
    const keep = makeDomainFilter('gov.hu', []);
    expect(keep('example.com')).toBeNull();
    expect(keep('gov.huawei.com')).toBeNull(); // must be a proper suffix boundary
  });

  it('excludes named apex + subdomains', () => {
    const keep = makeDomainFilter('gov.hu', ['nki.gov.hu', 'nbsz.gov.hu']);
    expect(keep('nki.gov.hu')).toBeNull();
    expect(keep('sub.nki.gov.hu')).toBeNull();
    expect(keep('nbsz.gov.hu')).toBeNull();
    expect(keep('other.gov.hu')).toBe('other.gov.hu');
  });

  it('lowercases the host', () => {
    const keep = makeDomainFilter('gov.hu', []);
    expect(keep('Example.Gov.HU')).toBe('example.gov.hu');
  });

  it('returns null for empty/undefined input', () => {
    const keep = makeDomainFilter('gov.hu', []);
    expect(keep(null)).toBeNull();
    expect(keep('')).toBeNull();
  });

  it('with no suffix, accepts any host', () => {
    const keep = makeDomainFilter(null, []);
    expect(keep('anything.example.io')).toBe('anything.example.io');
  });
});
