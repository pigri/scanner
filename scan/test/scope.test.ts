import { describe, it, expect } from 'vitest';
import { parseScope, inScope, checkTargets } from '../src/lib/scope.js';

describe('parseScope', () => {
  it('reads suffix and CIDR entries from lines', () => {
    const scope = parseScope(`
      # comment
      .gov.hu
      example.com
      84.206.0.0/16
      2001:738::/32
    `);
    expect(scope.suffixes).toEqual(['gov.hu', 'example.com']);
    expect(scope.cidrs.map((c) => c.raw)).toEqual(['84.206.0.0/16', '2001:738::/32']);
  });

  it('ignores blank lines and # comments', () => {
    const scope = parseScope('# nope\n\n\n.gov.hu\n# also\n');
    expect(scope.suffixes).toEqual(['gov.hu']);
    expect(scope.cidrs).toEqual([]);
  });

  it('lowercases suffixes', () => {
    expect(parseScope('.Gov.HU').suffixes).toEqual(['gov.hu']);
  });
});

describe('inScope (hostname)', () => {
  const scope = parseScope('.gov.hu\nexample.com\n');
  it('accepts exact suffix match', () => {
    expect(inScope('foo.gov.hu', scope)).toBe(true);
  });
  it('accepts nested subdomain', () => {
    expect(inScope('a.b.c.gov.hu', scope)).toBe(true);
  });
  it('accepts the bare suffix', () => {
    expect(inScope('gov.hu', scope)).toBe(true);
  });
  it('rejects hosts not under the suffix', () => {
    expect(inScope('gov.huawei.com', scope)).toBe(false);
    expect(inScope('other.com', scope)).toBe(false);
  });
  it('case insensitive', () => {
    expect(inScope('EXAMPLE.COM', scope)).toBe(true);
  });
});

describe('inScope (IPv4)', () => {
  const scope = parseScope('84.206.0.0/16\n');
  it('accepts IPs inside the /16', () => {
    expect(inScope('84.206.128.147', scope)).toBe(true);
    expect(inScope('84.206.0.1', scope)).toBe(true);
  });
  it('rejects IPs outside', () => {
    expect(inScope('84.207.0.1', scope)).toBe(false);
    expect(inScope('1.2.3.4', scope)).toBe(false);
  });
});

describe('inScope (empty scope = allow all)', () => {
  it('treats empty scope as no restriction', () => {
    const scope = parseScope('');
    expect(inScope('anything.example.io', scope)).toBe(true);
    expect(inScope('1.2.3.4', scope)).toBe(true);
  });
});

describe('checkTargets', () => {
  const scope = parseScope('.gov.hu\n84.206.0.0/16\n');
  it('splits targets into inScope and outOfScope', () => {
    const r = checkTargets(['foo.gov.hu', '84.206.1.1', 'evil.com', '1.2.3.4'], scope);
    expect(r.inScope.sort()).toEqual(['84.206.1.1', 'foo.gov.hu']);
    expect(r.outOfScope.sort()).toEqual(['1.2.3.4', 'evil.com']);
  });
});
