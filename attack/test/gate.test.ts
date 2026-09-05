import { describe, it, expect } from 'vitest';
import {
  parseScope,
  inScope,
  classifyTargets,
  checkGate,
  type GateInput,
} from '../src/lib/gate.js';

describe('parseScope', () => {
  it('parses suffix + CIDR lines, skips blanks and comments', () => {
    const s = parseScope(`
      # header
      .gov.hu
      example.com
      10.0.0.0/8
      2001:db8::/32
      # trailing
    `);
    expect(s.suffixes).toEqual(['gov.hu', 'example.com']);
    expect(s.cidrs.map((c) => c.raw)).toEqual(['10.0.0.0/8', '2001:db8::/32']);
  });

  it('empty text → empty scope', () => {
    const s = parseScope('   ');
    expect(s.suffixes).toEqual([]);
    expect(s.cidrs).toEqual([]);
  });
});

describe('inScope', () => {
  const s = parseScope('.gov.hu\n10.20.0.0/16\n');
  it('accepts hostname under suffix', () => {
    expect(inScope('foo.gov.hu', s)).toBe(true);
    expect(inScope('gov.hu', s)).toBe(true);
    expect(inScope('a.b.c.gov.hu', s)).toBe(true);
  });
  it('rejects near-match suffixes', () => {
    expect(inScope('gov.huawei.com', s)).toBe(false);
    expect(inScope('example.com', s)).toBe(false);
  });
  it('accepts IPs inside CIDR', () => {
    expect(inScope('10.20.30.40', s)).toBe(true);
  });
  it('rejects IPs outside CIDR', () => {
    expect(inScope('10.21.0.1', s)).toBe(false);
    expect(inScope('1.2.3.4', s)).toBe(false);
  });
});

describe('classifyTargets', () => {
  const s = parseScope('.gov.hu\n10.20.0.0/16\n');
  it('splits into inScope + outOfScope', () => {
    const r = classifyTargets(['a.gov.hu', '1.2.3.4', 'b.gov.hu', '10.20.5.5'], s);
    expect(r.inScope.sort()).toEqual(['10.20.5.5', 'a.gov.hu', 'b.gov.hu']);
    expect(r.outOfScope).toEqual(['1.2.3.4']);
  });
});

describe('checkGate — refusal paths', () => {
  const scope = parseScope('.gov.hu\n');
  const goodInput: GateInput = {
    scope,
    targets: ['foo.gov.hu', 'bar.gov.hu'],
    authorized: true,
    scopeFileGiven: true,
  };

  it('refuses when --yes-i-am-authorized not passed', () => {
    const r = checkGate({ ...goodInput, authorized: false });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/authoriz/i);
  });

  it('refuses when scope file not given', () => {
    const r = checkGate({ ...goodInput, scopeFileGiven: false });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/scope/i);
  });

  it('refuses on empty scope', () => {
    const r = checkGate({ ...goodInput, scope: { suffixes: [], cidrs: [] } });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/empty/i);
  });

  it('refuses when any target is out of scope', () => {
    const r = checkGate({ ...goodInput, targets: ['foo.gov.hu', 'evil.com'] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/out.of.scope/i);
  });

  it('refuses on empty target list', () => {
    const r = checkGate({ ...goodInput, targets: [] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/no targets/i);
  });

  it('passes with all conditions met, returns filtered targets', () => {
    const r = checkGate(goodInput);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.targets.sort()).toEqual(['bar.gov.hu', 'foo.gov.hu']);
  });
});
