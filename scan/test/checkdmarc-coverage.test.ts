import { describe, it, expect } from 'vitest';
import { checkdmarcRowConclusive, checkdmarcCoveredTargets } from '../src/lib/checkdmarc-coverage.js';

const clean = (domain: string) => ({
  domain,
  dnssec: false,
  spf: { record: 'v=spf1 -all', valid: true },
  dmarc: { record: 'v=DMARC1; p=reject', valid: true },
  mx: { hosts: [] },
});

describe('checkdmarcRowConclusive', () => {
  it('accepts a clean row that yields no problem', () => {
    expect(checkdmarcRowConclusive(clean('a.example.com'))).toBe(true);
  });

  it('accepts a row whose records are genuinely absent (an answer was received)', () => {
    expect(checkdmarcRowConclusive({ domain: 'a.example.com', dmarc: { record: null, error: 'The domain does not exist' } })).toBe(true);
  });

  it.each([
    'The resolution lifetime expired after 5.1 seconds: Server Do53:192.0.2.53@53 answered The DNS operation timed out.',
    'The Resolution Lifetime Expired after 5.0 seconds',
    'All nameservers failed to answer the query _dmarc.a.example.com. IN TXT: Server Do53:192.0.2.53@53 answered SERVFAIL',
    'The DNS operation timed out after 2.0 seconds',
    'the DNSKEY query for a.example.com failed with SERVFAIL: x',
    'DNS resolution failed',
  ])('rejects a resolver failure anywhere in the row: %s', (msg) => {
    expect(checkdmarcRowConclusive({ domain: 'a.example.com', dmarc: { record: null, error: msg } })).toBe(false);
    expect(checkdmarcRowConclusive({ domain: 'a.example.com', mx: { warnings: [msg] } })).toBe(false);
  });

  it('rejects a row without a domain', () => {
    const noDomain = { domain: undefined, dmarc: { record: 'v=DMARC1; p=none' } };
    expect(checkdmarcRowConclusive(noDomain)).toBe(false);
  });
});

describe('checkdmarcCoveredTargets', () => {
  it('covers conclusive domains with zero findings and skips timeouts and absent domains', () => {
    const slow = { domain: 'slow.example.com', dmarc: { record: null, error: 'The resolution lifetime expired after 5.0 seconds' } };
    const rows = [clean('ok.example.com'), slow];
    // absent.example.com was requested but has no row in the output
    expect(checkdmarcCoveredTargets(rows)).toEqual(['ok.example.com']);
  });

  it('does not cover a domain that has any inconclusive row', () => {
    const failed = { domain: 'dup.example.com', spf: { warnings: ['nameservers failed to answer'] } };
    const rows = [clean('dup.example.com'), failed];
    expect(checkdmarcCoveredTargets(rows)).toEqual([]);
  });
});
