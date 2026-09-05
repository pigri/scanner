import { describe, it, expect } from 'vitest';
import { normalizeTestsslFinding } from '../src/lib/testssl-parse.js';

describe('normalizeTestsslFinding', () => {
  it('drops non-actionable severities (OK/INFO/WARN/DEBUG)', () => {
    for (const s of ['OK', 'INFO', 'WARN', 'DEBUG', '']) {
      expect(normalizeTestsslFinding({ id: 'x', severity: s, finding: 'y' })).toBeNull();
    }
  });

  it('builds title from the check id + finding value (not the value alone)', () => {
    const f = normalizeTestsslFinding({ id: 'cert_expirationStatus', severity: 'CRITICAL', finding: 'expired' })!;
    expect(f.severity).toBe('critical');
    expect(f.category).toBe('cert_expirationStatus');
    expect(f.title).toBe('Certificate expiration: expired'); // NOT just "expired"
  });

  it('retitles a real cert-trust garbage case (value → check: value)', () => {
    // used to be titled just "failed (chain incomplete)."
    expect(normalizeTestsslFinding({ id: 'cert_chain_of_trust', severity: 'CRITICAL', finding: 'failed (chain incomplete).' })!.title)
      .toBe('Certificate chain of trust: failed (chain incomplete).');
  });

  it('maps known ids to friendly labels, falls back to raw id otherwise', () => {
    expect(normalizeTestsslFinding({ id: 'POODLE_SSL', severity: 'HIGH', finding: 'VULNERABLE, uses SSLv3+CBC' })!.title)
      .toBe('POODLE (SSLv3): VULNERABLE, uses SSLv3+CBC');
    expect(normalizeTestsslFinding({ id: 'SSLv3', severity: 'HIGH', finding: 'offered' })!.title)
      .toBe('SSLv3: offered'); // unknown id → raw
  });

  it('collapses whitespace and preserves severity casing to lowercase', () => {
    const f = normalizeTestsslFinding({ id: 'BEAST_CBC_TLS1', severity: 'MEDIUM', finding: 'ECDHE-RSA-AES256-SHA   ECDHE-RSA-AES128-SHA' })!;
    expect(f.title).toBe('BEAST_CBC_TLS1: ECDHE-RSA-AES256-SHA ECDHE-RSA-AES128-SHA');
    expect(f.severity).toBe('medium');
  });

  it('handles a missing finding value (title is just the label)', () => {
    expect(normalizeTestsslFinding({ id: 'HSTS', severity: 'LOW' })!.title).toBe('HSTS');
  });

  it('carries a cve through when present', () => {
    expect(normalizeTestsslFinding({ id: 'heartbleed', severity: 'CRITICAL', finding: 'VULNERABLE', cve: 'CVE-2014-0160' })!.cve)
      .toBe('CVE-2014-0160');
  });

  it('drops redundant/summary checks (overall_grade, cert_notAfter/notBefore)', () => {
    expect(normalizeTestsslFinding({ id: 'overall_grade', severity: 'CRITICAL', finding: 'T' })).toBeNull();
    expect(normalizeTestsslFinding({ id: 'cert_notAfter', severity: 'CRITICAL', finding: '2018-11-04' })).toBeNull();
    expect(normalizeTestsslFinding({ id: 'cert_notBefore', severity: 'INFO', finding: '2016-01-01' })).toBeNull();
    // still drops them when they carry the multi-cert suffix
    expect(normalizeTestsslFinding({ id: 'cert_notAfter <hostCert#2>', severity: 'CRITICAL', finding: 'x' })).toBeNull();
  });

  it('strips the <hostCert#N> suffix from category/label', () => {
    const f = normalizeTestsslFinding({ id: 'cert_trust <hostCert#1>', severity: 'HIGH', finding: 'does not match' })!;
    expect(f.category).toBe('cert_trust');
    expect(f.title).toBe('Certificate trust: does not match');
  });
});
