import { describe, it, expect } from 'vitest';
import { splitCertId, parseKeySize, parseCertificates, harvestSans } from '../src/lib/testssl-cert.js';

describe('splitCertId', () => {
  it('extracts base id and cert index from the <hostCert#N> suffix', () => {
    expect(splitCertId('cert_commonName <hostCert#2>')).toEqual({ base: 'cert_commonName', index: 2 });
    expect(splitCertId('cert_chain_of_trust')).toEqual({ base: 'cert_chain_of_trust', index: 1 });
  });
});

describe('parseKeySize', () => {
  it('parses RSA and EC key sizes', () => {
    expect(parseKeySize('RSA 2048 bits (exponent is 65537)')).toEqual({ algo: 'RSA', bits: 2048 });
    expect(parseKeySize('EC 256 bits (curve P-256)')).toEqual({ algo: 'EC', bits: 256 });
  });
  it('returns nulls when unparseable', () => {
    expect(parseKeySize('weird')).toEqual({ algo: null, bits: null });
  });
});

describe('parseCertificates', () => {
  const recs = [
    { id: 'cert_commonName <hostCert#1>', port: '443', finding: '*.azureedge.net' },
    { id: 'cert_subjectAltName <hostCert#1>', port: '443', finding: '*.azureedge.net cdn.example.gov.hu' },
    { id: 'cert_keySize <hostCert#1>', finding: 'RSA 2048 bits (exponent is 65537)' },
    { id: 'cert_signatureAlgorithm <hostCert#1>', finding: 'SHA384 with RSA' },
    { id: 'cert_fingerprintSHA256 <hostCert#1>', finding: '994A3A06EEC4' },
    { id: 'cert_caIssuers <hostCert#1>', finding: 'Microsoft TLS G2 RSA CA' },
    { id: 'cert_notAfter <hostCert#1>', finding: '2026-12-03 18:15' },
    { id: 'cert_chain_of_trust <hostCert#1>', finding: 'passed.' },
    // a second cert (ECDSA)
    { id: 'cert_keySize <hostCert#2>', finding: 'EC 256 bits (curve P-256)' },
    { id: 'cert_fingerprintSHA256 <hostCert#2>', finding: '45392FEDE3' },
    { id: 'cert_chain_of_trust <hostCert#2>', finding: 'failed (self signed).' },
    // non-cert noise
    { id: 'SSLv3', finding: 'not offered' },
  ];

  it('groups records into one CertRecord per hostCert index', () => {
    const certs = parseCertificates(recs);
    expect(certs).toHaveLength(2);
    expect(certs[0]!.certIndex).toBe(1);
    expect(certs[1]!.certIndex).toBe(2);
  });

  it('populates structured fields for cert #1', () => {
    const c = parseCertificates(recs)[0]!;
    expect(c.commonName).toBe('*.azureedge.net');
    expect(c.san).toEqual(['*.azureedge.net', 'cdn.example.gov.hu']);
    expect(c.keyAlgo).toBe('RSA');
    expect(c.keySize).toBe(2048);
    expect(c.sigAlgo).toBe('SHA384 with RSA');
    expect(c.fingerprintSha256).toBe('994A3A06EEC4');
    expect(c.issuer).toBe('Microsoft TLS G2 RSA CA');
    expect(c.notAfter).toBe('2026-12-03 18:15');
    expect(c.port).toBe(443);
    expect(c.selfSigned).toBe(false);
  });

  it('flags self-signed from chain_of_trust', () => {
    expect(parseCertificates(recs)[1]!.selfSigned).toBe(true);
  });

  it('ignores non-cert records', () => {
    // SSLv3 must not create a cert row
    expect(parseCertificates([{ id: 'SSLv3', finding: 'offered' }])).toHaveLength(0);
  });
});

describe('harvestSans', () => {
  const certs = parseCertificates([
    { id: 'cert_subjectAltName <hostCert#1>', finding: 'a.gov.hu b.gov.hu *.wild.gov.hu external.example.com' },
    { id: 'cert_subjectAltName <hostCert#2>', finding: 'a.gov.hu c.gov.hu' },
  ]);

  it('keeps only in-scope, non-wildcard, deduped SANs', () => {
    expect(harvestSans(certs, 'gov.hu')).toEqual(['a.gov.hu', 'b.gov.hu', 'c.gov.hu']);
  });

  it('can include wildcards when asked', () => {
    expect(harvestSans(certs, 'gov.hu', true)).toContain('*.wild.gov.hu');
  });

  it('excludes out-of-scope SANs', () => {
    expect(harvestSans(certs, 'gov.hu')).not.toContain('external.example.com');
  });
});
