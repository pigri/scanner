import { describe, it, expect } from 'vitest';
import { toCertRecords, b64FingerprintToHex, quoteBigSerials } from '../src/lib/sslyze-cert.js';

// Trimmed from a real sslyze run (site.okfo.gov.hu, run #15324) plus a synthetic
// RSA leaf and two records that must be skipped. serial_number is a STRING here
// because sslyze.ts pre-quotes it before JSON.parse (the real value, ~123 bits,
// loses precision as a JS number).
const fixture = {
  server_scan_results: [
    {
      server_location: { hostname: 'site.okfo.gov.hu', ip_address: '1.2.3.4', port: 443 },
      scan_status: 'COMPLETED',
      scan_result: {
        certificate_info: {
          result: {
            certificate_deployments: [
              {
                received_certificate_chain: [
                  {
                    fingerprint_sha256: 'uTDvCVyiwPnM5M+7A6dM3WS6KZQGb8e8OFfrWcnlLHk=',
                    not_valid_before: '2025-11-03T15:12:11Z',
                    not_valid_after: '2026-12-04T15:12:10Z',
                    serial_number: '7742690324942097440523856490400309004',
                    signature_hash_algorithm: { name: 'sha256', digest_size: 32 },
                    subject: {
                      rfc4514_string: 'CN=*.okfo.gov.hu,O=Országos Kórházi Főigazgatóság,L=Budapest,C=HU',
                      attributes: [
                        { oid: { name: 'countryName' }, value: 'HU' },
                        { oid: { name: 'localityName' }, value: 'Budapest' },
                        { oid: { name: 'organizationName' }, value: 'Országos Kórházi Főigazgatóság' },
                        { oid: { name: 'commonName' }, value: '*.okfo.gov.hu' },
                      ],
                    },
                    issuer: { rfc4514_string: 'CN=e-Szigno OV TLS CA 2023,2.5.4.97=VATHU-23584497,O=Microsec Ltd.,L=Budapest,C=HU' },
                    subject_alternative_name: { dns_names: ['*.aeek.hu', '*.gyemszi.hu', '*.okfo.gov.hu', '*.okfo.hu', 'aeek.hu', 'gyemszi.hu', 'okfo.gov.hu', 'okfo.hu'] },
                    public_key: { algorithm: 'ECPublicKey', key_size: 256, ec_curve_name: 'secp256r1' },
                  },
                ],
              },
            ],
          },
        },
      },
    },
    // Synthetic RSA, self-signed leaf — exercises RSA key-algo mapping + selfSigned.
    {
      server_location: { hostname: 'self.example', port: 8443 },
      scan_status: 'COMPLETED',
      scan_result: {
        certificate_info: {
          result: {
            certificate_deployments: [
              {
                received_certificate_chain: [
                  {
                    fingerprint_sha256: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
                    not_valid_before: '2024-01-01T00:00:00Z',
                    not_valid_after: '2034-01-01T00:00:00Z',
                    serial_number: 12345,
                    signature_hash_algorithm: { name: 'sha384' },
                    subject: { rfc4514_string: 'CN=self.example', attributes: [{ oid: { name: 'commonName' }, value: 'self.example' }] },
                    issuer: { rfc4514_string: 'CN=self.example' },
                    subject_alternative_name: { dns_names: ['self.example'] },
                    public_key: { algorithm: 'RSAPublicKey', key_size: 2048 },
                  },
                ],
              },
            ],
          },
        },
      },
    },
    // COMPLETED but no chain → skipped.
    {
      server_location: { hostname: 'empty.example', port: 443 },
      scan_status: 'COMPLETED',
      scan_result: { certificate_info: { result: { certificate_deployments: [{ received_certificate_chain: [] }] } } },
    },
    // Not COMPLETED → skipped.
    {
      server_location: { hostname: 'failed.example', port: 443 },
      scan_status: 'ERROR',
      scan_result: {},
    },
  ],
};

describe('b64FingerprintToHex', () => {
  it('converts base64 sha256 to uppercase hex matching the stored format', () => {
    expect(b64FingerprintToHex('uTDvCVyiwPnM5M+7A6dM3WS6KZQGb8e8OFfrWcnlLHk='))
      .toBe('B930EF095CA2C0F9CCE4CFBB03A74CDD64BA2994066FC7BC3857EB59C9E52C79');
  });
  it('returns null for empty/missing input', () => {
    expect(b64FingerprintToHex(null)).toBeNull();
    expect(b64FingerprintToHex(undefined)).toBeNull();
    expect(b64FingerprintToHex('')).toBeNull();
  });
});

describe('toCertRecords', () => {
  const recs = toCertRecords(fixture);

  it('extracts one row per leaf, skipping non-COMPLETED and chain-less results', () => {
    expect(recs.map((r) => r.target)).toEqual(['site.okfo.gov.hu', 'self.example']);
  });

  it('maps the EC leaf with a byte-identical uppercase-hex fingerprint', () => {
    const c = recs[0]!;
    expect(c.target).toBe('site.okfo.gov.hu');
    expect(c.port).toBe(443);
    expect(c.certIndex).toBe(1);
    expect(c.fingerprintSha256).toBe('B930EF095CA2C0F9CCE4CFBB03A74CDD64BA2994066FC7BC3857EB59C9E52C79');
    expect(c.commonName).toBe('*.okfo.gov.hu');
    expect(c.san).toContain('*.okfo.gov.hu');
    expect(c.san).toContain('aeek.hu');
    expect(c.san).toHaveLength(8);
    expect(c.issuer).toBe('CN=e-Szigno OV TLS CA 2023,2.5.4.97=VATHU-23584497,O=Microsec Ltd.,L=Budapest,C=HU');
    expect(c.notBefore).toBe('2025-11-03T15:12:11Z');
    expect(c.notAfter).toBe('2026-12-04T15:12:10Z');
    expect(c.keyAlgo).toBe('EC');
    expect(c.keySize).toBe(256);
    expect(c.sigAlgo).toBe('sha256');
    expect(c.serial).toBe('7742690324942097440523856490400309004');
    expect(c.selfSigned).toBe(false);
  });

  it('maps RSA key algo, numeric serial, and self-signed', () => {
    const c = recs[1]!;
    expect(c.target).toBe('self.example');
    expect(c.port).toBe(8443);
    expect(c.keyAlgo).toBe('RSA');
    expect(c.keySize).toBe(2048);
    expect(c.sigAlgo).toBe('sha384');
    expect(c.serial).toBe('12345');
    expect(c.selfSigned).toBe(true);
  });
});


describe('quoteBigSerials', () => {
  it('round-trips a serial above 2^53 as an exact string', () => {
    const big = '7742690324942097440523856490400309004';
    const parsed = JSON.parse(quoteBigSerials(`{"serial_number": ${big}}`));
    expect(parsed.serial_number).toBe(big); // not 7.74e+36
  });
  it('leaves an already-quoted serial untouched', () => {
    const parsed = JSON.parse(quoteBigSerials('{"serial_number": "123"}'));
    expect(parsed.serial_number).toBe('123');
  });
  it('quotes a negative serial too', () => {
    const parsed = JSON.parse(quoteBigSerials('{"serial_number": -5}'));
    expect(parsed.serial_number).toBe('-5');
  });
  it('does not touch other numbers or a *_serial_number key', () => {
    const parsed = JSON.parse(quoteBigSerials('{"key_size": 2048, "x_serial_number": 5, "serial_number": 9}'));
    expect(parsed.key_size).toBe(2048);        // number, untouched
    expect(parsed.x_serial_number).toBe(5);    // suffixed key, untouched
    expect(parsed.serial_number).toBe('9');    // the real key, quoted
  });
});

// A single host presenting several deployments, the middle one fingerprint-less.
const fp1 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
const fp2 = 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=';
const leaf = (fingerprint_sha256: string | undefined, algo: string, cn: string) => ({
  ...(fingerprint_sha256 !== undefined ? { fingerprint_sha256 } : {}),
  public_key: { algorithm: algo, key_size: 256 },
  signature_hash_algorithm: { name: 'sha256' },
  subject: { rfc4514_string: `CN=${cn}`, attributes: [{ oid: { name: 'commonName' }, value: cn }] },
  issuer: { rfc4514_string: 'CN=Issuing CA' },
  subject_alternative_name: { dns_names: [cn] },
});
const multiFixture = {
  server_scan_results: [
    {
      server_location: { hostname: 'multi.example', port: 443 },
      scan_status: 'COMPLETED',
      scan_result: {
        certificate_info: {
          result: {
            certificate_deployments: [
              { received_certificate_chain: [leaf(fp1, 'ECPublicKey', 'a')] },
              { received_certificate_chain: [leaf(undefined, 'ECPublicKey', 'b')] }, // no fingerprint → skipped
              { received_certificate_chain: [leaf(fp2, 'RSAPublicKey', 'c')] },
            ],
          },
        },
      },
    },
  ],
};

describe('toCertRecords multi-deployment', () => {
  it('numbers certIndex per host and skips a fingerprint-less deployment without consuming an index', () => {
    const recs = toCertRecords(multiFixture);
    expect(recs).toHaveLength(2);
    expect(recs.map((r) => ({ target: r.target, port: r.port, certIndex: r.certIndex, keyAlgo: r.keyAlgo }))).toEqual([
      { target: 'multi.example', port: 443, certIndex: 1, keyAlgo: 'EC' },
      { target: 'multi.example', port: 443, certIndex: 2, keyAlgo: 'RSA' },
    ]);
  });
});
