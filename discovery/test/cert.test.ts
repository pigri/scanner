import { describe, it, expect } from 'vitest';
import {
  parseCert,
  certCsvFields,
  fetchCert,
  type RawPeerCert,
  type CertConnect,
} from '../src/lib/cert.js';

describe('parseCert', () => {
  it('extracts subject O/CN and issuer O', () => {
    const raw: RawPeerCert = {
      subject: { O: 'DTR Kft', CN: 'dtr.gov.hu' },
      issuer: { O: "Let's Encrypt" },
    };
    expect(parseCert(raw)).toEqual({ org: 'DTR Kft', cn: 'dtr.gov.hu', issuer_org: "Let's Encrypt" });
  });

  it('takes the first value of a multi-valued RDN', () => {
    const raw: RawPeerCert = {
      subject: { O: ['Primary Org', 'Secondary'], CN: 'host.example.com' },
      issuer: { O: ['CA One', 'CA Two'] },
    };
    expect(parseCert(raw)).toEqual({ org: 'Primary Org', cn: 'host.example.com', issuer_org: 'CA One' });
  });

  it('returns null for each missing field (partial cert)', () => {
    const raw: RawPeerCert = { subject: { CN: 'host.example.com' } };
    expect(parseCert(raw)).toEqual({ org: null, cn: 'host.example.com', issuer_org: null });
  });

  it('returns all-null for an empty/missing cert', () => {
    expect(parseCert({})).toEqual({ org: null, cn: null, issuer_org: null });
    expect(parseCert(null)).toEqual({ org: null, cn: null, issuer_org: null });
    expect(parseCert({ subject: { O: '   ' } })).toEqual({ org: null, cn: null, issuer_org: null });
  });
});

describe('certCsvFields', () => {
  it('returns three empty strings for a null cert', () => {
    expect(certCsvFields(null)).toEqual(['', '', '']);
  });

  it('passes an org containing a comma through intact (the openssl-awk bug)', () => {
    const cert = { org: 'Example Kft., Budapest', cn: 'www.example.hu', issuer_org: 'GlobalSign nv-sa' };
    expect(certCsvFields(cert)).toEqual(['Example Kft., Budapest', 'www.example.hu', 'GlobalSign nv-sa']);
  });

  it('maps null fields to empty strings', () => {
    expect(certCsvFields({ org: 'X', cn: null, issuer_org: null })).toEqual(['X', '', '']);
  });
});

describe('fetchCert', () => {
  const okConnect = (raw: RawPeerCert): CertConnect => async () => raw;

  it('returns the parsed cert on a successful handshake', async () => {
    const connect = okConnect({ subject: { O: 'DTR Kft', CN: 'dtr.gov.hu' }, issuer: { O: 'LE' } });
    await expect(fetchCert('dtr.gov.hu', { ip: '1.2.3.4', timeoutMs: 1000, connect })).resolves.toEqual({
      org: 'DTR Kft',
      cn: 'dtr.gov.hu',
      issuer_org: 'LE',
    });
  });

  it('passes host as servername and dials the resolved ip', async () => {
    let seen: { host: string; port: number; servername: string } | null = null;
    const connect: CertConnect = async (o) => {
      seen = { host: o.host, port: o.port, servername: o.servername };
      return { subject: { CN: 'h' } };
    };
    await fetchCert('dtr.gov.hu', { ip: '9.9.9.9', timeoutMs: 1000, connect });
    expect(seen).toEqual({ host: '9.9.9.9', port: 443, servername: 'dtr.gov.hu' });
  });

  it('resolves null (never throws) when the connection errors', async () => {
    const connect: CertConnect = async () => { throw new Error('ECONNREFUSED'); };
    await expect(fetchCert('nope.example', { ip: '1.2.3.4', timeoutMs: 1000, connect })).resolves.toBeNull();
  });

  it('resolves null (never throws) on timeout', async () => {
    const connect: CertConnect = async () => { throw new Error('tls timeout'); };
    await expect(fetchCert('slow.example', { ip: '1.2.3.4', timeoutMs: 1, connect })).resolves.toBeNull();
  });
});
