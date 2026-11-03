import { describe, it, expect, vi } from 'vitest';
import {
  parseCert,
  certCsvFields,
  fetchCert,
  connectPeerCert,
  type RawPeerCert,
  type CertConnect,
  type CertSocket,
  type SocketFactory,
} from '../src/lib/cert.js';

// A fake TLS socket the tests drive by hand, so connectPeerCert's real
// lifecycle (settle-once guard, destroy/clearTimeout, the four settle paths)
// is exercised without the network.
class FakeSocket implements CertSocket {
  listeners: Record<string, ((...a: unknown[]) => void)[]> = {};
  destroyed = 0;
  constructor(private cert: RawPeerCert = {}) {}
  getPeerCertificate(): RawPeerCert { return this.cert; }
  destroy(): void { this.destroyed++; }
  once(event: string, cb: (...a: unknown[]) => void): unknown { (this.listeners[event] ??= []).push(cb); return this; }
  on(event: string, cb: (...a: unknown[]) => void): unknown { (this.listeners[event] ??= []).push(cb); return this; }
  emit(event: string, ...args: unknown[]): void { for (const cb of (this.listeners[event] ?? []).slice()) cb(...args); }
}
const factory = (fake: FakeSocket): SocketFactory => () => fake;
const OPTS = { host: '1.2.3.4', port: 443, servername: 'h.example', timeoutMs: 1000 };

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


describe('connectPeerCert (socket lifecycle)', () => {
  it('resolves the peer cert on secureConnect and destroys the socket once', async () => {
    const fake = new FakeSocket({ subject: { O: 'Acme', CN: 'h.example' } });
    const p = connectPeerCert(OPTS, factory(fake));
    fake.emit('secureConnect');
    await expect(p).resolves.toEqual({ subject: { O: 'Acme', CN: 'h.example' } });
    expect(fake.destroyed).toBe(1);
  });

  it('rejects and destroys once on error', async () => {
    const fake = new FakeSocket();
    const p = connectPeerCert(OPTS, factory(fake));
    fake.emit('error', new Error('ECONNREFUSED'));
    await expect(p).rejects.toThrow('ECONNREFUSED');
    expect(fake.destroyed).toBe(1);
  });

  it('rejects and destroys once on a timeout event', async () => {
    const fake = new FakeSocket();
    const p = connectPeerCert(OPTS, factory(fake));
    fake.emit('timeout');
    await expect(p).rejects.toThrow(/timeout/i);
    expect(fake.destroyed).toBe(1);
  });

  it('settles via the hard timer even if no socket event ever fires', async () => {
    vi.useFakeTimers();
    try {
      const fake = new FakeSocket();
      const p = connectPeerCert({ ...OPTS, timeoutMs: 500 }, factory(fake));
      vi.advanceTimersByTime(500);
      await expect(p).rejects.toThrow(/timeout/i);
      expect(fake.destroyed).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('settles exactly once when secureConnect is followed by an error', async () => {
    const fake = new FakeSocket({ subject: { CN: 'h.example' } });
    const p = connectPeerCert(OPTS, factory(fake));
    fake.emit('secureConnect');
    // a late error on the (now destroyed) socket must not flip the result or throw
    expect(() => fake.emit('error', new Error('late'))).not.toThrow();
    await expect(p).resolves.toEqual({ subject: { CN: 'h.example' } });
    expect(fake.destroyed).toBe(1);
    // a no-op error listener was attached at teardown (alongside the original
    // once('error')), so a later error on the destroyed socket is swallowed.
    expect(fake.listeners['error']!.length).toBeGreaterThanOrEqual(2);
  });
});
