import tls from 'node:tls';

/** Organization-level identity read from a host's TLS certificate. */
export interface CertInfo {
  /** subject O (organization). */
  org: string | null;
  /** subject CN (common name). */
  cn: string | null;
  /** issuer O (the CA/organization that signed the cert). */
  issuer_org: string | null;
}

/** The slice of node:tls's getPeerCertificate() shape that we read. */
export interface RawPeerCert {
  subject?: { O?: string | string[]; CN?: string | string[] } | null;
  issuer?: { O?: string | string[] } | null;
}

/** First value of an RDN that may be a string or a multi-valued array; '' -> null. */
function firstRdn(v: string | string[] | undefined): string | null {
  const raw = Array.isArray(v) ? v[0] : v;
  if (raw == null) return null;
  const s = String(raw).trim();
  return s === '' ? null : s;
}

/** Pull org / cn / issuer_org out of a raw peer certificate (all nullable). */
export function parseCert(raw: RawPeerCert | null | undefined): CertInfo {
  return {
    org: firstRdn(raw?.subject?.O),
    cn: firstRdn(raw?.subject?.CN),
    issuer_org: firstRdn(raw?.issuer?.O),
  };
}

/**
 * The three CSV columns for a cert, in header order (cert_org, cert_cn,
 * cert_issuer_org). A null cert -> three empty strings. Values are returned
 * verbatim (the CSV writer handles quoting), so an org containing a comma
 * survives intact — unlike `openssl ... | awk -F', '`, which truncates it.
 */
export function certCsvFields(cert: CertInfo | null): [string, string, string] {
  return [cert?.org ?? '', cert?.cn ?? '', cert?.issuer_org ?? ''];
}

/** Minimal view of the TLS socket connectPeerCert drives — injectable for tests. */
export interface CertSocket {
  getPeerCertificate(): RawPeerCert;
  destroy(): void;
  once(event: string, listener: (...args: unknown[]) => void): unknown;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface ConnectOpts {
  host: string;
  port: number;
  servername: string;
  timeoutMs: number;
}

export type SocketFactory = (opts: ConnectOpts) => CertSocket;

const realSocketFactory: SocketFactory = ({ host, port, servername, timeoutMs }) =>
  // Recon wants the cert's identity regardless of validity: an expired or
  // self-signed cert still tells us who the host claims to be.
  tls.connect({ host, port, servername, rejectUnauthorized: false, timeout: timeoutMs }) as unknown as CertSocket;

/**
 * Open a TLS connection and resolve the peer certificate. Settles EXACTLY once
 * via `finish`: a hard timer guarantees settlement even if no socket event ever
 * fires, the socket is destroyed and the timer cleared on every path, and a
 * no-op error listener is attached before teardown so a second 'error' on the
 * destroyed socket cannot become an unhandled throw. The socket is injectable
 * so these paths are unit-tested without the network.
 */
export function connectPeerCert(
  opts: ConnectOpts,
  socketFactory: SocketFactory = realSocketFactory,
): Promise<RawPeerCert> {
  return new Promise<RawPeerCert>((resolve, reject) => {
    let settled = false;
    const socket = socketFactory(opts);
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.on('error', () => {}); // swallow any error raised after teardown
      socket.destroy();
      fn();
    };
    const timer = setTimeout(() => finish(() => reject(new Error('tls timeout'))), opts.timeoutMs);
    socket.once('secureConnect', () => finish(() => resolve(socket.getPeerCertificate())));
    socket.once('timeout', () => finish(() => reject(new Error('tls timeout'))));
    socket.once('error', (e: unknown) =>
      finish(() => reject(e instanceof Error ? e : new Error(String(e)))),
    );
  });
}

/** Injection point for fetchCert's high-level tests (returns/throws a Promise). */
export type CertConnect = (opts: ConnectOpts) => Promise<RawPeerCert>;

/**
 * Fetch the TLS certificate identity for `host`, dialing `ip` (its resolved
 * address) with SNI set to `host`. Returns the parsed CertInfo on a successful
 * handshake (individual fields may be null), or null when the connection fails.
 *
 * NEVER throws: every failure (timeout, refused, no 443, no cert) resolves to
 * null. The caller runs this inside the enrich pool worker, whose non-rejection
 * is what keeps enrich reaching a clean `exit 0` (the enrich-exit invariant).
 */
export async function fetchCert(
  host: string,
  opts: { ip?: string; port?: number; timeoutMs: number; connect?: CertConnect },
): Promise<CertInfo | null> {
  const connect = opts.connect ?? ((o: ConnectOpts) => connectPeerCert(o));
  try {
    const raw = await connect({
      host: opts.ip ?? host,
      port: opts.port ?? 443,
      servername: host,
      timeoutMs: opts.timeoutMs,
    });
    return parseCert(raw);
  } catch {
    return null;
  }
}
