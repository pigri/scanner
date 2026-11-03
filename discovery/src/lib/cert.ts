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

/**
 * Open a TLS connection and resolve the peer certificate. The injection point
 * for tests: the real implementation talks to the network, a fake one returns a
 * fixed cert (or throws) with no socket.
 */
export type CertConnect = (opts: {
  host: string;
  port: number;
  servername: string;
  timeoutMs: number;
}) => Promise<RawPeerCert>;

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

const realConnect: CertConnect = ({ host, port, servername, timeoutMs }) =>
  new Promise<RawPeerCert>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      fn();
    };
    const socket = tls.connect({
      host,
      port,
      servername,
      // Recon wants the cert's identity regardless of validity: an expired or
      // self-signed cert still tells us who the host claims to be.
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });
    const timer = setTimeout(() => finish(() => reject(new Error('tls timeout'))), timeoutMs);
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate() as RawPeerCert;
      finish(() => resolve(cert));
    });
    socket.once('timeout', () => finish(() => reject(new Error('tls timeout'))));
    socket.once('error', (e) => finish(() => reject(e)));
  });

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
  const connect = opts.connect ?? realConnect;
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
