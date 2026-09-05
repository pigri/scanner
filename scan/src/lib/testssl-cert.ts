// Parse the structured certificate block from a testssl JSON record list.
// testssl emits many cert_* records (mostly INFO/OK) that the findings path
// drops; here we assemble them into per-certificate rows for an inventory. A
// host can present multiple certs (RSA + ECDSA), tagged `<hostCert#N>`.

export interface TestsslCertInput { id?: string; port?: string; severity?: string; finding?: string }

export interface CertRecord {
  certIndex: number;
  port: number | null;
  commonName: string | null;
  san: string[];
  issuer: string | null;
  notBefore: string | null;
  notAfter: string | null;
  keyAlgo: string | null;
  keySize: number | null;
  sigAlgo: string | null;
  serial: string | null;
  fingerprintSha256: string | null;
  selfSigned: boolean;
}

/** Split "cert_commonName <hostCert#2>" → { base: "cert_commonName", index: 2 }. */
export function splitCertId(id: string): { base: string; index: number } {
  const m = id.match(/^(.*?)\s*<hostCert#(\d+)>\s*$/);
  if (m) return { base: m[1]!.trim(), index: parseInt(m[2]!, 10) };
  return { base: id.trim(), index: 1 };
}

/** "RSA 2048 bits (exponent is 65537)" / "EC 256 bits (curve P-256)" → algo+bits. */
export function parseKeySize(finding: string): { algo: string | null; bits: number | null } {
  const m = finding.match(/^([A-Za-z]+)\s+(\d+)\s*bit/i);
  if (!m) return { algo: null, bits: null };
  return { algo: m[1]!.toUpperCase(), bits: parseInt(m[2]!, 10) };
}

export function parseCertificates(records: readonly TestsslCertInput[]): CertRecord[] {
  const groups = new Map<number, TestsslCertInput[]>();
  let port: number | null = null;
  for (const r of records) {
    if (!r.id || !r.id.startsWith('cert')) continue;
    if (port === null && r.port) { const p = parseInt(r.port, 10); if (!Number.isNaN(p)) port = p; }
    const { index } = splitCertId(r.id);
    if (!groups.has(index)) groups.set(index, []);
    groups.get(index)!.push(r);
  }

  const out: CertRecord[] = [];
  for (const [certIndex, recs] of [...groups.entries()].sort((a, b) => a[0] - b[0])) {
    const get = (base: string): string | null => {
      const r = recs.find((x) => splitCertId(x.id!).base === base);
      return r && r.finding ? r.finding.replace(/\s+/g, ' ').trim() : null;
    };
    const sanRaw = get('cert_subjectAltName');
    const san = sanRaw ? [...new Set(sanRaw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean))] : [];
    const ks = parseKeySize(get('cert_keySize') ?? '');
    const chain = (get('cert_chain_of_trust') ?? '').toLowerCase();

    const cert: CertRecord = {
      certIndex, port,
      commonName: get('cert_commonName'),
      san,
      issuer: get('cert_caIssuers'),
      notBefore: get('cert_notBefore'),
      notAfter: get('cert_notAfter'),
      keyAlgo: ks.algo, keySize: ks.bits,
      sigAlgo: get('cert_signatureAlgorithm'),
      serial: get('cert_serialNumber'),
      fingerprintSha256: get('cert_fingerprintSHA256'),
      selfSigned: /self.signed/.test(chain),
    };
    // Skip empty groups (no identifying data at all).
    if (cert.fingerprintSha256 || cert.commonName || cert.notAfter || cert.san.length) out.push(cert);
  }
  return out;
}

/** In-scope, non-wildcard SAN hostnames — the discovery-feedback harvest. */
export function harvestSans(certs: readonly CertRecord[], suffix: string, includeWildcards = false): string[] {
  const suf = suffix.startsWith('.') ? suffix : `.${suffix}`;
  const set = new Set<string>();
  for (const c of certs) {
    for (const raw of c.san) {
      const name = raw.toLowerCase().replace(/\.$/, '');
      if (!includeWildcards && name.startsWith('*.')) continue;
      const bare = name.replace(/^\*\./, '');
      if (bare === suffix.replace(/^\./, '') || bare.endsWith(suf)) set.add(name);
    }
  }
  return [...set].sort();
}
