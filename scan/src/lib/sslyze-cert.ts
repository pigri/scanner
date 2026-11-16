// Turn an sslyze JSON result into certificate-inventory rows, mirroring
// lib/testssl-cert.ts. sslyze reports the full leaf certificate of every
// certificate deployment; we take the leaf (received_certificate_chain[0]) of
// each deployment for every COMPLETED host.
//
// Two conversions matter:
//  - `fingerprint_sha256` is base64 in sslyze, but the certificates table (and
//    testssl) stores uppercase hex. Convert it so the UNIQUE(target, port,
//    fingerprint_sha256) dedup stays byte-identical across the two tools.
//  - `serial_number` is a decimal integer that routinely exceeds 2^53, so
//    sslyze.ts pre-quotes it to a string before JSON.parse; here we accept
//    string | number and stringify.
import type { CertInput } from './db.js';

interface SslyzeOid { name?: string }
interface SslyzeAttr { oid?: SslyzeOid; value?: string }
interface SslyzeName { rfc4514_string?: string; attributes?: SslyzeAttr[] }
interface SslyzeLeaf {
  fingerprint_sha256?: string;
  not_valid_before?: string;
  not_valid_after?: string;
  serial_number?: string | number;
  signature_hash_algorithm?: { name?: string } | null;
  subject?: SslyzeName;
  issuer?: SslyzeName;
  subject_alternative_name?: { dns_names?: string[] };
  public_key?: { algorithm?: string; key_size?: number };
}
interface SslyzeDeployment { received_certificate_chain?: SslyzeLeaf[] }
interface SslyzeServerResult {
  server_location?: { hostname?: string; port?: number };
  scan_status?: string;
  scan_result?: { certificate_info?: { result?: { certificate_deployments?: SslyzeDeployment[] } } };
}
export interface SslyzeCertResult { server_scan_results?: SslyzeServerResult[] }

// The output is JSON from a scanned server: any field can have any type.
type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | null => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Obj) : null);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

/** sslyze base64 SHA-256 fingerprint → uppercase hex (stored/testssl format). */
export function b64FingerprintToHex(b64: string | null | undefined): string | null {
  if (!b64 || typeof b64 !== 'string') return null;
  const hex = Buffer.from(b64, 'base64').toString('hex');
  // A SHA-256 fingerprint is exactly 32 bytes; reject anything else so a
  // malformed value can never be stored in a shape that fails dedup against
  // testssl's 64-char hex.
  return hex.length === 64 ? hex.toUpperCase() : null;
}

/**
 * Pre-`JSON.parse` rewrite: quote every integer `serial_number` value so it
 * survives as a string. A certificate serial routinely exceeds 2^53 and would
 * lose precision as a JS number. Only the bare `"serial_number":` key matches
 * (never a `*_serial_number` key, never an in-string occurrence, which would
 * need escaped quotes and so break the key/colon adjacency); an already-quoted
 * value is left untouched because the next char is `"`, not a digit or sign.
 */
export function quoteBigSerials(text: string): string {
  return text.replace(/("serial_number":\s*)(-?\d+)/g, '$1"$2"');
}

/** "ECPublicKey" → "EC", "RSAPublicKey" → "RSA", else the name uppercased. */
function keyAlgo(algorithm: unknown): string | null {
  const a = str(algorithm);
  if (!a) return null;
  const base = a.replace(/PublicKey$/i, '');
  return (base || a).toUpperCase();
}

function subjectAttr(subject: Obj | null, oidName: string): string | null {
  for (const raw of arr(subject?.attributes)) {
    const a = obj(raw);
    const value = str(a?.value);
    if (obj(a?.oid)?.name === oidName && value) return value;
  }
  return null;
}

/** All leaf certificates across every COMPLETED host, ready for insertCertificate. */
export function toCertRecords(result: SslyzeCertResult): CertInput[] {
  const out: CertInput[] = [];
  for (const rawRow of arr(obj(result)?.server_scan_results)) {
    const row = obj(rawRow);
    const loc = obj(row?.server_location);
    const target = str(loc?.hostname);
    if (!row || !target || row.scan_status !== 'COMPLETED') continue;
    const port = num(loc?.port);
    const deployments = arr(obj(obj(obj(row.scan_result)?.certificate_info)?.result)?.certificate_deployments);
    let certIndex = 0;
    for (const rawDep of deployments) {
      const leaf = obj(arr(obj(rawDep)?.received_certificate_chain)[0]);
      if (!leaf) continue;
      const fingerprintSha256 = b64FingerprintToHex(str(leaf.fingerprint_sha256));
      if (!fingerprintSha256) continue;
      certIndex += 1;
      const subject = obj(leaf.subject);
      const san = [...new Set(arr(obj(leaf.subject_alternative_name)?.dns_names).filter((x): x is string => typeof x === 'string').map((x) => x.trim()).filter(Boolean))];
      const serial = typeof leaf.serial_number === 'string' || typeof leaf.serial_number === 'number' ? String(leaf.serial_number) : null;
      const subjectDn = str(subject?.rfc4514_string);
      const issuerDn = str(obj(leaf.issuer)?.rfc4514_string);
      const pub = obj(leaf.public_key);
      out.push({
        target,
        port,
        certIndex,
        commonName: subjectAttr(subject, 'commonName'),
        organization: subjectAttr(subject, 'organizationName'),
        orgUnit: subjectAttr(subject, 'organizationalUnitName'),
        locality: subjectAttr(subject, 'localityName'),
        country: subjectAttr(subject, 'countryName'),
        san,
        issuer: issuerDn,
        notBefore: str(leaf.not_valid_before),
        notAfter: str(leaf.not_valid_after),
        keyAlgo: keyAlgo(pub?.algorithm),
        keySize: num(pub?.key_size),
        sigAlgo: str(obj(leaf.signature_hash_algorithm)?.name),
        serial,
        fingerprintSha256,
        selfSigned: subjectDn != null && subjectDn === issuerDn,
      });
    }
  }
  return out;
}
