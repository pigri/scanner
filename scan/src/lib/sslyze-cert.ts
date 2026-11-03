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

/** sslyze base64 SHA-256 fingerprint → uppercase hex (stored/testssl format). */
export function b64FingerprintToHex(b64: string | null | undefined): string | null {
  if (!b64) return null;
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
function keyAlgo(algorithm: string | undefined): string | null {
  if (!algorithm) return null;
  const base = algorithm.replace(/PublicKey$/i, '');
  return (base || algorithm).toUpperCase();
}

function subjectAttr(subject: SslyzeName | undefined, oidName: string): string | null {
  for (const a of subject?.attributes ?? []) {
    if (a.oid?.name === oidName && a.value) return a.value;
  }
  return null;
}

/** All leaf certificates across every COMPLETED host, ready for insertCertificate. */
export function toCertRecords(result: SslyzeCertResult): CertInput[] {
  const out: CertInput[] = [];
  for (const row of result.server_scan_results ?? []) {
    const target = row.server_location?.hostname;
    if (!target || row.scan_status !== 'COMPLETED') continue;
    const port = row.server_location?.port ?? null;
    const deployments = row.scan_result?.certificate_info?.result?.certificate_deployments ?? [];
    let certIndex = 0;
    for (const dep of deployments) {
      const leaf = dep.received_certificate_chain?.[0];
      if (!leaf) continue;
      const fingerprintSha256 = b64FingerprintToHex(leaf.fingerprint_sha256);
      if (!fingerprintSha256) continue;
      certIndex += 1;
      const san = [...new Set((leaf.subject_alternative_name?.dns_names ?? []).map((s) => s.trim()).filter(Boolean))];
      const serial = leaf.serial_number == null ? null : String(leaf.serial_number);
      const subjectDn = leaf.subject?.rfc4514_string ?? null;
      const issuerDn = leaf.issuer?.rfc4514_string ?? null;
      out.push({
        target,
        port,
        certIndex,
        commonName: subjectAttr(leaf.subject, 'commonName'),
        organization: subjectAttr(leaf.subject, 'organizationName'),
        orgUnit: subjectAttr(leaf.subject, 'organizationalUnitName'),
        locality: subjectAttr(leaf.subject, 'localityName'),
        country: subjectAttr(leaf.subject, 'countryName'),
        san,
        issuer: issuerDn,
        notBefore: leaf.not_valid_before ?? null,
        notAfter: leaf.not_valid_after ?? null,
        keyAlgo: keyAlgo(leaf.public_key?.algorithm),
        keySize: leaf.public_key?.key_size ?? null,
        sigAlgo: leaf.signature_hash_algorithm?.name ?? null,
        serial,
        fingerprintSha256,
        selfSigned: subjectDn != null && subjectDn === issuerDn,
      });
    }
  }
  return out;
}
