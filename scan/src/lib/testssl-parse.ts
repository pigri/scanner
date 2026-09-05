// Normalize a testssl.sh JSON record into a finding row.
//
// testssl records look like { id, severity, finding }, where `id` is the CHECK
// NAME (cert_expirationStatus, POODLE_SSL, SSLv3, overall_grade, ...) and
// `finding` is the VALUE/detail (expired, "VULNERABLE, uses SSLv3+CBC", "T").
// The old code used `finding` as the title, producing garbage like "T",
// "expired", "2018-11-04 13:27". The title must be built from the id (the
// meaningful label) with the finding as detail.

export interface TestsslRecord { id?: string; severity?: string; finding?: string; cve?: string }
export interface NormalizedFinding { category: string; severity: string; title: string; cve: string | null }

// Only these severities become findings; OK/INFO/WARN/DEBUG are dropped.
const ACTIONABLE = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

// Non-distinct/redundant checks we drop even at actionable severity, so counts
// reflect real distinct issues:
//   overall_grade   — a summary of the other findings, not its own vuln
//   cert_notAfter   — the expiry date; redundant with cert_expirationStatus and
//                     now captured structurally in the certificates table
//   cert_notBefore  — a date fact, belongs in the cert inventory
const NOISE_IDS = new Set(['overall_grade', 'cert_notAfter', 'cert_notBefore']);

/** True if this record is a redundant/summary check we don't store as a finding. */
export function isNoiseFinding(id: string): boolean {
  return NOISE_IDS.has(id.replace(/\s*<hostCert#\d+>\s*$/, '').trim());
}

// Severity overrides for testssl categories where upstream mis-classifies the
// real impact. testssl.sh calls certificate CHAIN-QUALITY deviations CRITICAL
// (chain-of-trust failure, self-signed CA, expired intermediate) — but those
// are functional/interop issues: modern browsers still work, JVM/mobile SDK
// clients break. They are NOT credential-theft or code-execution vectors, so
// they should not outrank real EOL-product / RCE / auth-bypass findings.
//
// Real cryptographic vulnerabilities (Heartbleed/ROBOT/CCS injection) are
// covered by sslyze with proper CRITICAL classification and are not affected
// by these overrides.
//
// Applied by normalizeTestsslFinding before emitting the row.
const SEVERITY_OVERRIDES: Record<string, string> = {
  // Chain-of-trust family — downgrade from testssl's CRITICAL to MEDIUM.
  cert_chain_of_trust: 'medium',
  cert_trust: 'medium',
  // End-entity expiry: "expired" and "expires < 15 days" — real ops issue but
  // functional (browsers show a warning users bypass), not compromise.
  cert_expirationStatus: 'medium',
  // Intermediate cert expiry-adjacent: also functional, not compromise.
  intermediate_cert_expiration: 'medium',
  intermediate_cert_notAfter: 'low',
  // SAN mismatch: cert doesn't cover the hostname — functional TLS issue.
  cert_subjectAltName: 'medium',
  // Missing CRL/OCSP URI: revocation-checking gap, not itself compromise.
  cert_revocation: 'low',
  // Insecure redirect (302 to http://): downgrade — real but common misconfig,
  // covered by our headers audit + testssl still emits it.
  insecure_redirect: 'medium',
};

/** Human-friendly names for a few common ids; others fall back to the raw id. */
const ID_LABELS: Record<string, string> = {
  cert_expirationStatus: 'Certificate expiration',
  cert_notAfter: 'Certificate valid-until',
  cert_chain_of_trust: 'Certificate chain of trust',
  cert_trust: 'Certificate trust',
  overall_grade: 'Overall TLS grade',
  POODLE_SSL: 'POODLE (SSLv3)',
  fallback_SCSV: 'TLS_FALLBACK_SCSV',
  LOGJAM_common_primes: 'LOGJAM common DH primes',
  'LOGJAM-common_primes': 'LOGJAM common DH primes',
  SWEET32: 'SWEET32 (64-bit block ciphers)',
  cipherlist_LOW: 'Low-strength cipher suites',
  cipherlist_3DES_IDEA: '3DES/IDEA cipher suites',
  cipherlist_OBSOLETED: 'Obsoleted cipher suites',
};

/**
 * Convert a raw testssl record to a normalized finding, or null if its severity
 * is not actionable. Title is "<label>: <finding>" so it reads clearly and the
 * severity/count stay trustworthy.
 */
export function normalizeTestsslFinding(rec: TestsslRecord): NormalizedFinding | null {
  const sev = (rec.severity || '').trim().toUpperCase();
  if (!ACTIONABLE.has(sev)) return null;

  const rawId = (rec.id || 'tls_issue').trim();
  if (isNoiseFinding(rawId)) return null; // redundant/summary check — not a distinct finding
  const id = rawId.replace(/\s*<hostCert#\d+>\s*$/, '').trim(); // drop multi-cert suffix
  const label = ID_LABELS[id] ?? id;
  const finding = (rec.finding || '').replace(/\s+/g, ' ').trim();
  const title = (finding ? `${label}: ${finding}` : label).slice(0, 200);

  // Apply the category-based severity override, if any. Preserves testssl's
  // upstream call for anything not on the list (so real crypto vulns keep
  // their critical/high).
  const severity = SEVERITY_OVERRIDES[id] ?? sev.toLowerCase();

  return { category: id, severity, title, cve: rec.cve ?? null };
}
