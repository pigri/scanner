// Pure logic for the local CT mirror: parse an entry from scrape-ct-log's
// JSON output, extract DNS names from the X.509 cert, and decide which
// subset matches our authorised scope suffixes.
//
// scrape-ct-log entry shape (json format):
//   { entry_number: number, timestamp: number (ms), certificate: string (base64 DER) }
// The tree-head envelope arrives once per invocation:
//   { log_url, scrape_begin_timestamp, scrape_end_timestamp, sth: {tree_size, ...}, entries: [...] }
//
// SubjectAltName format from node:crypto's X509Certificate.subjectAltName is
// a comma-separated string like:
//   'DNS:foo.example, DNS:*.foo.example, IP Address:1.2.3.4, DNS:bar.example'
// Only 'DNS:' entries are relevant to us. Wildcards ('*.zone') are treated
// as a match for zone-suffix scope but flagged with is_wildcard.
import { X509Certificate, createHash } from 'node:crypto';

export interface ScrapeEntry {
  entry_number: number;
  timestamp: number;              // ms since epoch
  certificate: string;            // base64 DER
}

export interface ScrapeEnvelope {
  log_url: string;
  scrape_begin_timestamp: number;
  scrape_end_timestamp: number;
  sth: { tree_size: number; timestamp: number };
  entries: ScrapeEntry[];
}

export interface ParsedEntry {
  entryId: number;
  sctAt: string;                  // ISO 8601 from entry.timestamp
  cn: string | null;
  issuerO: string | null;
  certDerSha256: string;          // lowercase hex
  dnsNames: string[];             // lowercased; wildcard prefix retained ('*.foo.example')
}

export interface ScopeMatch {
  dnsName: string;                // lowercased; wildcard '*.' stripped
  isWildcard: boolean;
  matchedSuffix: string;          // canonical form (leading dot stripped)
}

/** Parse a scrape-ct-log entry to a normalised shape. Throws on bad cert. */
export function parseEntry(entry: ScrapeEntry): ParsedEntry {
  const der = Buffer.from(entry.certificate, 'base64');
  const cert = new X509Certificate(der);
  const certDerSha256 = createHash('sha256').update(der).digest('hex');
  return {
    entryId: entry.entry_number,
    sctAt: new Date(entry.timestamp).toISOString(),
    cn: extractCn(cert.subject),
    issuerO: extractO(cert.issuer),
    certDerSha256,
    dnsNames: extractDnsNames(cert),
  };
}

/**
 * Extract CN from an X.509 subject string (multi-line, "CN=...\n...").
 * Some CT entries carry certs whose subject / issuer are empty or absent
 * — node's X509Certificate returns undefined then. Treat that as "no CN"
 * rather than crashing the whole parse.
 */
export function extractCn(subject: string | undefined | null): string | null {
  if (!subject) return null;
  for (const line of subject.split('\n')) {
    if (line.startsWith('CN=')) return line.slice(3).trim().toLowerCase() || null;
  }
  return null;
}

/** Extract Organization (O=) from an X.509 issuer string. Nullable input. */
export function extractO(issuer: string | undefined | null): string | null {
  if (!issuer) return null;
  for (const line of issuer.split('\n')) {
    if (line.startsWith('O=')) return line.slice(2).trim() || null;
  }
  return null;
}

/** Extract lowercased DNS names from SAN + CN, deduplicated. */
export function extractDnsNames(cert: X509Certificate): string[] {
  const names = new Set<string>();
  // SAN is a comma-separated list. dnsNames are ", DNS:..." (with space).
  // Values themselves cannot contain commas/spaces per RFC 1035, so a plain
  // split is safe.
  const san = cert.subjectAltName;
  if (san) {
    for (const raw of san.split(',')) {
      const part = raw.trim();
      if (!part.startsWith('DNS:')) continue;
      const v = part.slice(4).trim().toLowerCase();
      if (v) names.add(v);
    }
  }
  const cn = extractCn(cert.subject);
  if (cn && looksLikeDnsName(cn)) names.add(cn);
  return [...names];
}

/** Very loose DNS-name shape check — CN often contains a full FQDN. */
function looksLikeDnsName(v: string): boolean {
  return /^[a-z0-9*][a-z0-9*.-]*\.[a-z]{2,}$/i.test(v);
}

/**
 * Normalise a scope-suffix line ('.gov.hu' or 'gov.hu' → 'gov.hu').
 * Blank lines and '#'-prefixed comments become null (caller filters).
 * CIDRs (containing '/') are ignored by the CT mirror — CT entries carry no
 * IP addresses that map to our target scope in a useful way.
 */
export function normaliseSuffix(line: string): string | null {
  const t = line.replace(/#.*$/, '').trim().toLowerCase();
  if (!t) return null;
  if (t.includes('/')) return null;         // CIDR — not applicable to CT
  if (!t.includes('.')) return null;        // guard against single-label junk
  return t.replace(/^\./, '');
}

/**
 * Match a DNS name against the suffix list. Returns the LONGEST matching
 * suffix (so 'foo.bar.gov.hu' with scope ['.gov.hu', '.bar.gov.hu'] picks
 * '.bar.gov.hu'). Wildcards on the DNS side ('*.foo.example') match a suffix
 * iff the parent zone ('foo.example') matches — because the wildcard covers
 * every subdomain of that parent.
 */
export function matchScope(dnsName: string, suffixes: readonly string[]): ScopeMatch | null {
  const lower = dnsName.toLowerCase();
  const isWildcard = lower.startsWith('*.');
  const bare = isWildcard ? lower.slice(2) : lower;
  let best: string | null = null;
  for (const suf of suffixes) {
    if (bare === suf || bare.endsWith('.' + suf)) {
      if (best === null || suf.length > best.length) best = suf;
    }
  }
  if (!best) return null;
  return { dnsName: bare, isWildcard, matchedSuffix: best };
}

/**
 * Apply matchScope to a parsed entry's DNS names, deduping by (dnsName,
 * isWildcard). The returned array is what the caller inserts into ct_names.
 */
export function scopedMatches(entry: ParsedEntry, suffixes: readonly string[]): ScopeMatch[] {
  const seen = new Set<string>();
  const out: ScopeMatch[] = [];
  for (const name of entry.dnsNames) {
    const m = matchScope(name, suffixes);
    if (!m) continue;
    const k = `${m.isWildcard ? '*' : '-'}|${m.dnsName}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(m);
  }
  return out;
}
