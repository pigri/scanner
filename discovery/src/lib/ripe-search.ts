// Pure logic for the RIPE full-text search API. Normalises the somewhat
// verbose response envelope, and provides helpers to pull the interesting
// bits out — CIDRs (from inetnum/inet6num), ASN handles (from aut-num), org
// handles (from organisation), plus country/type filters.
//
// Response shape (docs.strs form):
//   { result: { numFound, docs: [
//       { doc: { strs: [ { str: { name, value } }, ... ] } }, ... ] } }
// Multi-value attributes (descr, nserver) appear as repeated strs entries;
// attrs on the normalised object is Record<key, string[]>.

export interface RipeObject {
  type: string;                       // 'inetnum' | 'inet6num' | 'aut-num' | 'organisation' | ...
  primaryKey: string;
  attrs: Record<string, string[]>;
}

export interface SearchResponse {
  numFound: number;
  docs: RipeObject[];
}

interface StrEntry { str?: { name?: string; value?: string } }
interface DocEntry { doc?: { strs?: StrEntry[] } }
interface RawResponse {
  result?: { numFound?: number; docs?: DocEntry[] };
  response?: { numFound?: number; docs?: DocEntry[] };
}

export function parseSearchResponse(json: unknown): SearchResponse {
  const r = (json as RawResponse | undefined) ?? {};
  const container = r.result ?? r.response ?? {};
  const numFound = container.numFound ?? 0;
  const docs: RipeObject[] = [];
  for (const d of container.docs ?? []) {
    const attrs: Record<string, string[]> = {};
    for (const s of d.doc?.strs ?? []) {
      const name = s.str?.name;
      const value = s.str?.value;
      if (!name || value == null) continue;
      (attrs[name] ??= []).push(value);
    }
    const type = attrs['object-type']?.[0];
    const primaryKey = attrs['primary-key']?.[0] ?? attrs['lookup-key']?.[0] ?? '';
    if (!type) continue;
    docs.push({ type, primaryKey, attrs });
  }
  return { numFound, docs };
}

/** Convert an IPv4 dotted-quad to a 32-bit unsigned integer. */
export function ipv4ToInt(ip: string): number {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) throw new Error(`invalid IPv4: ${ip}`);
  let n = 0;
  for (const p of parts) {
    const x = Number(p);
    if (!Number.isInteger(x) || x < 0 || x > 255) throw new Error(`invalid IPv4: ${ip}`);
    n = (n * 256) + x;
  }
  return n >>> 0;
}

function intToIpv4(n: number): string {
  return [
    Math.floor(n / 16777216) % 256,
    Math.floor(n / 65536) % 256,
    Math.floor(n / 256) % 256,
    n % 256,
  ].join('.');
}

// Count trailing binary zeros using plain integer math — JS bitwise ops
// coerce to 32-bit signed, which breaks for values >= 2^31 (e.g. IPs in
// 128.0.0.0/1). This works for any safe integer.
function trailingZeros(n: number): number {
  if (n === 0) return 32;
  let z = 0;
  while (n % 2 === 0) { n /= 2; z++; }
  return z;
}

/**
 * Decompose `1.2.3.0 - 1.2.3.255` (or a bare CIDR / bare address) into a list
 * of maximal-length CIDR prefixes covering the range exactly. Emits multiple
 * blocks when the range doesn't align to a single prefix.
 */
export function ipv4RangeToCidrs(rangeText: string): string[] {
  const t = rangeText.trim();
  if (t.includes('/')) return [t];
  if (!t.includes('-')) return [`${t}/32`];
  const [aStr, bStr] = t.split('-').map((s) => s.trim());
  const start = ipv4ToInt(aStr!);
  const end = ipv4ToInt(bStr!);
  if (end < start) throw new Error(`inverted range: ${rangeText}`);
  const out: string[] = [];
  let cur = start;
  while (cur <= end) {
    // Two constraints on the max block: alignment (how many trailing zeros
    // cur has → max power-of-2 that divides cur) and size (remaining range).
    const maxByAlign = trailingZeros(cur);
    const remaining = end - cur + 1;
    const maxBySize = Math.floor(Math.log2(remaining));
    const bits = Math.min(maxByAlign, maxBySize);
    const size = 2 ** bits;
    const prefixLen = 32 - bits;
    out.push(`${intToIpv4(cur)}/${prefixLen}`);
    cur += size;
    if (cur > 0xffffffff) break;
  }
  return out;
}

/** Extract CIDR(s) from an inetnum/inet6num object; empty for other types. */
export function extractCidrs(obj: RipeObject): string[] {
  if (obj.type === 'inet6num') {
    const v = obj.attrs['inet6num']?.[0];
    return v ? [v.trim()] : [];
  }
  if (obj.type === 'inetnum') {
    const v = obj.attrs['inetnum']?.[0];
    return v ? ipv4RangeToCidrs(v) : [];
  }
  return [];
}

/** Extract the AS handle from an aut-num object; null otherwise. */
export function extractAsn(obj: RipeObject): string | null {
  if (obj.type !== 'aut-num') return null;
  const v = obj.attrs['aut-num']?.[0];
  return v ? v.trim().toUpperCase() : null;
}

/** Extract the org handle (ORG-XXX-RIPE) from an organisation object. */
export function extractOrg(obj: RipeObject): string | null {
  if (obj.type !== 'organisation') return null;
  return obj.attrs['organisation']?.[0]?.trim() ?? null;
}

/** True when the object's country attribute matches (case-insensitive). */
export function hasCountry(obj: RipeObject, country: string): boolean {
  const want = country.trim().toUpperCase();
  return (obj.attrs['country'] ?? []).some((c) => c.trim().toUpperCase() === want);
}

/** True when the object references the given org handle (org: ORG-...). */
export function hasOrgRef(obj: RipeObject, orgHandle: string): boolean {
  const want = orgHandle.trim().toUpperCase();
  return (obj.attrs['org'] ?? []).some((o) => o.trim().toUpperCase() === want);
}

/**
 * Build the RIPE full-text search endpoint URL for a query. Terms and object
 * types are combined into a single Lucene-style query string; the caller can
 * post-filter with hasCountry / ofType / extractCidrs / etc.
 */
export function buildSearchUrl(
  terms: readonly string[],
  types: readonly string[],
  rows: number,
): string {
  if (!terms.length) throw new Error('at least one search term is required');
  const termClause = terms.map((t) => (t.includes(' ') ? `"${t}"` : t)).join(' OR ');
  const clause = types.length
    ? `(${termClause}) AND (${types.map((t) => `object-type:${t}`).join(' OR ')})`
    : `(${termClause})`;
  const params = new URLSearchParams({ q: clause, wt: 'json', rows: String(rows) });
  return `https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select?${params.toString()}`;
}
