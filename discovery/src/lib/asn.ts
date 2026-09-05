export function normalizeAsn(input: string): string {
  const s = String(input).trim().toUpperCase();
  const match = /^(?:AS)?(\d+)$/.exec(s);
  if (!match) throw new Error(`invalid ASN: ${input}`);
  return `AS${match[1]}`;
}

interface RipePrefixEntry {
  prefix?: unknown;
}

interface RipeResponse {
  data?: { prefixes?: readonly RipePrefixEntry[] };
}

export function extractPrefixes(response: unknown): string[] {
  if (!response || typeof response !== 'object') return [];
  const r = response as RipeResponse;
  const arr = r.data?.prefixes;
  if (!Array.isArray(arr)) return [];
  const out: string[] = [];
  for (const entry of arr) {
    if (entry && typeof entry === 'object' && typeof entry.prefix === 'string') {
      out.push(entry.prefix);
    }
  }
  return out;
}

export function familyOf(cidr: string): 4 | 6 | null {
  const slash = cidr.indexOf('/');
  const addr = slash === -1 ? cidr : cidr.slice(0, slash);
  if (/^[0-9.]+$/.test(addr) && addr.includes('.')) return 4;
  if (addr.includes(':')) return 6;
  return null;
}

function ipv4ToInt(addr: string): number {
  const parts = addr.split('.').map((p) => parseInt(p, 10));
  return ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!;
}

function comparePrefixes(a: string, b: string): number {
  const fa = familyOf(a);
  const fb = familyOf(b);
  if (fa !== fb) return (fa ?? 9) - (fb ?? 9);
  if (fa === 4 && fb === 4) {
    const [addrA, maskA] = a.split('/') as [string, string | undefined];
    const [addrB, maskB] = b.split('/') as [string, string | undefined];
    const diff = ipv4ToInt(addrA) - ipv4ToInt(addrB);
    if (diff !== 0) return diff;
    return parseInt(maskA ?? '32', 10) - parseInt(maskB ?? '32', 10);
  }
  return a.localeCompare(b);
}

export interface DedupeOpts {
  sort?: boolean;
}

export function dedupePrefixes(input: readonly string[], opts: DedupeOpts = {}): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of input) {
    if (!seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  }
  return opts.sort ? out.slice().sort(comparePrefixes) : out;
}
