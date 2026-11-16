import net from 'node:net';

export type IpClass =
  | 'public' | 'private' | 'cgnat' | 'loopback' | 'link-local'
  | 'multicast' | 'unspecified' | 'reserved';

export interface NormalizedIp { ip: string; version: 4 | 6 }

/** Canonical text form of an IP, or null when `raw` is not a bare IP address. IPv4-mapped IPv6 becomes IPv4. */
export function normalizeIp(raw: string): NormalizedIp | null {
  let s = raw.trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct);
  const kind = net.isIP(s);
  if (kind === 4) return { ip: s, version: 4 };
  if (kind !== 6) return null;
  // The WHATWG URL serializer yields lower-case, zero-compressed IPv6; net.isIP has already vetted the input.
  const host = new URL(`http://[${s}]`).hostname;
  const groups = expand(host.slice(1, -1));
  if (!groups) return null;
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const hi = groups[6]!, lo = groups[7]!;
    return { ip: `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`, version: 4 };
  }
  return { ip: host.slice(1, -1), version: 6 };
}

function expand(canonical: string): number[] | null {
  const halves = canonical.split('::');
  if (halves.length > 2) return null;
  const parse = (part: string): number[] => (part === '' ? [] : part.split(':').map((g) => parseInt(g, 16)));
  const head = parse(halves[0]!);
  const tail = halves.length === 2 ? parse(halves[1]!) : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  const groups = [...head, ...new Array<number>(fill).fill(0), ...tail];
  return groups.length === 8 && groups.every((g) => Number.isInteger(g)) ? groups : null;
}

/** Documentation ranges are deliberately `public`: scans of lab data stay representable. */
export function classifyIp(ip: string): IpClass {
  const n = normalizeIp(ip);
  if (!n) return 'reserved';
  if (n.version === 4) {
    const [a, b] = n.ip.split('.').map(Number) as [number, number, number, number];
    if (a === 0) return 'unspecified';
    if (a === 10) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
    if (a === 127) return 'loopback';
    if (a === 169 && b === 254) return 'link-local';
    if (a === 172 && b >= 16 && b <= 31) return 'private';
    if (a === 192 && b === 168) return 'private';
    if (a >= 224 && a <= 239) return 'multicast';
    if (a >= 240) return 'reserved';
    return 'public';
  }
  const g = expand(n.ip)!;
  if (g.every((x) => x === 0)) return 'unspecified';
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return 'loopback';
  const first = g[0]!;
  if ((first & 0xfe00) === 0xfc00) return 'private';
  if ((first & 0xffc0) === 0xfe80) return 'link-local';
  if ((first & 0xff00) === 0xff00) return 'multicast';
  return 'public';
}
