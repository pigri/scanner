const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function ipv4ToInt(addr: string): number {
  const parts = addr.split('.').map((p) => parseInt(p, 10));
  return (((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!) >>> 0;
}

function intToIpv4(n: number): string {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

export function cidrSize(cidr: string): number {
  const [addr, maskStr] = cidr.split('/');
  if (!addr || !maskStr) return 0;
  const mask = parseInt(maskStr, 10);
  if (!IPV4_RE.test(addr)) return 0;
  if (isNaN(mask) || mask < 0 || mask > 32) return 0;
  return 2 ** (32 - mask);
}

export function* expandCidr(cidr: string): Generator<string, void, unknown> {
  const [addr, maskStr] = cidr.split('/');
  if (!addr || !maskStr) return;
  if (!IPV4_RE.test(addr)) return;
  const mask = parseInt(maskStr, 10);
  if (isNaN(mask) || mask < 0 || mask > 32) return;
  const size = 2 ** (32 - mask);
  const ip = ipv4ToInt(addr) >>> 0;
  const network = mask === 0 ? 0 : ((ip >>> (32 - mask)) << (32 - mask)) >>> 0;
  for (let i = 0; i < size; i++) {
    yield intToIpv4((network + i) >>> 0);
  }
}

export interface PtrResult {
  ip: string;
  ptr: string | null;
}

export function extractHostsFromResults(
  results: readonly PtrResult[],
  suffix: string | null
): string[] {
  const s = suffix ? suffix.toLowerCase().replace(/^\./, '') : null;
  const dotS = s ? `.${s}` : null;
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of results) {
    if (!r.ptr) continue;
    const host = r.ptr.trim().toLowerCase().replace(/\.$/, '');
    if (!host) continue;
    if (s && host !== s && (!dotS || !host.endsWith(dotS))) continue;
    if (!seen.has(host)) {
      seen.add(host);
      out.push(host);
    }
  }
  return out;
}
