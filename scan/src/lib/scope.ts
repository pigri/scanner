export interface Cidr {
  raw: string;
  family: 4 | 6;
  network: bigint;
  prefix: number;
}

export interface Scope {
  suffixes: string[];
  cidrs: Cidr[];
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function ipv4ToBigInt(addr: string): bigint {
  const parts = addr.split('.').map((p) => BigInt(parseInt(p, 10)));
  return (parts[0]! << 24n) | (parts[1]! << 16n) | (parts[2]! << 8n) | parts[3]!;
}

function ipv6ToBigInt(addr: string): bigint {
  const [head, tail] = addr.includes('::') ? addr.split('::') : [addr, ''];
  const headParts = head ? head.split(':') : [];
  const tailParts = tail ? tail.split(':') : [];
  const fill = 8 - headParts.length - tailParts.length;
  const groups = [
    ...headParts,
    ...Array(Math.max(0, fill)).fill('0'),
    ...tailParts,
  ];
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(parseInt(g || '0', 16));
  return n;
}

function parseCidr(raw: string): Cidr | null {
  const [addr, maskStr] = raw.split('/');
  if (!addr || maskStr === undefined) return null;
  const prefix = parseInt(maskStr, 10);
  if (isNaN(prefix)) return null;
  if (IPV4_RE.test(addr)) {
    const ip = ipv4ToBigInt(addr);
    const shift = BigInt(32 - prefix);
    return { raw, family: 4, network: (ip >> shift) << shift, prefix };
  }
  if (addr.includes(':') && IPV6_RE.test(addr)) {
    const ip = ipv6ToBigInt(addr);
    const shift = BigInt(128 - prefix);
    return { raw, family: 6, network: (ip >> shift) << shift, prefix };
  }
  return null;
}

export function parseScope(text: string): Scope {
  const suffixes: string[] = [];
  const cidrs: Cidr[] = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.includes('/')) {
      const c = parseCidr(line);
      if (c) cidrs.push(c);
      continue;
    }
    const suffix = line.toLowerCase().replace(/^\./, '');
    if (suffix) suffixes.push(suffix);
  }
  return { suffixes, cidrs };
}

function isIp(target: string): 4 | 6 | null {
  if (IPV4_RE.test(target)) return 4;
  if (target.includes(':') && IPV6_RE.test(target)) return 6;
  return null;
}

export function inScope(target: string, scope: Scope): boolean {
  const t = target.trim();
  if (!scope.suffixes.length && !scope.cidrs.length) return true;
  const family = isIp(t);
  if (family) {
    const ip = family === 4 ? ipv4ToBigInt(t) : ipv6ToBigInt(t);
    for (const c of scope.cidrs) {
      if (c.family !== family) continue;
      const bits = family === 4 ? 32 : 128;
      const shift = BigInt(bits - c.prefix);
      if ((ip >> shift) << shift === c.network) return true;
    }
    return false;
  }
  const host = t.toLowerCase().replace(/^www\./, '');
  for (const s of scope.suffixes) {
    if (host === s || host.endsWith(`.${s}`)) return true;
  }
  return false;
}

export interface CheckResult {
  inScope: string[];
  outOfScope: string[];
}

export function checkTargets(targets: readonly string[], scope: Scope): CheckResult {
  const inS: string[] = [];
  const out: string[] = [];
  for (const t of targets) {
    if (inScope(t, scope)) inS.push(t);
    else out.push(t);
  }
  return { inScope: inS, outOfScope: out };
}
