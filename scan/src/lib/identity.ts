// Target identity resolution: fold IP-keyed rows onto a hostname when the scan
// unambiguously ties them together.
//
// Builds on canonicalizeTarget (reverse-DNS -> IP). On top of that we apply the
// "prefer hostname" policy: when the scan establishes that IP Y belongs to
// hostname H (e.g. nmap stored target=H with ip=Y), IP-keyed findings for Y are
// folded onto H so the host stops appearing as two rows.
//
// SAFETY: we only fold when Y maps to EXACTLY ONE hostname in the scan. If two
// vhosts (a.gov.hu, b.gov.hu) share one IP, an IP-only finding can't be
// attributed to either, so we leave the bare IP as its own identity.
import { canonicalizeTarget, reverseDnsToIp } from './target-normalize.js';

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpAddress(s: string): boolean {
  const v4 = s.match(IPV4);
  if (v4) return [v4[1]!, v4[2]!, v4[3]!, v4[4]!].every((o) => Number(o) <= 255);
  // IPv6: at least one ':' and only hex digits / colons (accepts compressed ::)
  if (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s) && !s.includes(':::')) return true;
  return false;
}

export interface TargetIpPair { target: string; ip: string | null }

/**
 * Build a resolver that maps any raw target string to its canonical identity.
 *
 * Resolution order for a target T:
 *   1. canonicalizeTarget(T)        // reverse-DNS pseudo-name -> IP
 *   2. if the result is an IP that the scan ties to exactly one hostname,
 *      return that hostname                        // prefer-hostname fold
 *   3. otherwise return the canonicalized value.
 */
export function buildTargetResolver(pairs: TargetIpPair[]): (target: string) => string {
  // ip -> set of hostnames the scan associates with it
  const ipToHosts = new Map<string, Set<string>>();
  for (const { target, ip } of pairs) {
    if (!ip || !isIpAddress(ip)) continue;
    // the hostname side must be an actual hostname, not the IP itself and not a
    // reverse-DNS pseudo-name (those canonicalize back to an IP, not a host).
    if (target === ip || isIpAddress(target) || reverseDnsToIp(target)) continue;
    if (!ipToHosts.has(ip)) ipToHosts.set(ip, new Set());
    ipToHosts.get(ip)!.add(target);
  }

  // Precompute the unambiguous ip -> host folds (exactly one hostname).
  const fold = new Map<string, string>();
  for (const [ip, hosts] of ipToHosts) {
    if (hosts.size === 1) fold.set(ip, [...hosts][0]!);
  }

  return (target: string): string => {
    const canon = canonicalizeTarget(target);
    if (isIpAddress(canon) && fold.has(canon)) return fold.get(canon)!;
    return canon;
  };
}
