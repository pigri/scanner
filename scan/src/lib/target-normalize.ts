// Target identity normalization.
//
// Different tools store different identity strings for the same host. In
// particular nuclei's PTR templates emit the reverse-DNS pseudo-name
// (e.g. `29.102.206.84.in-addr.arpa`) while httpx/nmap store the IP we scanned
// (`84.206.102.29`). Left unnormalized these become separate rows in the risk
// table — the same host fragmented across identities.
//
// We ONLY canonicalize reverse-DNS pseudo-names back to their IP. We do NOT
// merge forward hostnames onto IPs: several distinct `.gov.hu` vhosts routinely
// share one IP, so collapsing hostname->IP would wrongly fuse different targets
// and corrupt their scores. Hostnames and plain IPs pass through unchanged.

/** Convert a reverse-DNS name to its IP address, or null if it isn't one. */
export function reverseDnsToIp(name: string): string | null {
  const lower = name.trim().toLowerCase().replace(/\.$/, '');

  // IPv4: d.c.b.a.in-addr.arpa  ->  a.b.c.d
  const v4 = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa$/);
  if (v4) {
    const octets = [v4[4]!, v4[3]!, v4[2]!, v4[1]!].map((o) => Number(o));
    if (octets.every((o) => o >= 0 && o <= 255)) return octets.join('.');
    return null;
  }

  // IPv6: 32 reversed nibbles + .ip6.arpa  ->  full 8-hextet address
  const v6 = lower.match(/^((?:[0-9a-f]\.){31}[0-9a-f])\.ip6\.arpa$/);
  if (v6) {
    const nibbles = v6[1]!.split('.').reverse(); // most-significant first
    const hextets: string[] = [];
    for (let i = 0; i < 32; i += 4) hextets.push(nibbles.slice(i, i + 4).join(''));
    return hextets.join(':');
  }

  return null;
}

/**
 * Canonical identity for a scan target. Reverse-DNS pseudo-names collapse to
 * their IP; everything else (hostnames, plain IPs) is returned unchanged.
 */
export function canonicalizeTarget(target: string): string {
  return reverseDnsToIp(target) ?? target;
}
