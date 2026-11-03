import dns from 'node:dns/promises';

/**
 * Pinned public resolvers used by default. Recon DNS does not need to egress
 * through the scan VPN, and the system/VPN resolver rate-limits under the
 * enrich concurrency, which used to evict live hosts on transient failures.
 */
export const DEFAULT_RESOLVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

/** The subset of dns.Resolver this module needs — lets tests inject a stub. */
export interface ResolverLike {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  reverse(ip: string): Promise<string[]>;
}

// c-ares / node error codes that mean "the answer is authoritatively negative"
// — the name genuinely has no such record. Retrying these is pointless.
const AUTHORITATIVE_NEGATIVE = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN', 'NODATA']);

/**
 * Should a failed lookup be retried? Transient infrastructure failures
 * (timeout, SERVFAIL, REFUSED, connection resets) are retryable; an
 * authoritative "no such record" is not. Unknown codes are treated as
 * transient — a missed retry only costs one more lookup, but a wrong
 * eviction loses a live host.
 */
export function isRetryableDnsError(err: { code?: string; message?: string }): boolean {
  if (err.code && AUTHORITATIVE_NEGATIVE.has(err.code)) return false;
  // Synthetic timeout (withTimeout) carries no code.
  if (!err.code && /timeout/i.test(err.message ?? '')) return true;
  return true;
}

/** Round-robins lookups across one dedicated resolver per configured server. */
export class ResolverPool {
  private readonly resolvers: ResolverLike[];
  private idx = 0;

  constructor(servers: string[] | null) {
    if (servers && servers.length) {
      this.resolvers = servers.map((s) => {
        const r = new dns.Resolver();
        r.setServers([s]);
        return r;
      });
    } else {
      // No override: a single resolver using the OS-configured servers.
      this.resolvers = [new dns.Resolver()];
    }
  }

  get size(): number {
    return this.resolvers.length;
  }

  next(): ResolverLike {
    const r = this.resolvers[this.idx % this.resolvers.length]!;
    this.idx++;
    return r;
  }
}

export interface ResolveOpts {
  ipv6: boolean;
  maxTries: number;
  timeoutMs: number;
  backoffMs?: number;
}

export interface HostResolution {
  a: string[];
  aaaa: string[];
  errors: string[];
}

type Sleep = (ms: number) => Promise<void>;
const realSleep: Sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, rej) => setTimeout(() => rej(new Error(`${label} timeout`)), ms)),
  ]);
}

/** Resolve one record type with bounded retry, rotating a resolver per attempt. */
async function resolveRecord(
  name: string,
  kind: 'A' | 'AAAA',
  pool: { next(): ResolverLike },
  opts: ResolveOpts,
  sleep: Sleep,
): Promise<{ records: string[]; error?: string }> {
  let last: (Error & { code?: string }) | null = null;
  for (let attempt = 1; attempt <= opts.maxTries; attempt++) {
    const r = pool.next();
    try {
      const recs = await withTimeout(
        kind === 'A' ? r.resolve4(name) : r.resolve6(name),
        opts.timeoutMs,
        kind,
      );
      return { records: recs };
    } catch (e) {
      const errObj = e as Error & { code?: string };
      last = errObj;
      if (!isRetryableDnsError(errObj)) {
        return { records: [], error: `${kind}:${errObj.code || errObj.message}` };
      }
      if (attempt < opts.maxTries) {
        await sleep((opts.backoffMs ?? 150) * attempt);
      }
    }
  }
  return { records: [], error: `${kind}:${last?.code || last?.message || 'failed'}` };
}

/**
 * Resolve a host to its A (and optionally AAAA) records, with retry. A host is
 * considered resolvable if either record type returns an address. Never
 * rejects — failures surface in `errors`.
 */
export async function resolveHost(
  name: string,
  pool: { next(): ResolverLike },
  opts: ResolveOpts,
  sleep: Sleep = realSleep,
): Promise<HostResolution> {
  const [a, aaaa] = await Promise.all([
    resolveRecord(name, 'A', pool, opts, sleep),
    opts.ipv6
      ? resolveRecord(name, 'AAAA', pool, opts, sleep)
      : Promise.resolve<{ records: string[]; error?: string }>({ records: [] }),
  ]);
  const errors: string[] = [];
  if (a.error) errors.push(a.error);
  if (aaaa.error) errors.push(aaaa.error);
  return { a: a.records, aaaa: aaaa.records, errors };
}

/** Reverse-lookup an IP (best-effort, no retry — PTR is advisory). */
export async function reverseIp(
  ip: string,
  pool: { next(): ResolverLike },
  timeoutMs: number,
): Promise<string[]> {
  try {
    return await withTimeout(pool.next().reverse(ip), timeoutMs, 'PTR');
  } catch {
    return [];
  }
}
