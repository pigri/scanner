import dns from 'node:dns';

const MAX_NAMES = 5;
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Reverse-DNS names are attacker-controlled: keep only plain hostnames. */
export function sanitizePtrNames(names: unknown): string[] {
  if (!Array.isArray(names)) return [];
  const out: string[] = [];
  for (const n of names) {
    if (typeof n !== 'string') continue;
    const name = (n.endsWith('.') ? n.slice(0, -1) : n).toLowerCase();
    if (name.length === 0 || name.length > 253) continue;
    if (!name.split('.').every((l) => LABEL.test(l))) continue;
    if (out.includes(name)) continue;
    out.push(name);
    if (out.length === MAX_NAMES) break;
  }
  return out;
}

export interface PtrResolver {
  resolvePtr(name: string): Promise<string[]>;
  cancel?(): void;
}

export interface LookupPtrsOpts {
  timeoutMs?: number;
  concurrency?: number;
  budgetMs: number;
  resolver?: PtrResolver;
  now?: () => number;
  /** Filled in: how many IPs were never started because the budget ran out. */
  stats?: { skippedByBudget: number };
}

/** The in-addr.arpa / ip6.arpa name for a normalised IP (lower-case, `::` compressed, no embedded IPv4). */
export function arpaName(ip: string): string {
  if (!ip.includes(':')) return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
  const halves = ip.split('::');
  const part = (x: string | undefined): string[] => (x ? x.split(':') : []);
  const head = part(halves[0]);
  const tail = part(halves[1]);
  const fill = new Array<string>(Math.max(0, 8 - head.length - tail.length)).fill('0');
  const nibbles = [...head, ...fill, ...tail].map((g) => g.padStart(4, '0')).join('');
  return `${nibbles.split('').reverse().join('.')}.ip6.arpa`;
}

/**
 * [] only when the server says the name does not exist or has no PTR record.
 * Every other failure is unknown (null), so a transient error never wipes stored names.
 */
export function ptrOutcome(err: unknown): [] | null {
  const code = (err as { code?: unknown } | null)?.code;
  return code === 'ENOTFOUND' || code === 'ENODATA' ? [] : null;
}

/**
 * Resolves the PTR record of each distinct IP. [] = the resolver says there is no PTR,
 * null = unknown (error, timeout, or budget spent), to be retried next run.
 * Only Resolver#resolvePtr on the arpa name is used (Resolver#reverse reports every
 * failure as ENOTFOUND and reads /etc/hosts); c-ares reads the namespace resolv.conf.
 */
export async function lookupPtrs(ips: readonly string[], opts: LookupPtrsOpts): Promise<Map<string, string[] | null>> {
  const timeoutMs = opts.timeoutMs ?? 3000;
  const concurrency = Math.max(1, opts.concurrency ?? 10);
  const now = opts.now ?? Date.now;
  const queue = [...new Set(ips)];
  const result = new Map<string, string[] | null>(queue.map((ip) => [ip, null]));
  if (opts.stats) opts.stats.skippedByBudget = 0;
  if (queue.length === 0) return result;

  const resolver: PtrResolver = opts.resolver ?? new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 });
  const start = now();
  let next = 0;

  const one = async (ip: string): Promise<string[] | null> => {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<null>((res) => { timer = setTimeout(() => res(null), timeoutMs); });
    const lookup = Promise.resolve().then(() => resolver.resolvePtr(arpaName(ip))).then(
      (names) => sanitizePtrNames(names),
      (e: unknown) => ptrOutcome(e),
    );
    try { return await Promise.race([lookup, timeout]); }
    finally { clearTimeout(timer); }
  };

  const worker = async (): Promise<void> => {
    while (next < queue.length) {
      if (now() - start >= opts.budgetMs) return;
      const ip = queue[next++]!;
      result.set(ip, await one(ip));
    }
  };

  try {
    await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
  } finally {
    // Drop any query a timeout abandoned so it cannot keep the event loop alive.
    resolver.cancel?.();
  }
  if (opts.stats) opts.stats.skippedByBudget = queue.length - next;
  return result;
}
