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
  reverse(ip: string): Promise<string[]>;
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

const errCode = (e: unknown): string | undefined => (e as { code?: string } | null)?.code;

/**
 * Reverse-resolves each distinct IP. [] = the resolver says there is no PTR,
 * null = unknown (error, timeout, or budget spent), to be retried next run.
 * Only Resolver.reverse is used: c-ares reads the namespace resolv.conf.
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
    const lookup = resolver.reverse(ip).then(
      (names) => sanitizePtrNames(names),
      (e: unknown) => (errCode(e) === 'ENOTFOUND' || errCode(e) === 'ENODATA' ? [] : null),
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
