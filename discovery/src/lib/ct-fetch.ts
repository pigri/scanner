import { extractCtHosts, extractCertspotterHosts } from './ct.js';

export type CtSource = 'crtsh' | 'certspotter' | 'both';

export type FetchImpl = (url: string, init?: RequestInit) => Promise<Response>;
type Sleep = (ms: number) => Promise<void>;
const realSleep: Sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export interface FetchRetryOpts {
  headers?: Record<string, string> | undefined;
  timeoutMs: number;
  /** Extra attempts after the first (default 3). */
  maxRetries?: number | undefined;
  backoffBaseMs?: number | undefined;
  /** Cap on any single wait, so a hostile Retry-After cannot stall a run. */
  maxBackoffMs?: number | undefined;
  fetchImpl?: FetchImpl | undefined;
  sleep?: Sleep | undefined;
  rng?: (() => number) | undefined;
}

/**
 * Parse a Retry-After header value. HTTP allows either a non-negative integer
 * number of seconds or an HTTP date. Returns milliseconds to wait, or null if
 * the header is absent or unparseable (the caller then falls back to backoff).
 */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | null {
  if (value == null) return null;
  const trimmed = value.trim();
  if (trimmed === '') return null;
  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1000;
  const when = Date.parse(trimmed);
  if (Number.isNaN(when)) return null;
  return Math.max(0, when - now);
}

/**
 * fetch() that retries ONLY on HTTP 429, honoring Retry-After when present and
 * otherwise using exponential backoff with jitter. It returns the first
 * non-429 response (ok or not — the caller decides what a non-ok status means)
 * and, once the retry budget is spent, returns the final 429 so the caller can
 * surface it. A 429 is the one status certspotter throttles with; every other
 * failure (timeout, 5xx) propagates as a thrown error or a non-ok response, to
 * be swallowed per-source by queryAll rather than retried here.
 */
export async function fetchWithRetry(url: string, opts: FetchRetryOpts): Promise<Response> {
  const {
    headers,
    timeoutMs,
    maxRetries = 3,
    backoffBaseMs = 1000,
    maxBackoffMs = 30000,
    fetchImpl = fetch,
    sleep = realSleep,
    rng = Math.random,
  } = opts;
  let attempt = 0;
  for (;;) {
    const init: RequestInit = { signal: AbortSignal.timeout(timeoutMs) };
    if (headers) init.headers = headers;
    const res = await fetchImpl(url, init);
    if (res.status !== 429 || attempt >= maxRetries) return res;
    const retryAfter = parseRetryAfter(res.headers.get('retry-after'));
    const backoff = Math.round(backoffBaseMs * 2 ** attempt * (0.5 + rng()));
    const wait = Math.min(maxBackoffMs, retryAfter ?? backoff);
    attempt++;
    await sleep(wait);
  }
}

/** '%.dtr.gov.hu' or '*.dtr.gov.hu' -> 'dtr.gov.hu' (certspotter wants a bare domain). */
export function patternToDomain(pattern: string): string {
  return pattern.replace(/^[%*]\./, '').replace(/^%/, '').trim();
}

export async function queryCrtSh(
  pattern: string,
  opts: { timeoutMs: number; fetchImpl?: FetchImpl },
): Promise<string[]> {
  const url = `https://crt.sh/?q=${encodeURIComponent(pattern)}&output=json`;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const res = await fetchImpl(url, {
    headers: { 'User-Agent': 'discovery/ct-log', Accept: 'application/json' },
    signal: AbortSignal.timeout(opts.timeoutMs),
  });
  if (!res.ok) throw new Error(`crt.sh returned HTTP ${res.status}`);
  const text = await res.text();
  if (!text.trim()) return [];
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`crt.sh returned non-JSON (${text.length}b, likely HTML error page)`);
  }
  return extractCtHosts(json);
}

export async function queryCertspotter(
  pattern: string,
  opts: {
    timeoutMs: number;
    token?: string | undefined;
    fetchImpl?: FetchImpl | undefined;
    sleep?: Sleep | undefined;
    maxRetries?: number | undefined;
    rng?: (() => number) | undefined;
  },
): Promise<string[]> {
  const domain = patternToDomain(pattern);
  const url =
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
    `&include_subdomains=true&expand=dns_names`;
  const headers: Record<string, string> = {
    'User-Agent': 'discovery/ct-log',
    Accept: 'application/json',
  };
  // A free certspotter key lifts the aggressive anonymous rate limit that
  // returns 429 on nearly every query.
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  const res = await fetchWithRetry(url, {
    headers,
    timeoutMs: opts.timeoutMs,
    maxRetries: opts.maxRetries,
    fetchImpl: opts.fetchImpl,
    sleep: opts.sleep,
    rng: opts.rng,
  });
  if (!res.ok) throw new Error(`certspotter returned HTTP ${res.status}`);
  const json = await res.json();
  return extractCertspotterHosts(json);
}

export interface CtDeps {
  crtsh: (pattern: string, timeoutMs: number) => Promise<string[]>;
  certspotter: (pattern: string, timeoutMs: number) => Promise<string[]>;
}

/**
 * Query the requested source(s) for one pattern and return the de-duplicated
 * union. A failing source is logged and skipped, never fatal, so crt.sh being
 * down (it 502'd globally for months) still lets certspotter contribute, and
 * vice versa.
 */
export async function queryAll(
  pattern: string,
  source: CtSource,
  opts: {
    timeoutMs: number;
    crtshEnabled: boolean;
    token?: string | undefined;
    /**
     * Retry budget for certspotter. Retrying only helps with a token: an
     * anonymous 429 is a steady-state rate limit that will not clear within a
     * run, so backing off just wastes wall-clock (× every parent). ct-log
     * passes 0 when no token is set.
     */
    certspotterMaxRetries?: number | undefined;
    log?: ((s: string) => void) | undefined;
    deps?: Partial<CtDeps> | undefined;
  },
): Promise<string[]> {
  const log = opts.log ?? (() => {});
  const crtsh = opts.deps?.crtsh ?? ((p: string, t: number) => queryCrtSh(p, { timeoutMs: t }));
  const certspotter =
    opts.deps?.certspotter ??
    ((p: string, t: number) =>
      queryCertspotter(p, { timeoutMs: t, token: opts.token, maxRetries: opts.certspotterMaxRetries }));

  const all = new Set<string>();
  const attempt = async (name: string, fn: () => Promise<string[]>) => {
    try {
      const hosts = await fn();
      log(`    ${name}: ${hosts.length} hosts`);
      for (const h of hosts) all.add(h);
    } catch (e: unknown) {
      log(`    ${name}: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  if (source === 'crtsh' || source === 'both') {
    if (opts.crtshEnabled) await attempt('crt.sh', () => crtsh(pattern, opts.timeoutMs));
    else log('    crt.sh: SKIPPED (CT_CRTSH_DISABLED set)');
  }
  if (source === 'certspotter' || source === 'both') {
    await attempt('certspotter', () => certspotter(pattern, opts.timeoutMs));
  }
  return [...all];
}
