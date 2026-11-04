import { readFileSync } from 'node:fs';
import { fetchWithRetry, type FetchImpl } from './ct-fetch.js';

const BASE = 'https://api.ctlogs.dev';
const DEFAULT_KEY_PATH = '/home/pigri/gen0sec/redteam/.ctlogs';

export interface LoadKeyOpts {
  env?: Record<string, string | undefined> | undefined;
  path?: string | undefined;
}

/**
 * API key from CTLOGS_API_KEY, else the single-line key file. The key is a
 * secret: it must never reach a log line, an error message or a URL.
 */
export function loadKey(opts: LoadKeyOpts = {}): string {
  const env = opts.env ?? process.env;
  const path = opts.path ?? DEFAULT_KEY_PATH;
  const fromEnv = env.CTLOGS_API_KEY?.trim();
  if (fromEnv) return fromEnv;
  let fromFile = '';
  try {
    fromFile = readFileSync(path, 'utf8').trim();
  } catch {
    // fall through to the error below
  }
  if (fromFile) return fromFile;
  throw new Error(`ctlogs.dev API key not found: set CTLOGS_API_KEY or put it in ${path}`);
}

export interface CtlogsOpts {
  key: string;
  fetchImpl?: FetchImpl | undefined;
  timeoutMs?: number | undefined;
  maxRetries?: number | undefined;
  sleep?: ((ms: number) => Promise<void>) | undefined;
  rng?: (() => number) | undefined;
}

export interface SubdomainsOpts extends CtlogsOpts {
  /** Max HTTP requests (retries included) this call may issue. */
  budget: number;
}

export type SubdomainsResult =
  | { ok: true; hosts: string[]; requests: number }
  | { ok: false; reason: 'quota' | 'budget'; hosts: string[]; requests: number };

export interface Usage {
  /** Every numeric field of the /v1/usage response, keyed by dotted path. */
  figures: Record<string, number>;
}

/** Throw an Error that cannot carry the key, whatever the underlying error said. */
function scrubbed(what: string, e: unknown, key: string): Error {
  const raw = e instanceof Error ? e.message : String(e);
  return new Error(`ctlogs ${what} failed: ${raw.split(key).join('[redacted]')}`);
}

async function get(url: string, o: CtlogsOpts, maxRetries: number | undefined): Promise<Response> {
  try {
    return await fetchWithRetry(url, {
      headers: { Authorization: `Bearer ${o.key}`, Accept: 'application/json' },
      timeoutMs: o.timeoutMs ?? 30000,
      maxRetries,
      fetchImpl: o.fetchImpl,
      sleep: o.sleep,
      rng: o.rng,
    });
  } catch (e) {
    throw scrubbed('request', e, o.key);
  }
}

async function json(res: Response, key: string): Promise<unknown> {
  try {
    return await res.json();
  } catch (e) {
    throw scrubbed('response parse', e, key);
  }
}

function pageHosts(body: unknown): string[] {
  const list = (body as { subdomains?: unknown } | null)?.subdomains;
  if (!Array.isArray(list)) return [];
  const out: string[] = [];
  for (const item of list) {
    if (typeof item === 'string') out.push(item);
    else if (item && typeof (item as { name?: unknown }).name === 'string') out.push((item as { name: string }).name);
  }
  return out;
}

/**
 * Paginate GET /v1/subdomains/{zone} via the `after` cursor. Stops when the
 * server returns no cursor (ok), when `budget` requests are spent, or when a
 * 429 survives the retries (quota wall, returned rather than thrown).
 */
export async function fetchSubdomains(zone: string, o: SubdomainsOpts): Promise<SubdomainsResult> {
  const hosts: string[] = [];
  const seen = new Set<string>();
  const counted: FetchImpl = (url, init) => {
    requests++;
    return (o.fetchImpl ?? fetch)(url, init);
  };
  let requests = 0;
  let after: string | null = null;
  for (;;) {
    if (requests >= o.budget) return { ok: false, reason: 'budget', hosts, requests };
    const qs: string = after === null ? '' : `?after=${encodeURIComponent(after)}`;
    const url = `${BASE}/v1/subdomains/${encodeURIComponent(zone)}${qs}`;
    // Retries are requests too: cap them so the budget is a hard ceiling.
    const retries = Math.min(o.maxRetries ?? 3, o.budget - requests - 1);
    const res = await get(url, { ...o, fetchImpl: counted }, retries);
    if (res.status === 429) return { ok: false, reason: 'quota', hosts, requests };
    if (!res.ok) throw new Error(`ctlogs subdomains returned HTTP ${res.status}`);
    const body = await json(res, o.key);
    for (const h of pageHosts(body)) {
      if (!seen.has(h)) {
        seen.add(h);
        hosts.push(h);
      }
    }
    const next = (body as { after?: unknown } | null)?.after;
    if (typeof next !== 'string' || next === '' || next === after) return { ok: true, hosts, requests };
    after = next;
  }
}

function flatten(v: unknown, prefix: string, out: Record<string, number>): void {
  if (typeof v === 'number' && Number.isFinite(v)) {
    out[prefix] = v;
  } else if (v && typeof v === 'object' && !Array.isArray(v)) {
    for (const [k, child] of Object.entries(v)) flatten(child, prefix ? `${prefix}.${k}` : k, out);
  }
}

/** GET /v1/usage: the quota state, as flat numeric figures. */
export async function usage(o: CtlogsOpts): Promise<Usage> {
  const res = await get(`${BASE}/v1/usage`, o, o.maxRetries);
  if (!res.ok) throw new Error(`ctlogs usage returned HTTP ${res.status}`);
  const figures: Record<string, number> = {};
  flatten(await json(res, o.key), '', figures);
  return { figures };
}
