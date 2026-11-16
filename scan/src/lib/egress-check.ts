import fs from 'node:fs';
import dns from 'node:dns';
import net from 'node:net';
import { openGeo, DEFAULT_MMDB, type GeoLookup } from './geoip.js';

// Preflight checks for a worker that must scan from inside a network namespace.
// A worker joins its namespace only at start, so when the namespace is replaced
// the process keeps running in the old, deleted one. The netns check detects that;
// the DNS check detects a namespace whose resolver or tunnel is not working.

export interface NetnsDeps {
  statIno: (path: string) => number;
  readlink: (path: string) => string;
}

export type NetnsResult =
  | { status: 'ok' }
  | { status: 'mismatch'; expected: number; actual: number }
  | { status: 'error'; reason: string };

const defaultNetnsDeps: NetnsDeps = {
  statIno: (p) => fs.statSync(p).ino,
  readlink: (p) => fs.readlinkSync(p),
};

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e));

// `expected` is the inode of /run/netns/<name>; `actual` is the namespace this
// process is in, parsed from the "net:[NNN]" link.
export function checkNetns(name: string, deps: NetnsDeps = defaultNetnsDeps): NetnsResult {
  if (!name || name.includes('/') || name.includes('..')) return { status: 'error', reason: `invalid netns name ${JSON.stringify(name)}` };
  let expected: number;
  let link: string;
  try {
    expected = deps.statIno(`/run/netns/${name}`);
    link = deps.readlink('/proc/self/ns/net');
  } catch (e) {
    return { status: 'error', reason: errMsg(e) };
  }
  const m = /^net:\[(\d+)\]$/.exec(link);
  if (!m) return { status: 'error', reason: `unparsable /proc/self/ns/net link ${JSON.stringify(link)}` };
  const actual = Number(m[1]);
  return actual === expected ? { status: 'ok' } : { status: 'mismatch', expected, actual };
}

export interface DnsDeps {
  resolve: (host: string) => Promise<unknown>;
  cancel?: () => void;
}

export type DnsResult = { status: 'ok' } | { status: 'fail'; reason: string } | { status: 'timeout' };

// c-ares reads resolv.conf and queries the nameservers itself. getaddrinfo
// (dns.lookup) would also run nsswitch modules, which can reach a resolver over
// a unix socket on the host and so succeed from the wrong namespace. Only A
// records are probed: the probe tests that the namespace has a working resolver
// path, not which address families the target has.
function defaultDnsDeps(timeoutMs: number): DnsDeps {
  const r = new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 });
  return { resolve: (h) => r.resolve4(h), cancel: () => r.cancel() };
}

export async function checkDns(host: string, timeoutMs: number, deps: DnsDeps = defaultDnsDeps(timeoutMs)): Promise<DnsResult> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<DnsResult>((res) => { timer = setTimeout(() => { deps.cancel?.(); res({ status: 'timeout' }); }, timeoutMs); });
  const lookup = (async (): Promise<DnsResult> => {
    try { await deps.resolve(host); return { status: 'ok' }; }
    catch (e) { return { status: 'fail', reason: errMsg(e) }; }
  })();
  try { return await Promise.race([lookup, timeout]); }
  finally { clearTimeout(timer); }
}

export type PreflightResult =
  | { action: 'ok' }
  | { action: 'retry'; reason: string }
  | { action: 'restart'; reason: string };

export interface PreflightOpts {
  netns: string | null;
  dnsProbe: string;
  timeoutMs: number;
  country?: CountryOpts | null;
  deps?: { netns?: NetnsDeps; dns?: DnsDeps; country?: CountryDeps };
}

// Country check: the netns check proves which namespace the process is in, not
// where that namespace's traffic leaves. This asks an IP-echo service what the
// public address is and looks its country up. Every failure is a failure of the
// check, never a pass. The address itself is never put in a result or a log.

export interface CountryOpts {
  country: string | null;
  notCountry: string | null;
  echoUrl: string;
  mmdb: string;
}

export interface CountryDeps {
  fetch?: typeof fetch;
  openGeo?: (file: string) => Promise<GeoLookup | null>;
  now?: () => number;
  timeoutMs?: number;
}

export type CountryResult = { status: 'ok'; country: string } | { status: 'fail'; reason: string };

export const DEFAULT_ECHO_URL = 'https://api.ipify.org';
export const COUNTRY_RECHECK_MS = 10 * 60_000;
export const COUNTRY_FETCH_TIMEOUT_MS = 10_000;

export function normalizeCountryCode(cc: string): string {
  const u = (cc ?? '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(u)) throw new Error(`invalid country code ${JSON.stringify(cc)}: expected two letters`);
  return u;
}

export function countryCheckEnabled(o: { country: string | null; notCountry: string | null }): boolean {
  return Boolean(o.country || o.notCountry);
}

async function fetchPublicIp(url: string, f: typeof fetch, timeoutMs: number): Promise<{ ip: string } | { fail: string }> {
  try {
    const res = await f(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return { fail: `echo service answered HTTP ${res.status}` };
    const ip = (await res.text()).trim();
    if (net.isIP(ip) === 0) return { fail: 'echo service did not return an IP address' };
    return { ip };
  } catch (e) {
    const name = e instanceof Error ? e.name : '';
    return { fail: name === 'TimeoutError' || name === 'AbortError' ? 'echo request timed out' : 'echo request failed' };
  }
}

export async function checkEgressCountry(o: CountryOpts, deps: CountryDeps = {}): Promise<CountryResult> {
  const got = await fetchPublicIp(o.echoUrl, deps.fetch ?? fetch, deps.timeoutMs ?? COUNTRY_FETCH_TIMEOUT_MS);
  if ('fail' in got) return { status: 'fail', reason: got.fail };
  const geo = await (deps.openGeo ?? ((f: string) => openGeo(f)))(o.mmdb);
  if (!geo) return { status: 'fail', reason: `no usable country database at ${o.mmdb}` };
  const cc = geo.get(got.ip)?.country_code?.toUpperCase();
  if (!cc) return { status: 'fail', reason: 'egress country unknown' };
  if (o.country && cc !== o.country) return { status: 'fail', reason: `egress country is ${cc}, must be ${o.country}` };
  if (o.notCountry && cc === o.notCountry) return { status: 'fail', reason: `egress country is ${cc}, must not be ${o.notCountry}` };
  return { status: 'ok', country: cc };
}

// A pass is trusted for COUNTRY_RECHECK_MS; after a failure every call checks again.
export function makeCountryGate(o: CountryOpts, deps: CountryDeps = {}): () => Promise<CountryResult> {
  const now = deps.now ?? Date.now;
  let passedAt: number | null = null;
  let last: CountryResult | null = null;
  return async () => {
    if (passedAt !== null && last && now() - passedAt < COUNTRY_RECHECK_MS) return last;
    const r = await checkEgressCountry(o, deps);
    if (r.status === 'ok') { passedAt = now(); last = r; } else { passedAt = null; last = null; }
    return r;
  };
}

// A wrong or missing namespace cannot heal in this process, so it asks for a
// restart. A DNS problem may clear by itself, so it asks to wait and try again.
export function makePreflight(o: PreflightOpts): () => Promise<PreflightResult> {
  const gate = o.country ? makeCountryGate(o.country, o.deps?.country) : null;
  return async () => {
    if (o.netns) {
      const n = checkNetns(o.netns, o.deps?.netns);
      if (n.status === 'mismatch') return { action: 'restart', reason: `running in netns inode ${n.actual}, but ${o.netns} is now inode ${n.expected}` };
      if (n.status === 'error') return { action: 'restart', reason: `netns ${o.netns} check failed: ${n.reason}` };
      const d = await checkDns(o.dnsProbe, o.timeoutMs, o.deps?.dns);
      if (d.status === 'fail') return { action: 'retry', reason: `dns probe ${o.dnsProbe} failed: ${d.reason}` };
      if (d.status === 'timeout') return { action: 'retry', reason: `dns probe ${o.dnsProbe} timed out after ${o.timeoutMs} ms` };
    }
    if (gate) {
      const c = await gate();
      if (c.status === 'fail') return { action: 'retry', reason: `egress country check failed: ${c.reason}` };
    }
    return { action: 'ok' };
  };
}

export type PostBatchResult = { action: 'ok' } | { action: 'restart'; reason: string };

// Run after a batch, before its rows are marked: netns and country, no DNS, so a
// resolver hiccup cannot throw away a finished batch. A replaced namespace or a
// wrong egress country means the batch ran from the wrong place and its result
// cannot be trusted. The country check is not gated here.
export function postBatchFromOpts(
  o: { netns: string | null; egressCountry?: string | null; egressNotCountry?: string | null; egressEchoUrl?: string; mmdb?: string },
  deps?: { netns?: NetnsDeps; country?: CountryDeps },
): (() => Promise<PostBatchResult>) | undefined {
  const name = o.netns;
  const cOpts = countryOptsFrom(o);
  if (!name && !cOpts) return undefined;
  return async () => {
    if (name) {
      const n = checkNetns(name, deps?.netns);
      if (n.status === 'mismatch') return { action: 'restart', reason: `batch ran in netns inode ${n.actual}, but ${name} is now inode ${n.expected}` };
      if (n.status === 'error') return { action: 'restart', reason: `netns ${name} check failed after the batch: ${n.reason}` };
    }
    if (cOpts) {
      const c = await checkEgressCountry(cOpts, deps?.country);
      if (c.status === 'fail') return { action: 'restart', reason: `egress country check failed after the batch: ${c.reason}` };
    }
    return { action: 'ok' };
  };
}

function countryOptsFrom(o: { egressCountry?: string | null; egressNotCountry?: string | null; egressEchoUrl?: string; mmdb?: string }): CountryOpts | null {
  const country = o.egressCountry ?? null;
  const notCountry = o.egressNotCountry ?? null;
  if (!countryCheckEnabled({ country, notCountry })) return null;
  return { country, notCountry, echoUrl: o.egressEchoUrl ?? DEFAULT_ECHO_URL, mmdb: o.mmdb ?? DEFAULT_MMDB };
}

export const EXIT_RESTART = 75; // EX_TEMPFAIL: non-zero, so Restart=on-failure starts a fresh worker

export function exitCodeFor(r: { batches: number; restart?: string }): number {
  return r.restart === undefined ? 0 : EXIT_RESTART;
}

export function preflightFromOpts(
  o: { netns: string | null; dnsProbe: string; dnsTimeoutMs: number; egressCountry?: string | null; egressNotCountry?: string | null; egressEchoUrl?: string; mmdb?: string },
  deps?: PreflightOpts['deps'],
): (() => Promise<PreflightResult>) | undefined {
  const country = countryOptsFrom(o);
  if (!o.netns && !country) return undefined;
  return makePreflight({ netns: o.netns, dnsProbe: o.dnsProbe, timeoutMs: o.dnsTimeoutMs, country, ...(deps ? { deps } : {}) });
}
