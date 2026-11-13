import fs from 'node:fs';
import dns from 'node:dns';

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
  netns: string;
  dnsProbe: string;
  timeoutMs: number;
  deps?: { netns?: NetnsDeps; dns?: DnsDeps };
}

// A wrong or missing namespace cannot heal in this process, so it asks for a
// restart. A DNS problem may clear by itself, so it asks to wait and try again.
export function makePreflight(o: PreflightOpts): () => Promise<PreflightResult> {
  return async () => {
    const n = checkNetns(o.netns, o.deps?.netns);
    if (n.status === 'mismatch') return { action: 'restart', reason: `running in netns inode ${n.actual}, but ${o.netns} is now inode ${n.expected}` };
    if (n.status === 'error') return { action: 'restart', reason: `netns ${o.netns} check failed: ${n.reason}` };
    const d = await checkDns(o.dnsProbe, o.timeoutMs, o.deps?.dns);
    if (d.status === 'fail') return { action: 'retry', reason: `dns probe ${o.dnsProbe} failed: ${d.reason}` };
    if (d.status === 'timeout') return { action: 'retry', reason: `dns probe ${o.dnsProbe} timed out after ${o.timeoutMs} ms` };
    return { action: 'ok' };
  };
}

export const EXIT_RESTART = 75; // EX_TEMPFAIL: non-zero, so Restart=on-failure starts a fresh worker

export function exitCodeFor(r: { batches: number; restart?: string }): number {
  return r.restart === undefined ? 0 : EXIT_RESTART;
}

export function preflightFromOpts(
  o: { netns: string | null; dnsProbe: string; dnsTimeoutMs: number },
  deps?: PreflightOpts['deps'],
): (() => Promise<PreflightResult>) | undefined {
  if (!o.netns) return undefined;
  return makePreflight({ netns: o.netns, dnsProbe: o.dnsProbe, timeoutMs: o.dnsTimeoutMs, ...(deps ? { deps } : {}) });
}
