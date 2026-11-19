import type Database from 'better-sqlite3';
import { findingsRuleOpts, watermarkSelect } from './current-findings.js';
import { NUCLEI_URL_TOOL } from './nuclei-tool.js';

/** Host (with a non-default port) and lowercase hostname of a nuclei matched-at value, from one parse. */
export function parseMatched(url: string | null | undefined): { host: string; hostname: string } {
  if (!url) return { host: '', hostname: '' };
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    return { host: u.host, hostname: u.hostname.toLowerCase() };
  } catch {
    return { host: url.split('/')[0] ?? '', hostname: '' };
  }
}

// Extract the bare host from a nuclei matched-at URL so we can look up its
// canary. Falls back to the raw string when parsing fails.
export function hostOf(url: string | null | undefined): string {
  return parseMatched(url).host;
}

export interface NucleiRowEvidence {
  type?: string | undefined;
  'matched-at'?: string | undefined;
  /** The row's `host`, which keys its finding. */
  host?: string | undefined;
  /** Every finding of this row reached the database. */
  stored: boolean;
}

const SKIP_RE = /Skipped (\S+) from target list as found unresponsive/g;

/**
 * Hosts nuclei gave up on under -mhe. It logs `Skipped <host[:port]> from target
 * list as found unresponsive N times` to stderr and still exits 0. The -elog
 * file holds one JSON line per failed request with its `address`; a host with
 * `limit` or more of them is treated as skipped too.
 */
export function nucleiSkippedHosts(stderr: string, errorLog: readonly string[], limit: number): Set<string> {
  const skipped = new Set<string>();
  for (const m of stderr.matchAll(SKIP_RE)) {
    const h = parseMatched(m[1]).hostname;
    if (h) skipped.add(h);
  }
  const errors = new Map<string, number>();
  for (const line of errorLog) {
    try {
      const addr = (JSON.parse(line) as { address?: unknown }).address;
      const h = typeof addr === 'string' ? parseMatched(addr).hostname : '';
      if (h) errors.set(h, (errors.get(h) ?? 0) + 1);
    } catch { /* not a log entry */ }
  }
  for (const [h, n] of errors) if (n >= limit) skipped.add(h);
  return skipped;
}

/**
 * Key of an input URL or a finding's `url`: scheme, host, non-default port, path
 * (no trailing slash) and query. A value without a scheme is read as https, so
 * an ssl row's `matched-at` of `host:443` keys like the bare host.
 */
export function inputKey(url: string | null | undefined): string {
  if (!url) return '';
  try {
    const u = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
    return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}${u.search}`;
  } catch {
    return '';
  }
}

/** Keys of what a `--from-urls` run feeds nuclei. A bare host is probed on either scheme. */
export function nucleiInputKeys(targets: readonly string[], urlSample: readonly string[]): Set<string> {
  const keys = new Set<string>();
  for (const t of targets) {
    keys.add(inputKey(`http://${t}`));
    keys.add(inputKey(`https://${t}`));
  }
  for (const u of urlSample) keys.add(inputKey(u));
  keys.delete('');
  return keys;
}

/**
 * Input keys of each target's open nuclei-url rows: nuclei's `url` (the input it
 * scanned), else `matched_at`. Read before this run inserts anything, or its rows
 * would move the watermark past the old ones. Throws when the read fails.
 */
export function openNucleiUrlKeys(raw: Database.Database, targets: readonly string[]): Map<string, string[]> {
  const stmt = raw.prepare(
    `SELECT DISTINCT COALESCE(json_extract(f.meta_json, '$.url'), f.matched_at) AS u
     FROM findings f JOIN (${watermarkSelect({ ...findingsRuleOpts(raw), targetParam: '@t' })}) wm
       ON wm.target = f.target AND wm.tool = f.tool
     WHERE f.target = @t AND f.tool = '${NUCLEI_URL_TOOL}' AND f.seen_at >= wm.w`,
  );
  const out = new Map<string, string[]>();
  for (const t of new Set(targets)) {
    const keys = (stmt.all({ t }) as { u: string | null }[]).map((r) => inputKey(r.u));
    if (keys.length) out.set(t, keys);
  }
  return out;
}

/** Targets with an open key that is not among `inputs`. An empty key counts as outside. */
export function targetsWithKeysOutside(openKeys: ReadonlyMap<string, readonly string[]>, inputs: ReadonlySet<string>): string[] {
  return [...openKeys].filter(([, keys]) => keys.some((k) => !inputs.has(k))).map(([t]) => t);
}

/**
 * Targets the `--from-urls` pass conclusively examined. nuclei exits 0 when it
 * skips a host under -mhe or when a host merely errors, so the exit code is not
 * enough: a target counts only when a non-dns row matched on its hostname, every
 * row for that hostname was stored, and nuclei did not report it skipped.
 */
export function nucleiCoveredTargets(
  targets: readonly string[],
  rows: readonly NucleiRowEvidence[],
  opts: {
    fromUrls: boolean; exitCode: number; skipped?: ReadonlySet<string>;
    inputs: ReadonlySet<string>; openKeys: ReadonlyMap<string, readonly string[]> | null;
  },
): string[] {
  if (!opts.fromUrls || opts.exitCode !== 0 || !opts.openKeys) return [];
  const outside = new Set(targetsWithKeysOutside(opts.openKeys, opts.inputs));
  const state = new Map<string, { hit: boolean; failed: boolean }>();
  for (const r of rows) {
    const h = parseMatched(r['matched-at']).hostname;
    const keys = new Set([h, parseMatched(r.host).hostname].filter(Boolean));
    for (const k of keys) {
      const s = state.get(k) ?? { hit: false, failed: false };
      if (!r.stored) s.failed = true;
      else if (r.type !== 'dns' && k === h) s.hit = true;
      state.set(k, s);
    }
  }
  const out: string[] = [];
  for (const t of targets) {
    const h = t.toLowerCase();
    const s = state.get(h);
    if (s && s.hit && !s.failed && !opts.skipped?.has(h) && !outside.has(t) && !out.includes(t)) out.push(t);
  }
  return out;
}
