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
 * Targets the `--from-urls` pass conclusively examined. nuclei exits 0 when it
 * skips a host under -mhe or when a host merely errors, so the exit code is not
 * enough: a target counts only when a non-dns row matched on its hostname, every
 * row for that hostname was stored, and nuclei did not report it skipped.
 */
export function nucleiCoveredTargets(
  targets: readonly string[],
  rows: readonly NucleiRowEvidence[],
  opts: { fromUrls: boolean; exitCode: number; skipped?: ReadonlySet<string> },
): string[] {
  if (!opts.fromUrls || opts.exitCode !== 0) return [];
  const state = new Map<string, { hit: boolean; failed: boolean }>();
  for (const r of rows) {
    const h = parseMatched(r['matched-at']).hostname;
    if (!h) continue;
    const s = state.get(h) ?? { hit: false, failed: false };
    if (!r.stored) s.failed = true;
    else if (r.type !== 'dns') s.hit = true;
    state.set(h, s);
  }
  const out: string[] = [];
  for (const t of targets) {
    const h = t.toLowerCase();
    const s = state.get(h);
    if (s && s.hit && !s.failed && !opts.skipped?.has(h) && !out.includes(t)) out.push(t);
  }
  return out;
}
