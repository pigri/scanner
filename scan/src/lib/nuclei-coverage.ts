// Extract the bare host from a nuclei matched-at URL so we can look up its
// canary. Falls back to the raw string when parsing fails.
export function hostOf(url: string | null | undefined): string {
  if (!url) return '';
  try { return new URL(url.startsWith('http') ? url : `https://${url}`).host; }
  catch { return url.split('/')[0] ?? ''; }
}

function hostnameOf(url: string | null | undefined): string {
  if (!url) return '';
  try { return new URL(url.startsWith('http') ? url : `https://${url}`).hostname.toLowerCase(); }
  catch { return ''; }
}

/**
 * Targets the `--from-urls` pass conclusively examined. nuclei exits 0 after
 * `-mhe` skips a host, and when a host simply errors, so the exit code cannot
 * tell: a target counts only when a non-dns row matched on its own hostname.
 */
export function nucleiCoveredTargets(
  targets: readonly string[],
  rows: readonly { type?: string | undefined; 'matched-at'?: string | undefined }[],
  opts: { fromUrls: boolean; exitCode: number },
): string[] {
  if (!opts.fromUrls || opts.exitCode !== 0) return [];
  const matched = new Set<string>();
  for (const r of rows) {
    if (r.type === 'dns') continue;
    const h = hostnameOf(r['matched-at']);
    if (h) matched.add(h);
  }
  const out: string[] = [];
  for (const t of targets) if (matched.has(t.toLowerCase()) && !out.includes(t)) out.push(t);
  return out;
}
