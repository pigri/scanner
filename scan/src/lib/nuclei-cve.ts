/**
 * The CVE ids to record for one nuclei match. A template's
 * `info.classification.cve-id` is an array and may carry several ids (e.g. a
 * shared template covering a CVE pair); we record EVERY one, not just the
 * first, so secondary CVEs are not silently dropped. A match with no CVE yields
 * a single `[null]` so it is still stored as a (CVE-less) finding.
 */
export function cveIdsFor(cveIds: string[] | undefined | null): (string | null)[] {
  const ids = (cveIds ?? []).map((c) => c.trim()).filter((c) => c.length > 0);
  return ids.length ? ids : [null];
}
