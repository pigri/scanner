// Pure logic for finding-regression detection: for one target, compare the
// findings observed in the target's most-recent scan window against every
// finding observed before that window. Anything that used to fire but didn't
// come back is "resolved"; anything new to the latest window is "novel";
// anything seen in both is "persistent" (still open).
//
// A finding's identity is (tool, category, title). Same key convention as
// `query new-since` uses (see src/query.ts) so behavior stays consistent
// across the two differential views.

export interface Observation {
  tool: string;
  target: string;
  category: string;         // COALESCE(findings.category, '') — grouping key
  title: string;
  severity: string | null;  // critical | high | medium | low | info | null
  seen_at: string;          // ISO 8601
  cve: string | null;
  matched_at: string | null;
}

export type Key = string;

// Unambiguous JSON-encoded key. tool/category/title carry arbitrary
// punctuation (nuclei template ids, TLS issue names) so a plain delimiter
// would risk collisions.
export function keyOf(o: Pick<Observation, 'tool' | 'category' | 'title'>): Key {
  return JSON.stringify([o.tool, o.category, o.title]);
}

export interface ScanWindow {
  target: string;
  startedAt: string;   // inclusive lower bound
  finishedAt: string;  // inclusive upper bound
}

export interface PersistentPair {
  key: Key;
  pre: Observation;
  during: Observation;
}

export interface Diff {
  target: string;
  window: ScanWindow;
  // Key seen before the window, absent from it. Value = last pre observation.
  resolved: Observation[];
  // Key seen in both. `pre` = last pre observation; `during` = last during.
  persistent: PersistentPair[];
  // Key seen only in the window. Value = last during observation.
  novel: Observation[];
}

// Severities that count as "real issues" (matches deep-audit.ts convention).
// info-severity nuclei/testssl noise is excluded — it's mostly redirect stubs
// and bland TLS banner metadata, not something a host owner would call an issue.
export const MEANINGFUL_SEVERITIES: ReadonlySet<string> = new Set([
  'critical', 'high', 'medium', 'low',
]);

export function isMeaningful(o: Pick<Observation, 'severity'>): boolean {
  return o.severity != null && MEANINGFUL_SEVERITIES.has(o.severity.toLowerCase());
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

function rank(o: Pick<Observation, 'severity'>): number {
  return SEVERITY_RANK[String(o.severity ?? '').toLowerCase()] ?? -1;
}

function severityThenTimeDesc(a: Observation, b: Observation): number {
  const d = rank(b) - rank(a);
  return d !== 0 ? d : b.seen_at.localeCompare(a.seen_at);
}

/**
 * Split `observations` (all for `window.target`) into resolved / persistent / novel
 * buckets relative to `window`. Pre-window = seen_at < window.startedAt; during-window
 * = window.startedAt <= seen_at <= window.finishedAt. Observations after the window
 * are ignored (shouldn't exist when window is the latest scan).
 *
 * Multiple observations of the same key collapse to the latest one per bucket.
 */
export function diffAgainstScan(
  observations: readonly Observation[],
  window: ScanWindow,
): Diff {
  const pre = new Map<Key, Observation>();
  const during = new Map<Key, Observation>();

  for (const o of observations) {
    if (o.target !== window.target) {
      throw new Error(
        `diffAgainstScan: observation target ${o.target} != window.target ${window.target}`,
      );
    }
    const k = keyOf(o);
    if (o.seen_at < window.startedAt) {
      const prev = pre.get(k);
      if (!prev || o.seen_at > prev.seen_at) pre.set(k, o);
    } else if (o.seen_at <= window.finishedAt) {
      const prev = during.get(k);
      if (!prev || o.seen_at > prev.seen_at) during.set(k, o);
    }
  }

  const resolved: Observation[] = [];
  const persistent: PersistentPair[] = [];
  const novel: Observation[] = [];

  for (const [k, preObs] of pre) {
    const duringObs = during.get(k);
    if (duringObs) persistent.push({ key: k, pre: preObs, during: duringObs });
    else resolved.push(preObs);
  }
  for (const [k, duringObs] of during) {
    if (!pre.has(k)) novel.push(duringObs);
  }

  resolved.sort(severityThenTimeDesc);
  novel.sort(severityThenTimeDesc);
  persistent.sort((a, b) => severityThenTimeDesc(a.during, b.during));

  return { target: window.target, window, resolved, persistent, novel };
}

export type HostStatus =
  | 'clean-always'  // never had any meaningful finding
  | 'clean-now'     // had meaningful findings before the window, none in it
  | 'still-dirty'   // has meaningful findings in the latest window
  | 'unknown';      // no scan window available

/**
 * Classify a host based on presence of meaningful findings before vs. during
 * the scan window. Only critical/high/medium/low count; info-severity is
 * excluded (same policy as deep-audit).
 */
export function classifyHost(diff: Diff): HostStatus {
  const meaningfulPre =
    diff.resolved.some(isMeaningful) ||
    diff.persistent.some((p) => isMeaningful(p.pre));
  const meaningfulDuring =
    diff.novel.some(isMeaningful) ||
    diff.persistent.some((p) => isMeaningful(p.during));

  if (!meaningfulPre && !meaningfulDuring) return 'clean-always';
  if (!meaningfulDuring) return 'clean-now';
  return 'still-dirty';
}
