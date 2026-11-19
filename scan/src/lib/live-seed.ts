import { findingsRuleOpts, watermarkSelect } from './current-findings.js';
import type { Db } from './db.js';

/** Scheme, lowercase host and a non-default port of a URL; '' when it does not parse. */
export function originOf(url: string | null | undefined): string {
  if (!url) return '';
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin.toLowerCase() : '';
  } catch {
    return '';
  }
}

const rank = (url: string): [number, number] => {
  const o = originOf(url);
  return [o.startsWith('https:') ? 0 : 1, /:\d+$/.test(o) ? 1 : 0];
};

/**
 * One http(s) seed URL per target from http_probes. The choice does not depend
 * on row order: https before http, a default port before an explicit one, then
 * the lowest URL. A wrapper that covers a target by what it fetched from this
 * seed needs it to be the same on every run.
 */
export function liveSeeds(db: Db, targets: readonly string[]): { target: string; url: string }[] {
  if (!targets.length) return [];
  const rows = db.raw.prepare(
    `SELECT DISTINCT target, url FROM http_probes
     WHERE target IN (${targets.map(() => '?').join(',')}) AND (url LIKE 'http://%' OR url LIKE 'https://%')
     ORDER BY target, url`
  ).all(...targets) as { target: string; url: string }[];
  const best = new Map<string, { target: string; url: string }>();
  for (const r of rows) {
    const cur = best.get(r.target);
    if (!cur) { best.set(r.target, r); continue; }
    const [a, b] = [rank(r.url), rank(cur.url)];
    if (a[0] < b[0] || (a[0] === b[0] && a[1] < b[1])) best.set(r.target, r);
  }
  return [...best.values()];
}

/**
 * Targets that have an open finding of `tool` from an origin other than the
 * seed's, or null when the findings cannot be read. Such a target is not
 * covered: this run never looked at that origin. A finding with no readable
 * matched_at counts as outside. Call it before the run inserts its own rows,
 * which would move the watermark. One indexed read per target
 * (idx_findings_logical on target, tool).
 */
export function targetsOutsideSeedOrigin(
  db: Db, tool: string, seeds: readonly { target: string; url: string }[],
): Set<string> | null {
  const outside = new Set<string>();
  try {
    const stmt = db.raw.prepare(
      `SELECT DISTINCT f.matched_at AS u
       FROM findings f JOIN (${watermarkSelect({ ...findingsRuleOpts(db.raw), targetParam: '@t' })}) wm
         ON wm.target = f.target AND wm.tool = f.tool
       WHERE f.target = @t AND f.tool = @tool AND f.seen_at >= wm.w`,
    );
    for (const s of seeds) {
      const seedOrigin = originOf(s.url);
      const rows = stmt.all({ t: s.target, tool }) as { u: string | null }[];
      if (rows.some((r) => !seedOrigin || originOf(r.u) !== seedOrigin)) outside.add(s.target);
    }
  } catch {
    return null;
  }
  return outside;
}

/** The run note for the result of `targetsOutsideSeedOrigin`; none when every target was clear. */
export function originGuardNote(tool: string, outside: ReadonlySet<string> | null): string[] {
  if (!outside) return [`coverage skipped: cannot read open ${tool} findings`];
  return outside.size ? [`${outside.size} target(s) not covered: an open finding came from an origin outside this run`] : [];
}
