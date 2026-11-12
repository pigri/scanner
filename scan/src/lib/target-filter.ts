// Pure filtering, faceting, sorting and paging for the hosts ("Targets") list.
// Kept free of any DB or I/O so it is unit-testable; src/ui.ts loads the cached
// per-target aggregate and delegates here.

export interface TargetRowLike {
  target: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  findings: number;
  cves: number;
  versionMatch: number; // distinct CVEs from version-match (banner-inferred) findings
  created_at: string | null;
  updated_at: string | null;
  organization: string | null;
  active: number; // 0 = archived (host_state), 1 = active
}

export const SEVERITIES: readonly string[] = ['critical', 'high', 'medium', 'low', 'info'];

export function sevOf(r: TargetRowLike, s: string): number {
  return s === 'critical'
    ? r.critical
    : s === 'high'
      ? r.high
      : s === 'medium'
        ? r.medium
        : s === 'low'
          ? r.low
          : r.info;
}

export interface TargetFilterParams {
  search?: string;
  sevList?: string[];
  cve?: string | null; // '1' = has >=1 CVE, '0' = none
  minScore?: number | null;
  maxScore?: number | null;
  org?: string; // exact-match on the cert Organization; '' = any
  archived?: string; // '' = active only (default), '1' = archived only, 'all' = both
  sort?: string;
  offset?: number;
  limit?: number;
}

export interface OrgCount {
  org: string;
  c: number;
}

export interface TargetFacetResult<T> {
  rows: T[];
  total: number;
  limit: number;
  offset: number;
  sevCounts: Record<string, number>;
  orgs: OrgCount[];
  archivedCount: number;
}

export function filterAndFacet<T extends TargetRowLike>(
  all: T[],
  p: TargetFilterParams,
): TargetFacetResult<T> {
  const search = (p.search ?? '').trim().toLowerCase();
  const cve = p.cve ?? null;
  const hasMin = p.minScore != null && Number.isFinite(p.minScore);
  const hasMax = p.maxScore != null && Number.isFinite(p.maxScore);
  const minScore = p.minScore as number;
  const maxScore = p.maxScore as number;
  const sevList = (p.sevList ?? []).map((s) => s.trim()).filter((s) => SEVERITIES.includes(s));
  const org = (p.org ?? '').trim();
  const archived = (p.archived ?? '').trim();
  const sort = p.sort || 'score';
  const offset = p.offset ?? 0;
  const limit = p.limit ?? 100;

  // Everything except the archived set and the severity/org selections.
  const matched = all.filter((r) => {
    if (search && !r.target.toLowerCase().includes(search)) return false;
    if (cve === '1' && !(r.cves > 0)) return false;
    if (cve === '0' && r.cves > 0) return false;
    if (hasMin && r.score < minScore) return false;
    if (hasMax && r.score > maxScore) return false;
    return true;
  });

  // Archived tally is taken before the set is chosen, so the toggle can show
  // how many hosts the other set holds.
  const archivedCount = matched.reduce((n, r) => n + (r.active === 0 ? 1 : 0), 0);

  // Base predicate: the chosen archived set too, but not the severity and org
  // selections, so each facet's counts stay independent of its own selection.
  const base = matched.filter((r) =>
    archived === 'all' ? true : archived === '1' ? r.active === 0 : r.active !== 0,
  );

  const sevCounts: Record<string, number> = {};
  for (const s of SEVERITIES) sevCounts[s] = 0;
  for (const r of base) for (const s of SEVERITIES) if (sevOf(r, s) > 0) sevCounts[s] = (sevCounts[s] ?? 0) + 1;

  // Org facet: # of targets per non-null Organization, over the base (so it is
  // independent of the chosen org, matching the severity-facet convention).
  const orgTally = new Map<string, number>();
  for (const r of base) {
    const o = r.organization;
    if (o != null && o !== '') orgTally.set(o, (orgTally.get(o) ?? 0) + 1);
  }
  const orgs: OrgCount[] = [...orgTally.entries()]
    .map(([o, c]) => ({ org: o, c }))
    .sort((a, b) => b.c - a.c || a.org.localeCompare(b.org));

  const filtered = base.filter((r) => {
    if (sevList.length && !sevList.some((s) => sevOf(r, s) > 0)) return false;
    if (org && r.organization !== org) return false;
    return true;
  });

  const cmp = (a: T, b: T): number => {
    const byNum = (k: keyof TargetRowLike) =>
      (b[k] as number) - (a[k] as number) || b.score - a.score || a.target.localeCompare(b.target);
    switch (sort) {
      case 'critical':
        return byNum('critical');
      case 'high':
        return byNum('high');
      case 'findings':
        return byNum('findings');
      case 'cves':
        return byNum('cves');
      case 'versionMatch':
        return byNum('versionMatch');
      case 'updated':
        return (b.updated_at || '').localeCompare(a.updated_at || '') || a.target.localeCompare(b.target);
      case 'created':
        return (b.created_at || '').localeCompare(a.created_at || '') || a.target.localeCompare(b.target);
      case 'target':
        return a.target.localeCompare(b.target);
      default:
        return b.score - a.score || a.target.localeCompare(b.target);
    }
  };
  filtered.sort(cmp);

  return {
    rows: filtered.slice(offset, offset + limit),
    total: filtered.length,
    limit,
    offset,
    sevCounts,
    orgs,
    archivedCount,
  };
}
