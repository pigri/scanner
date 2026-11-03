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
  created_at: string | null;
  updated_at: string | null;
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
  sort?: string;
  offset?: number;
  limit?: number;
}

export interface TargetFacetResult<T> {
  rows: T[];
  total: number;
  limit: number;
  offset: number;
  sevCounts: Record<string, number>;
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
  const sort = p.sort || 'score';
  const offset = p.offset ?? 0;
  const limit = p.limit ?? 100;

  // Base predicate: everything except the severity selection, so the severity
  // facet counts are independent of the severity the user has chosen.
  const base = all.filter((r) => {
    if (search && !r.target.toLowerCase().includes(search)) return false;
    if (cve === '1' && !(r.cves > 0)) return false;
    if (cve === '0' && r.cves > 0) return false;
    if (hasMin && r.score < minScore) return false;
    if (hasMax && r.score > maxScore) return false;
    return true;
  });

  const sevCounts: Record<string, number> = {};
  for (const s of SEVERITIES) sevCounts[s] = 0;
  for (const r of base) for (const s of SEVERITIES) if (sevOf(r, s) > 0) sevCounts[s] = (sevCounts[s] ?? 0) + 1;

  const filtered = sevList.length
    ? base.filter((r) => sevList.some((s) => sevOf(r, s) > 0))
    : base;

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

  return { rows: filtered.slice(offset, offset + limit), total: filtered.length, limit, offset, sevCounts };
}
