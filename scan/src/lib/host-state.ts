// Per-host archive state, decided from one dnsx batch. Pure: no I/O.
// A host that stops resolving is archived (active=0); one that resolves again
// is un-archived. dns_fail_count lets the threshold be raised without a schema
// change.

export const DNS_ARCHIVE_THRESHOLD = 1;
export const DNS_ARCHIVE_REASON = 'dns';

export interface HostStateRow {
  target: string;
  active: number; // 0 = archived
  reason: string | null;
  dns_fail_count: number;
  last_checked: string | null;
  last_resolved: string | null;
  first_archived_at: string | null;
  updated_at: string;
}

export function decideHostStates(
  targets: readonly string[],
  resolved: ReadonlySet<string>,
  current: ReadonlyMap<string, HostStateRow>,
  atIso: string,
  threshold: number,
): HostStateRow[] {
  const out: HostStateRow[] = [];
  for (const target of new Set(targets)) {
    const prev = current.get(target);
    if (resolved.has(target)) {
      out.push({
        target, active: 1, reason: null, dns_fail_count: 0,
        last_checked: atIso, last_resolved: atIso, first_archived_at: null, updated_at: atIso,
      });
      continue;
    }
    const fails = (prev?.dns_fail_count ?? 0) + 1;
    const archived = fails >= threshold || prev?.active === 0;
    out.push({
      target,
      active: archived ? 0 : 1,
      reason: archived ? DNS_ARCHIVE_REASON : null,
      dns_fail_count: fails,
      last_checked: atIso,
      last_resolved: prev?.last_resolved ?? null,
      first_archived_at: archived ? (prev?.first_archived_at ?? atIso) : null,
      updated_at: atIso,
    });
  }
  return out;
}
