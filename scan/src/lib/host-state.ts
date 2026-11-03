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
      // Start of the current archive episode (reset on recovery), not the first-ever archival.
      first_archived_at: archived ? (prev?.first_archived_at ?? atIso) : null,
      updated_at: atIso,
    });
  }
  return out;
}

// Reads dnsx -j output. `rows` counts parsed rows with a host, so a caller can
// tell an empty output (crash, timeout) from a run that answered.
export function parseDnsxResolved(jsonl: string): { rows: number; resolved: Set<string> } {
  const resolved = new Set<string>();
  let rows = 0;
  for (const line of jsonl.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      const row = JSON.parse(t) as { host?: string; a?: string[]; aaaa?: string[] };
      if (!row.host) continue;
      rows++;
      if ((row.a?.length ?? 0) > 0 || (row.aaaa?.length ?? 0) > 0) resolved.add(row.host);
    } catch { /* ignore */ }
  }
  return { rows, resolved };
}

// A failed run, or one with no output rows, proves nothing about resolution.
export function shouldApplyResolution(code: number, rows: number): boolean {
  return code === 0 && rows > 0;
}
