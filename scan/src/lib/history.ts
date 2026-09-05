// Pure logic for per-finding history: for one target, group observations by
// (tool, category, title) and mark presence across every completed scan
// window. Lets callers see "resolved cleanly" vs "flapping" vs "actually
// gone" — the same finding disappearing and reappearing across scans usually
// means a WAF / rate-limit / DNS artifact, not a real fix.
//
// Presence is tri-state because each scan window is per-tool: a nuclei key's
// presence in a testssl-only window is 'n/a', not 'absent'. Status +
// flapping are computed only over windows whose tool applies to the key
// (window.tool === key.tool, or window.tool === 'scan-all' which acts as a
// wildcard for the orchestrator's umbrella row).
import { keyOf, type Key } from './resolved.js';

export interface Observation {
  tool: string;
  target: string;
  category: string;         // COALESCE(findings.category, '')
  title: string;
  severity: string | null;
  seen_at: string;          // ISO 8601
  cve: string | null;
  matched_at: string | null;
  run_id: number | null;
}

export interface ScanWindow {
  target: string;
  tool: string;             // 'scan-all' acts as wildcard for any key tool
  startedAt: string;        // inclusive lower bound
  finishedAt: string;       // inclusive upper bound
}

export type PresenceState = 'present' | 'absent' | 'n/a';
export type Status = 'persistent' | 'resolved' | 'unknown';

export interface KeyAttendance {
  key: Key;
  tool: string;
  category: string;
  title: string;
  observations: number;
  presence: PresenceState[];              // parallel to windows (chronological)
  severityPerWindow: (string | null)[];   // worst severity observed in window, or null if absent/n-a
  firstSeen: string;
  lastSeen: string;
  status: Status;                         // 'unknown' when every window is n/a
  flapping: boolean;                      // >= 2 present↔absent transitions across applicable windows
  worstSeverity: string | null;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

function rank(s: string | null | undefined): number {
  return SEVERITY_RANK[String(s ?? '').toLowerCase()] ?? -1;
}

function worse(a: string | null, b: string | null): string | null {
  if (a == null) return b;
  if (b == null) return a;
  return rank(a) >= rank(b) ? a : b;
}

function assertChronological(windows: readonly ScanWindow[]): void {
  for (let i = 1; i < windows.length; i++) {
    if (windows[i - 1]!.startedAt > windows[i]!.startedAt) {
      throw new Error('computeAttendance: windows must be sorted by startedAt ascending');
    }
  }
}

function windowAppliesToKey(w: ScanWindow, keyTool: string): boolean {
  return w.tool === 'scan-all' || w.tool === keyTool;
}

function computeStatus(applicable: PresenceState[]): Status {
  for (let i = applicable.length - 1; i >= 0; i--) {
    const p = applicable[i]!;
    if (p === 'present') return 'persistent';
    if (p === 'absent') return 'resolved';
  }
  return 'unknown';
}

function countTransitions(applicable: PresenceState[]): number {
  // Only 'present' <-> 'absent' transitions count; 'n/a' is skipped rather
  // than treated as its own state (it means "no signal", not a real gap).
  let n = 0;
  let last: 'present' | 'absent' | null = null;
  for (const p of applicable) {
    if (p === 'n/a') continue;
    if (last != null && last !== p) n++;
    last = p;
  }
  return n;
}

/**
 * Group observations by (tool, category, title) and compute per-window
 * attendance. Windows must be sorted chronologically by startedAt and all
 * for the same target; observations must be for that same target.
 */
export function computeAttendance(
  observations: readonly Observation[],
  windows: readonly ScanWindow[],
): KeyAttendance[] {
  if (windows.length === 0) {
    throw new Error('computeAttendance: at least one scan window is required');
  }
  const target = windows[0]!.target;
  for (const w of windows) {
    if (w.target !== target) {
      throw new Error(`computeAttendance: all windows must be for the same target (got ${target} and ${w.target})`);
    }
  }
  assertChronological(windows);

  const byKey = new Map<Key, Observation[]>();
  for (const o of observations) {
    if (o.target !== target) {
      throw new Error(`computeAttendance: observation target ${o.target} != window target ${target}`);
    }
    const k = keyOf(o);
    const list = byKey.get(k);
    if (list) list.push(o);
    else byKey.set(k, [o]);
  }

  const out: KeyAttendance[] = [];
  for (const [k, obsList] of byKey) {
    const first = obsList[0]!;
    const presence: PresenceState[] = windows.map((w) =>
      windowAppliesToKey(w, first.tool) ? 'absent' : 'n/a',
    );
    const severityPerWindow: (string | null)[] = windows.map(() => null);
    let firstSeen = first.seen_at;
    let lastSeen = first.seen_at;
    let worstSeverity: string | null = null;

    for (const o of obsList) {
      if (o.seen_at < firstSeen) firstSeen = o.seen_at;
      if (o.seen_at > lastSeen) lastSeen = o.seen_at;
      worstSeverity = worse(worstSeverity, o.severity);
      for (let i = 0; i < windows.length; i++) {
        const w = windows[i]!;
        if (!windowAppliesToKey(w, first.tool)) continue;
        if (o.seen_at >= w.startedAt && o.seen_at <= w.finishedAt) {
          presence[i] = 'present';
          severityPerWindow[i] = worse(severityPerWindow[i]!, o.severity);
        }
      }
    }

    out.push({
      key: k,
      tool: first.tool,
      category: first.category,
      title: first.title,
      observations: obsList.length,
      presence,
      severityPerWindow,
      firstSeen,
      lastSeen,
      status: computeStatus(presence),
      flapping: countTransitions(presence) >= 2,
      worstSeverity,
    });
  }

  out.sort((a, b) => {
    const d = rank(b.worstSeverity) - rank(a.worstSeverity);
    if (d !== 0) return d;
    return b.lastSeen.localeCompare(a.lastSeen);
  });
  return out;
}
