export interface RunRow {
  id: number;
  tool: string;
  started_at: string;
}

export interface PruneOpts {
  olderThanDays: number;
  now: string;
  keepMinPerTool?: number;
}

function daysBetween(a: string, b: string): number {
  return (Date.parse(b) - Date.parse(a)) / 86_400_000;
}

/**
 * Given a list of runs, pick the ones eligible for pruning.
 * - `olderThanDays`: only consider runs strictly older than this.
 * - `keepMinPerTool`: always keep the N newest per tool, even if old.
 */
export function runsToPrune(rows: readonly RunRow[], opts: PruneOpts): RunRow[] {
  const cutoffDays = opts.olderThanDays;
  const keepMin = opts.keepMinPerTool ?? 0;

  // Newest-first per tool.
  const byTool = new Map<string, RunRow[]>();
  for (const r of rows) {
    if (!byTool.has(r.tool)) byTool.set(r.tool, []);
    byTool.get(r.tool)!.push(r);
  }
  for (const arr of byTool.values()) arr.sort((a, b) => b.started_at.localeCompare(a.started_at));

  const prunable: RunRow[] = [];
  for (const [, arr] of byTool) {
    // Skip the newest `keepMin` unconditionally.
    for (let i = keepMin; i < arr.length; i++) {
      const r = arr[i]!;
      if (daysBetween(r.started_at, opts.now) > cutoffDays) prunable.push(r);
    }
  }
  prunable.sort((a, b) => a.id - b.id);
  return prunable;
}
