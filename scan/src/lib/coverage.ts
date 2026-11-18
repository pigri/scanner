/** Targets with at least one outcome and no failed one, in first-seen order. */
export function coveredTargets(outcomes: { target: string; ok: boolean }[]): string[] {
  const state = new Map<string, boolean>();
  for (const o of outcomes) state.set(o.target, (state.get(o.target) ?? true) && o.ok);
  return [...state].filter(([, ok]) => ok).map(([t]) => t);
}
