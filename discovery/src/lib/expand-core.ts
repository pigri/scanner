// Pure tier classification for the expand stage. No I/O.

export type Tier = 'A' | 'B' | 'C' | 'D';

export interface Signals {
  resolves: boolean;
  ctCorroborated: boolean;
  wildcardHit: boolean;
}

/**
 * A = CT-corroborated and resolving, B = CT-corroborated but NXDOMAIN (both
 * merged), C = resolving without CT and outside a wildcard (sidecar), D = drop.
 * CT corroboration makes a name real regardless of wildcard noise.
 */
export function classify(sig: Signals): Tier {
  if (sig.ctCorroborated) return sig.resolves ? 'A' : 'B';
  if (sig.resolves && !sig.wildcardHit) return 'C';
  return 'D';
}

/** True when another pass would add nothing new. */
export function converged(state: { admitted: number }): boolean {
  return state.admitted === 0;
}
