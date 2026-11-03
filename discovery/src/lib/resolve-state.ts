import fs from 'node:fs';

/**
 * Per-host consecutive-failure counter, persisted across refresh runs. Only
 * currently-failing hosts are stored; a host that resolves is removed, so the
 * file stays small and a transient miss cannot ratchet a live host out.
 */
export interface ResolveState {
  [host: string]: number;
}

export interface Classification {
  /** Hosts to keep in domains.txt: everything resolved, plus failing hosts still within grace. */
  domains: string[];
  /** Hosts moved to phantoms.txt: failing for >= threshold consecutive runs. */
  phantoms: string[];
  /** The next state file contents: only hosts with an active failure streak. */
  state: ResolveState;
}

export function loadState(file: string): ResolveState {
  try {
    const obj: unknown = JSON.parse(fs.readFileSync(file, 'utf8'));
    return obj && typeof obj === 'object' ? (obj as ResolveState) : {};
  } catch {
    return {};
  }
}

export function saveState(file: string, state: ResolveState): void {
  fs.writeFileSync(file, JSON.stringify(state) + '\n');
}

/**
 * Decide, from this run's resolve results and the previous failure counters,
 * which hosts stay in domains.txt and which move to phantoms.txt.
 *
 * - resolved host      -> domains, counter reset (removed from state)
 * - failing host       -> counter++ ; phantoms once counter >= threshold,
 *                         otherwise kept in domains (grace period)
 *
 * This is self-healing: a phantom that resolves again returns immediately, and
 * a single transient miss never evicts a live host.
 */
export function classify(
  prev: ResolveState,
  resolved: Iterable<string>,
  failed: Iterable<string>,
  threshold: number,
): Classification {
  const t = Math.max(1, Math.floor(threshold));
  const domains = new Set<string>();
  const phantoms = new Set<string>();
  const state: ResolveState = {};

  for (const h of resolved) domains.add(h);

  for (const h of failed) {
    if (domains.has(h)) continue; // a resolved answer wins over a failed one
    const count = (prev[h] ?? 0) + 1;
    state[h] = count;
    if (count >= t) phantoms.add(h);
    else domains.add(h);
  }

  return {
    domains: [...domains].sort(),
    phantoms: [...phantoms].sort(),
    state,
  };
}
