// Wildcard-DNS detection: if a guaranteed-nonexistent label under a parent zone
// still resolves, the zone has a wildcard record and every brute-forced
// subdomain would appear to "exist". We probe with two fixed random-looking
// labels and treat any answer as evidence of a wildcard.

export const WILDCARD_PROBE_LABELS = ['zzzrand987nomatch', 'xxx111notreal999'] as const;

/** The probe FQDNs to resolve for a given parent zone. */
export function wildcardProbeHosts(parent: string): string[] {
  return WILDCARD_PROBE_LABELS.map((label) => `${label}.${parent}`);
}

export interface WildcardVerdict {
  parent: string;
  wildcard: boolean;
  ips: string[]; // deduped union of every answer across the probes
}

/**
 * Decide whether a parent zone is a wildcard from the resolver answers for its
 * probe hosts. `answers` is one string[] per probe host (in any order). A zone
 * is a wildcard iff any probe returned at least one answer.
 */
export function classifyWildcard(parent: string, answers: string[][]): WildcardVerdict {
  const ips = [...new Set(answers.flat().map((s) => s.trim()).filter(Boolean))];
  return { parent, wildcard: ips.length > 0, ips };
}
