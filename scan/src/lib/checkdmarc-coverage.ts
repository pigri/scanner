import { coveredTargets } from './coverage.js';

// dnspython and checkdmarc phrasings for "the resolver gave no answer":
// LifetimeTimeout, NoNameservers, Timeout, SERVFAIL and checkdmarc's own SMTP/DNS failure text.
const RESOLVER_FAILURE = /resolution lifetime expired|nameservers failed to answer|timed out|servfail|dns resolution failed/i;

/** True when checkdmarc got answers for the row's domain: it names a domain and no resolver failure appears anywhere in the row. */
export function checkdmarcRowConclusive<R extends { domain?: string | undefined }>(row: R): boolean {
  if (typeof row.domain !== 'string' || row.domain === '') return false;
  return !RESOLVER_FAILURE.test(JSON.stringify(row));
}

/** Domains with at least one row and only conclusive rows. A domain missing from the output is not covered. */
export function checkdmarcCoveredTargets<R extends { domain?: string | undefined }>(rows: readonly R[]): string[] {
  const outcomes: { target: string; ok: boolean }[] = [];
  for (const row of rows) {
    if (typeof row.domain === 'string' && row.domain !== '') outcomes.push({ target: row.domain, ok: checkdmarcRowConclusive(row) });
  }
  return coveredTargets(outcomes);
}
