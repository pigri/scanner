// Hostname primitives for the expand stage: registrable-zone lookup and
// label tokenisation. Pure, no I/O.

// Deliberate narrowing: the corpus is .gov.hu-shaped, so instead of a full
// public-suffix-list dependency we keep a small explicit set of multi-label
// suffixes and fall back to "last two labels" for everything else. Extend the
// set when a new multi-label suffix enters the corpus.
const MULTI_LABEL_SUFFIXES: ReadonlySet<string> = new Set([
  'gov.hu',
  'co.hu',
  'org.hu',
  'edu.hu',
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
]);

export function zoneOf(fqdn: string): string {
  const labels = fqdn.trim().toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const last2 = labels.slice(-2).join('.');
  const keep = MULTI_LABEL_SUFFIXES.has(last2) ? 3 : 2;
  return labels.slice(-keep).join('.');
}

export interface Token {
  text: string;
  kind: 'word' | 'num';
}

/** Split one DNS label on `-` and letter/digit boundaries, lowercased. */
export function tokenize(label: string): Token[] {
  const out: Token[] = [];
  for (const m of label.toLowerCase().matchAll(/[0-9]+|[^0-9-]+/g)) {
    const text = m[0];
    out.push({ text, kind: /^[0-9]/.test(text) ? 'num' : 'word' });
  }
  return out;
}
