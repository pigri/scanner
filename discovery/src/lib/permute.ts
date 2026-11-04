// Candidate permuter: turns a mined grammar into a bounded, deterministic
// list of new hostnames per zone. Pure, no I/O.
import type { MinedGrammar, NumericSequence, TokenStat, ZoneGrammar } from './patterns.js';

export interface PermuteCaps {
  /** Hard ceiling on candidates emitted per zone. */
  perZone: number;
  /** How far past a run's max value to extend. Default 3. */
  sequenceLookahead?: number;
}

const DEFAULT_LOOKAHEAD = 3;
const MAX_STEMS = 5;
const MAX_MODIFIERS = 5;

function renderLabel(seq: NumericSequence, n: number): string {
  const digits = seq.width > 0 ? String(n).padStart(seq.width, '0') : String(n);
  return seq.template.replace('#', digits);
}

function sequenceLabels(seq: NumericSequence, lookahead: number): string[] {
  const first = seq.values[0];
  const last = seq.values[seq.values.length - 1];
  if (first === undefined || last === undefined) return [];
  const observed = new Set(seq.values);
  const lo = first === last ? Math.max(0, first - 1) : first;
  const hi = last + lookahead;
  const labels: string[] = [];
  // Gaps inside the range first, then the extension past the max.
  for (let n = lo; n <= last; n++) if (!observed.has(n)) labels.push(renderLabel(seq, n));
  for (let n = last + 1; n <= hi; n++) labels.push(renderLabel(seq, n));
  return labels;
}

function topTokens(tokens: TokenStat[], classes: TokenStat['class'][], limit: number): TokenStat[] {
  return tokens
    .filter((t) => classes.includes(t.class))
    .sort((a, b) => b.count - a.count || a.text.localeCompare(b.text))
    .slice(0, limit);
}

function recombinedLabels(tokens: TokenStat[]): string[] {
  const stems = topTokens(tokens, ['role', 'word'], MAX_STEMS);
  const mods = topTokens(tokens, ['suffix', 'region'], MAX_MODIFIERS);
  const scored: { label: string; score: number }[] = [];
  for (const stem of stems) {
    for (const mod of mods) {
      if (stem.text === mod.text) continue;
      scored.push({ label: `${stem.text}-${mod.text}`, score: stem.count + mod.count });
    }
  }
  scored.sort((a, b) => b.score - a.score || a.label.localeCompare(b.label));
  return scored.map((s) => s.label);
}

function permuteZone(g: ZoneGrammar, known: Set<string>, caps: PermuteCaps): string[] {
  const lookahead = Math.max(0, caps.sequenceLookahead ?? DEFAULT_LOOKAHEAD);
  const labels: string[] = [];
  for (const seq of g.sequences) labels.push(...sequenceLabels(seq, lookahead));
  labels.push(...recombinedLabels(g.tokens));

  const out: string[] = [];
  const seen = new Set<string>();
  for (const label of labels) {
    if (out.length >= caps.perZone) break;
    const fqdn = `${label}.${g.zone}`.toLowerCase();
    if (seen.has(fqdn) || known.has(fqdn)) continue;
    seen.add(fqdn);
    out.push(fqdn);
  }
  return out;
}

export function permute(grammar: MinedGrammar, known: Set<string>, caps: PermuteCaps): string[] {
  const knownLower = new Set([...known].map((k) => k.toLowerCase().replace(/\.$/, '')));
  const out: string[] = [];
  const seen = new Set<string>();
  for (const zone of Object.keys(grammar.zones).sort()) {
    const g = grammar.zones[zone];
    if (!g) continue;
    for (const fqdn of permuteZone(g, knownLower, caps)) {
      if (seen.has(fqdn)) continue;
      seen.add(fqdn);
      out.push(fqdn);
    }
  }
  return out;
}
