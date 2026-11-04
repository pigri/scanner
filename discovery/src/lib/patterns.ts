// Pattern miner: turns a list of known FQDNs into the per-zone grammar that
// `permute` consumes. Output is plain JSON-serialisable data.
import { tokenize, zoneOf } from './hostname.js';

export type TokenClass = 'role' | 'region' | 'suffix' | 'word';

export interface TokenStat {
  text: string;
  /** Number of labels in the zone that contain this token. */
  count: number;
  class: TokenClass;
}

/**
 * A numeric run: a label shape with one number slot, e.g. `web#` seen with
 * values [1, 2]. `width` is the zero-pad width (0 when not padded).
 */
export interface NumericSequence {
  template: string;
  values: number[];
  width: number;
}

export interface ZoneGrammar {
  zone: string;
  /** FQDNs seen in this zone, apex included. */
  names: number;
  /** Word tokens, by count desc then text. */
  tokens: TokenStat[];
  /** Numeric runs, by template. */
  sequences: NumericSequence[];
}

export interface MinedGrammar {
  zones: Record<string, ZoneGrammar>;
}

const ROLE = new Set([
  'www', 'mail', 'smtp', 'imap', 'pop', 'mx', 'ns', 'web', 'api', 'app', 'vpn',
  'ftp', 'sftp', 'portal', 'admin', 'login', 'sso', 'auth', 'db', 'sql',
  'git', 'ci', 'cdn', 'static', 'img', 'proxy', 'gw', 'gateway', 'webmail',
  'intranet', 'extranet', 'ldap', 'dns', 'ntp', 'monitor', 'backup',
]);
const REGION = new Set([
  'eu', 'us', 'hu', 'de', 'uk', 'at', 'bp', 'budapest', 'dc1', 'dc2', 'east',
  'west', 'north', 'south',
]);
const SUFFIX = new Set([
  'test', 'dev', 'stage', 'staging', 'prod', 'uat', 'qa', 'old', 'new', 'demo',
  'beta', 'preview', 'bak', 'int', 'internal',
]);

function classOf(word: string): TokenClass {
  if (ROLE.has(word)) return 'role';
  if (REGION.has(word)) return 'region';
  if (SUFFIX.has(word)) return 'suffix';
  return 'word';
}

export function minePatterns(names: string[]): MinedGrammar {
  interface Acc {
    names: Set<string>;
    words: Map<string, number>;
    seqs: Map<string, { values: Set<number>; padded: boolean; maxLen: number }>;
  }
  const accs = new Map<string, Acc>();

  for (const raw of names) {
    const fqdn = raw.trim().toLowerCase().replace(/\.$/, '');
    if (!fqdn) continue;
    const zone = zoneOf(fqdn);
    let acc = accs.get(zone);
    if (!acc) {
      acc = { names: new Set(), words: new Map(), seqs: new Map() };
      accs.set(zone, acc);
    }
    if (acc.names.has(fqdn)) continue;
    acc.names.add(fqdn);

    const sub = fqdn === zone ? '' : fqdn.slice(0, -(zone.length + 1));
    for (const label of sub ? sub.split('.') : []) {
      const toks = tokenize(label);
      for (const t of new Set(toks.filter((x) => x.kind === 'word').map((x) => x.text))) {
        acc.words.set(t, (acc.words.get(t) ?? 0) + 1);
      }
      const nums = toks.filter((x) => x.kind === 'num');
      nums.forEach((t, n) => {
        let seen = -1;
        const key = label.replace(/[0-9]+/g, (m) => (++seen === n ? '#' : m));
        const s = acc.seqs.get(key) ?? { values: new Set<number>(), padded: false, maxLen: 0 };
        s.values.add(Number(t.text));
        if (t.text.length > 1 && t.text.startsWith('0')) s.padded = true;
        s.maxLen = Math.max(s.maxLen, t.text.length);
        acc.seqs.set(key, s);
      });
    }
  }

  const zones: Record<string, ZoneGrammar> = {};
  for (const [zone, acc] of [...accs].sort(([a], [b]) => a.localeCompare(b))) {
    zones[zone] = {
      zone,
      names: acc.names.size,
      tokens: [...acc.words]
        .map(([text, count]) => ({ text, count, class: classOf(text) }))
        .sort((a, b) => b.count - a.count || a.text.localeCompare(b.text)),
      sequences: [...acc.seqs]
        .map(([template, s]) => ({
          template,
          values: [...s.values].sort((a, b) => a - b),
          width: s.padded ? s.maxLen : 0,
        }))
        .sort((a, b) => a.template.localeCompare(b.template)),
    };
  }
  return { zones };
}
