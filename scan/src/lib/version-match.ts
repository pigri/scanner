// version-match: pure matching of software versions seen in evidence against
// the CPE ranges in the offline NVD mirror. No network, no database import:
// the mirror is injected as a `VulnLookup`.
import type { CpeMatchRow, VulnLookup } from './nvd-db.js';
import { resolveAlias, type AliasEntry } from './cpe-aliases.js';

export type VersionSeg = number | string;

export interface Evidence {
  /** Product name as seen (header token, tech label or nmap product). */
  name: string;
  /** Version used for matching: build suffix stripped. */
  version: string;
  /** Version exactly as seen. */
  raw: string;
  /** Distro named by the banner, if any: backports make these likely false positives. */
  distro: string | null;
}

export type MatchRule = 'exact' | 'update' | 'range';
export type Confidence = 'version-match' | 'version-match-distro';

export interface CveMatch {
  cve: string;
  cvss: number;
  cvssVersion: string | null;
  cpe: string;
  rule: MatchRule;
  confidence: Confidence;
  vendor: string;
  product: string;
  /** Allowlist entry label, for titles. */
  display: string;
  evidence: Evidence;
}

export function parseVersion(v: string): VersionSeg[] {
  const out: VersionSeg[] = [];
  for (const m of v.toLowerCase().matchAll(/\d+|[a-z]+/g)) {
    out.push(/^\d/.test(m[0]) ? Number(m[0]) : m[0]);
  }
  return out;
}

function cmpSeg(a: VersionSeg | undefined, b: VersionSeg | undefined): number {
  if (a === undefined && b === undefined) return 0;
  // A missing segment is 0 against a number and "before" a letter suffix (1.0.2 < 1.0.2k).
  if (a === undefined) return typeof b === 'number' ? (b === 0 ? 0 : -1) : -1;
  if (b === undefined) return typeof a === 'number' ? (a === 0 ? 0 : 1) : 1;
  if (typeof a === 'number' && typeof b === 'number') return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === 'string' && typeof b === 'string') return a < b ? -1 : a > b ? 1 : 0;
  return typeof a === 'number' ? -1 : 1;
}

export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a), pb = parseVersion(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const c = cmpSeg(pa[i], pb[i]);
    if (c !== 0) return c;
  }
  return 0;
}

/** True when `v` falls inside the row's start/end bounds. A row with no bounds is not a range. */
export function inRange(v: string, row: Pick<CpeMatchRow, 'start_incl' | 'start_excl' | 'end_incl' | 'end_excl'>): boolean {
  if (!row.start_incl && !row.start_excl && !row.end_incl && !row.end_excl) return false;
  if (row.start_incl && compareVersions(v, row.start_incl) < 0) return false;
  if (row.start_excl && compareVersions(v, row.start_excl) <= 0) return false;
  if (row.end_incl && compareVersions(v, row.end_incl) > 0) return false;
  if (row.end_excl && compareVersions(v, row.end_excl) >= 0) return false;
  return true;
}

/** Strip a build suffix after `-` and require at least two numeric segments; null otherwise. */
export function normalizeVersion(raw: string): string | null {
  const v = raw.trim().replace(/^v(?=\d)/i, '').split(/[-+~_ ]/)[0] ?? '';
  return /^\d+\.\d+/.test(v) ? v : null;
}

const DISTRO_RE = /\b(Ubuntu|Debian|CentOS|Red ?Hat|RHEL|SUSE|SLES|Fedora|Rocky|Alma)/i;

export function detectDistro(text: string | null | undefined): string | null {
  const m = text ? DISTRO_RE.exec(text) : null;
  return m ? m[1]! : null;
}

function mk(name: string, rawVersion: string, distro: string | null): Evidence | null {
  const version = normalizeVersion(rawVersion);
  return { name, version: version ?? rawVersion, raw: rawVersion, distro };
}

const TOKEN_RE = /([A-Za-z][A-Za-z0-9._-]*)\/(\d[A-Za-z0-9._+~-]*)/g;

/** `Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/8.0.30` to one Evidence per `name/version` token. */
export function parseServerHeader(header: string): Evidence[] {
  const distro = detectDistro(header);
  const out: Evidence[] = [];
  for (const m of header.matchAll(TOKEN_RE)) {
    const e = mk(m[1]!, m[2]!, distro);
    if (e) out.push(e);
  }
  return out;
}

/** An httpx tech label `Name:version`, or null when it carries no version. */
export function parseTechToken(token: string): Evidence | null {
  const i = token.lastIndexOf(':');
  if (i <= 0) return null;
  const name = token.slice(0, i).trim();
  const ver = token.slice(i + 1).trim();
  if (!name || !/^\d/.test(ver)) return null;
  return mk(name, ver, null);
}

/** Evidence from an nmap service row; the version is its leading token. */
export function evidenceFromPort(
  product: string | null | undefined,
  version: string | null | undefined,
  extrainfo: string | null | undefined,
): Evidence | null {
  if (!product || !version) return null;
  const lead = version.trim().split(/\s+/)[0] ?? '';
  if (!/^\d/.test(lead)) return null;
  return mk(product.trim(), lead, detectDistro(`${version} ${extrainfo ?? ''}`));
}

export function severityForCvss(cvss: number): 'critical' | 'high' | 'medium' | 'low' {
  return cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low';
}

/** Which candidate, tried in order (exact, version+update_, range), makes `row` hit `version`. */
function matchRow(version: string, row: CpeMatchRow): MatchRule | null {
  const lc = version.toLowerCase();
  if (row.version !== '*' && row.version !== '-') {
    const base = row.version.toLowerCase();
    const upd = row.update_ === '*' || row.update_ === '-' ? '' : row.update_.toLowerCase();
    if (!upd && lc === base) return 'exact';
    if (upd && lc.replace(/[-_.]/g, '') === (base + upd).replace(/[-_.]/g, '')) return 'update';
    return null;
  }
  return inRange(version, row) ? 'range' : null;
}

const RULE_RANK: Record<MatchRule, number> = { exact: 0, update: 1, range: 2 };

export interface MatchResult { matches: CveMatch[]; skipped: number }

/**
 * Match each piece of evidence against the lookup. Evidence whose product is
 * not allowlisted is ignored; evidence with a version of fewer than two
 * numeric segments is counted in `skipped`. CVEs without a CVSS score are dropped.
 */
export function matchCves(evidence: readonly Evidence[], lookup: VulnLookup): MatchResult {
  const matches: CveMatch[] = [];
  let skipped = 0;
  for (const ev of evidence) {
    const alias: AliasEntry | null = resolveAlias(ev.name);
    if (!alias) continue;
    const version = normalizeVersion(ev.version);
    if (!version) { skipped++; continue; }
    const hits = new Map<string, { rule: MatchRule; vendor: string; product: string }>();
    for (const [vendor, product] of alias.pairs) {
      for (const row of lookup.cpeMatches(vendor, product)) {
        const rule = matchRow(version, row);
        if (!rule) continue;
        const prev = hits.get(row.cve_id);
        if (!prev || RULE_RANK[rule] < RULE_RANK[prev.rule]) hits.set(row.cve_id, { rule, vendor, product });
      }
    }
    if (hits.size === 0) continue;
    const meta = lookup.cveMeta([...hits.keys()]);
    for (const [cve, h] of hits) {
      const cvss = meta.get(cve)?.cvss;
      if (typeof cvss !== 'number') continue;
      matches.push({
        cve, cvss, cvssVersion: meta.get(cve)?.cvss_version ?? null,
        cpe: `cpe:2.3:a:${h.vendor}:${h.product}:${version}`,
        rule: h.rule,
        confidence: ev.distro ? 'version-match-distro' : 'version-match',
        vendor: h.vendor, product: h.product, display: alias.display,
        evidence: { ...ev, version },
      });
    }
  }
  matches.sort((a, b) => a.cve.localeCompare(b.cve));
  return { matches, skipped };
}
