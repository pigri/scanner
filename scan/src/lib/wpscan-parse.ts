/** wpscan --format json prints JSON.pretty_generate output: one key per line, so stdout is one multi-line document. */
export function parseWpscanStdout(stdout: string): unknown {
  const text = stdout.trim();
  // Anything before the document (a stray warning) ends where the first line starting with '{' begins.
  const start = text.startsWith('{') ? 0 : text.search(/^\{/m);
  if (start < 0) throw new Error('no JSON object in wpscan output');
  return JSON.parse(text.slice(start));
}

interface Vuln { title?: string; cvss?: unknown; references?: { cve?: string[] | string } }

export interface WpscanParsed {
  interesting_findings?: { to_s?: string; type?: string; url?: string; references?: unknown }[];
  version?: { number?: string; vulnerabilities?: Vuln[] } | null;
  plugins?: Record<string, { version?: { number?: string } | null; vulnerabilities?: Vuln[] }>;
}

/** wpscan reports CVE ids without the prefix ("2014-4663"), as a list or a single string. */
export function wpscanCves(v: Vuln): string[] {
  const raw = v.references?.cve;
  const ids = (Array.isArray(raw) ? raw : [raw]).filter((c): c is string => typeof c === 'string' && c !== '');
  return [...new Set(ids.map((c) => (/^CVE-/i.test(c) ? c.toUpperCase() : `CVE-${c}`)))];
}

export function wpscanCve(v: Vuln): string | null {
  return wpscanCves(v)[0] ?? null;
}

/** The score of wpscan's `cvss: {score, vector}` object, or null when there is none above zero. */
function cvssScore(cvss: unknown): number | null {
  const raw = (cvss as { score?: unknown } | null | undefined)?.score;
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number.parseFloat(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? n : null;
}

/** critical >= 9, high >= 7, medium >= 4, low above 0. Without a score the vulnerability stays `high`. */
export function wpscanSeverity(cvss: unknown): string {
  const n = cvssScore(cvss);
  if (n === null) return 'high';
  return n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : 'low';
}

export interface WpscanRow {
  category: string;
  severity: string;
  title: string;
  cve: string | null;
  matched_at: string | null;
  meta: unknown;
}

type Node = Record<string, unknown>;

interface Section {
  /** Dot path into the wpscan document; `*` stands for every key of an object. */
  path: string;
  category: string;
  /** null: the entries are vulnerabilities and the severity comes from their CVSS score. */
  severity: string | null;
  /** `key` is the URL or slug the entry sits under; the item is the entry (a vulnerability for severity null). */
  title: (key: string, item: Node) => string;
}

// One row per entry. The title is part of the dedup key (target, tool, severity, category, title),
// so it holds only what identifies the finding and nothing that changes between scans.
const SECTIONS: Section[] = [
  { path: 'version.vulnerabilities', category: 'core-vulnerability', severity: null, title: (_k, v) => str(v['title']) ?? 'core vuln' },
  { path: 'plugins.*.vulnerabilities', category: 'plugin-vulnerability', severity: null, title: (k, v) => `${k}: ${str(v['title']) ?? 'plugin vuln'}` },
  { path: 'main_theme.vulnerabilities', category: 'theme-vulnerability', severity: null, title: (k, v) => `${k}: ${str(v['title']) ?? 'theme vuln'}` },
  { path: 'themes.*.vulnerabilities', category: 'theme-vulnerability', severity: null, title: (k, v) => `${k}: ${str(v['title']) ?? 'theme vuln'}` },
  { path: 'timthumbs.*', category: 'timthumb', severity: 'medium', title: (k) => `timthumb exposed: ${k}` },
  { path: 'timthumbs.*.vulnerabilities', category: 'timthumb-vulnerability', severity: null, title: (k, v) => `${k}: ${str(v['title']) ?? 'timthumb vuln'}` },
  { path: 'config_backups.*', category: 'config-backup', severity: 'high', title: (k) => `config backup exposed: ${k}` },
  { path: 'db_exports.*', category: 'db-export', severity: 'high', title: (k) => `db export exposed: ${k}` },
];

function str(v: unknown): string | undefined { return typeof v === 'string' && v ? v : undefined; }
function urlOf(key: string): string | null { return /^https?:/.test(key) ? key : null; }
function isNode(v: unknown): v is Node { return typeof v === 'object' && v !== null && !Array.isArray(v); }

/** Yields [key, value] for every node `segs` reaches; `key` is the last `*` key, or the theme slug for main_theme. */
function* walk(node: unknown, segs: string[], key = ''): Generator<[string, unknown]> {
  if (segs.length === 0) { yield [key, node]; return; }
  if (!isNode(node)) return;
  const [head, ...rest] = segs as [string, ...string[]];
  if (head === '*') { for (const [k, v] of Object.entries(node)) yield* walk(v, rest, k); return; }
  const child = node[head];
  const slug = head === 'main_theme' && isNode(child) ? str(child['slug']) : undefined;
  yield* walk(child, rest, slug ?? key);
}

function vulnRows(s: Section, key: string, v: Node, seen: Set<string>): WpscanRow[] {
  const title = s.title(key, v);
  const cves = wpscanCves(v as Vuln);
  // main_theme is also listed under themes when all themes are enumerated. Only that overlap is
  // deduplicated, by the vulnerability's identity, so two vulnerabilities sharing a title both stay.
  if (s.category === 'theme-vulnerability') {
    const wpvulndb = isNode(v['references']) ? v['references']['wpvulndb'] : undefined;
    const id = Array.isArray(wpvulndb) && wpvulndb.length ? `db:${wpvulndb.map(String).sort().join(',')}` : `cve:${[...cves].sort().join(',')}`;
    const dedup = `${title}\0${id}`;
    if (seen.has(dedup)) return [];
    seen.add(dedup);
  }
  const score = cvssScore(v['cvss']);
  const vector = str((v['cvss'] as Node | undefined)?.['vector']);
  const meta = { ...v, cves, ...(score !== null ? { cvss: score, cvss_vector: vector } : {}) };
  const severity = wpscanSeverity(v['cvss']);
  // Like nuclei, one row per CVE: cve-rollup reads only the cve column.
  return (cves.length ? cves : [null]).map((cve) => ({ category: s.category, severity, title, cve, matched_at: urlOf(key), meta }));
}

const USERS_IN_TITLE = 5;
const USER_SLUG_MAX = 40;

/** Site-sourced text without control or line-separator characters, which would break markdown reports. */
function plain(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, '');
}

/** Every finding a wpscan document reports, in storable form. */
export function wpscanRows(doc: unknown): WpscanRow[] {
  if (!isNode(doc)) return [];
  const rows: WpscanRow[] = [];
  const interesting = doc['interesting_findings'];
  for (const f of Array.isArray(interesting) ? interesting as Node[] : []) {
    rows.push({ category: str(f['type']) ?? 'interesting', severity: 'info', title: str(f['to_s']) ?? 'interesting finding', cve: null, matched_at: null, meta: f });
  }
  const seen = new Set<string>();
  for (const s of SECTIONS) {
    const segs = s.path.split('.');
    for (const [key, node] of walk(doc, segs)) {
      if (s.severity === null) {
        for (const v of Array.isArray(node) ? node : []) if (isNode(v)) rows.push(...vulnRows(s, key, v, seen));
      } else if (isNode(node)) {
        rows.push({ category: s.category, severity: s.severity, title: s.title(key, node), cve: null, matched_at: urlOf(key), meta: node });
      }
    }
  }
  const users = doc['users'];
  if (isNode(users) && Object.keys(users).length) {
    const list = Object.entries(users).map(([slug, u]) => ({ slug: plain(slug), id: isNode(u) ? u['id'] : undefined, found_by: isNode(u) ? u['found_by'] : undefined }))
      .sort((a, b) => (a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0));
    // The title is part of the logical key, so it stays bounded and the same for the same set of users.
    const shown = list.slice(0, USERS_IN_TITLE).map((u) => u.slug.replace(/,/g, '').slice(0, USER_SLUG_MAX));
    const title = `WordPress users (${list.length}): ${shown.join(', ')}${list.length > USERS_IN_TITLE ? '…' : ''}`;
    rows.push({ category: 'wordpress-users', severity: 'info', title, cve: null, matched_at: null, meta: { users: list } });
  }
  return rows;
}
