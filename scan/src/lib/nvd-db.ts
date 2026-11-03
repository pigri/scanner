// nvd-db: the offline NVD mirror (`nvd.db`), separate from scan.db.
// Holds only what the version matcher needs: application CPE matches and
// the CVSS score per CVE. `nvd-sync.ts` writes it; the matcher reads it.
import fs from 'node:fs';
import Database from 'better-sqlite3';

export const NVD_SCHEMA_VERSION = 1;

export const NVD_DDL = `
CREATE TABLE IF NOT EXISTS cve (
  cve_id        TEXT PRIMARY KEY,
  cvss          REAL,
  cvss_version  TEXT,
  published     TEXT,
  last_modified TEXT
);
CREATE TABLE IF NOT EXISTS cpe_match (
  cve_id     TEXT,
  vendor     TEXT,
  product    TEXT,
  version    TEXT,
  update_    TEXT,
  start_incl TEXT,
  start_excl TEXT,
  end_incl   TEXT,
  end_excl   TEXT
);
CREATE INDEX IF NOT EXISTS idx_cpe_match_vp ON cpe_match(vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpe_match_cve ON cpe_match(cve_id);
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
`;

interface NvdMetric { cvssData?: { baseScore?: number } }
interface NvdCpeMatch {
  vulnerable?: boolean;
  criteria?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}
/** The subset of an NVD 2.0 `vulnerabilities[].cve` object this module reads. */
export interface NvdCveInput {
  id?: string;
  vulnStatus?: string;
  published?: string;
  lastModified?: string;
  metrics?: { cvssMetricV31?: NvdMetric[]; cvssMetricV30?: NvdMetric[]; cvssMetricV2?: NvdMetric[] };
  configurations?: Array<{ nodes?: Array<{ cpeMatch?: NvdCpeMatch[] }> }>;
}

export interface CpeMatchRow {
  cve_id: string;
  vendor: string;
  product: string;
  version: string;
  update_: string;
  start_incl: string | null;
  start_excl: string | null;
  end_incl: string | null;
  end_excl: string | null;
}

export interface CveMeta {
  cvss: number | null;
  cvss_version: string | null;
  published: string | null;
  last_modified: string | null;
}

export interface VulnLookup {
  snapshotAt: string | null;
  cpeMatches(vendor: string, product: string): CpeMatchRow[];
  cveMeta(ids: string[]): Map<string, CveMeta>;
}

export function isRejected(cve: NvdCveInput): boolean {
  return cve.vulnStatus === 'Rejected';
}

/** Split a CPE 2.3 formatted string on unescaped colons and drop the escapes. */
function splitCpe(criteria: string): string[] {
  const parts: string[] = [];
  let cur = '';
  for (let i = 0; i < criteria.length; i++) {
    const ch = criteria[i]!;
    if (ch === '\\' && i + 1 < criteria.length) { cur += criteria[++i]!; continue; }
    if (ch === ':') { parts.push(cur); cur = ''; continue; }
    cur += ch;
  }
  parts.push(cur);
  return parts;
}

const nn = (s: string | undefined): string | null => (s && s.length > 0 ? s : null);

/** Application, vulnerable, bounded CPE matches of one CVE. */
export function cpeRowsFromCve(cve: NvdCveInput): CpeMatchRow[] {
  if (!cve.id || isRejected(cve)) return [];
  const rows: CpeMatchRow[] = [];
  for (const cfg of cve.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (m.vulnerable !== true || !m.criteria) continue;
        const p = splitCpe(m.criteria);
        if (p[0] !== 'cpe' || p[1] !== '2.3' || p[2] !== 'a') continue;
        const vendor = p[3], product = p[4], version = p[5];
        if (!vendor || !product || !version) continue;
        const row: CpeMatchRow = {
          cve_id: cve.id,
          vendor,
          product,
          version,
          update_: p[6] || '*',
          start_incl: nn(m.versionStartIncluding),
          start_excl: nn(m.versionStartExcluding),
          end_incl: nn(m.versionEndIncluding),
          end_excl: nn(m.versionEndExcluding),
        };
        const bounded = row.start_incl || row.start_excl || row.end_incl || row.end_excl;
        if ((version === '*' || version === '-') && !bounded) continue;
        rows.push(row);
      }
    }
  }
  return rows;
}

/** CVSS v3.1 > v3.0 > v2, first metric present wins. */
export function cveMetaFromCve(cve: NvdCveInput): CveMeta {
  const m = cve.metrics;
  const picks: Array<[NvdMetric[] | undefined, string]> = [
    [m?.cvssMetricV31, '3.1'],
    [m?.cvssMetricV30, '3.0'],
    [m?.cvssMetricV2, '2.0'],
  ];
  let cvss: number | null = null;
  let cvss_version: string | null = null;
  for (const [list, ver] of picks) {
    const score = list?.[0]?.cvssData?.baseScore;
    if (typeof score === 'number') { cvss = score; cvss_version = ver; break; }
  }
  return { cvss, cvss_version, published: cve.published ?? null, last_modified: cve.lastModified ?? null };
}

/** Write side. All writes sit in one transaction until `commit()`. */
export class NvdWriter {
  private db: Database.Database;
  private done = false;
  private insCve;
  private delCve;
  private delMatches;
  private insMatch;
  private setMetaStmt;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma('synchronous = OFF');
    this.db.exec(NVD_DDL);
    this.db.exec('BEGIN');
    this.insCve = this.db.prepare(
      'INSERT OR REPLACE INTO cve (cve_id, cvss, cvss_version, published, last_modified) VALUES (?,?,?,?,?)');
    this.delCve = this.db.prepare('DELETE FROM cve WHERE cve_id = ?');
    this.delMatches = this.db.prepare('DELETE FROM cpe_match WHERE cve_id = ?');
    this.insMatch = this.db.prepare(
      `INSERT INTO cpe_match (cve_id, vendor, product, version, update_, start_incl, start_excl, end_incl, end_excl)
       VALUES (@cve_id,@vendor,@product,@version,@update_,@start_incl,@start_excl,@end_incl,@end_excl)`);
    this.setMetaStmt = this.db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)');
    this.setMeta('schema_version', String(NVD_SCHEMA_VERSION));
  }

  insertCve(id: string, meta: CveMeta): void {
    this.insCve.run(id, meta.cvss, meta.cvss_version, meta.published, meta.last_modified);
  }

  insertMatches(rows: CpeMatchRow[]): void {
    for (const r of rows) this.insMatch.run(r);
  }

  /** Replace everything stored for a CVE; a Rejected CVE is removed. */
  upsertCve(cve: NvdCveInput): void {
    if (!cve.id) return;
    this.delMatches.run(cve.id);
    if (isRejected(cve)) { this.delCve.run(cve.id); return; }
    const rows = cpeRowsFromCve(cve);
    this.insertCve(cve.id, cveMetaFromCve(cve));
    this.insertMatches(rows);
  }

  setMeta(key: string, value: string): void {
    this.setMetaStmt.run(key, value);
  }

  getMeta(key: string): string | null {
    const r = this.db.prepare('SELECT value FROM meta WHERE key = ?').get(key) as { value: string } | undefined;
    return r?.value ?? null;
  }

  counts(): { cves: number; matches: number } {
    const c = (this.db.prepare('SELECT COUNT(*) n FROM cve').get() as { n: number }).n;
    const m = (this.db.prepare('SELECT COUNT(*) n FROM cpe_match').get() as { n: number }).n;
    return { cves: c, matches: m };
  }

  commit(): void {
    if (this.done) return;
    this.done = true;
    this.db.exec('COMMIT');
    this.db.close();
  }

  /** Abandon the transaction (used when a build fails). */
  abort(): void {
    if (this.done) return;
    this.done = true;
    try { this.db.exec('ROLLBACK'); } catch { /* ignore */ }
    this.db.close();
  }
}

/**
 * Run `build(tmpPath)` against `<finalPath>.tmp`, then rename over finalPath.
 * If build throws, the tmp file is removed and finalPath is left untouched.
 */
export async function replaceAtomically(
  finalPath: string,
  build: (tmpPath: string) => void | Promise<void>,
): Promise<void> {
  const tmp = `${finalPath}.tmp`;
  rmTmp(tmp);
  try {
    await build(tmp);
    fs.renameSync(tmp, finalPath);
  } catch (e) {
    rmTmp(tmp);
    throw e;
  }
}

function rmTmp(tmp: string): void {
  for (const s of ['', '-journal', '-wal', '-shm']) {
    try { fs.rmSync(tmp + s, { force: true }); } catch { /* ignore */ }
  }
}

/** Open nvd.db read-only. Never throws: null when missing, unreadable or the wrong schema. */
export function openNvdLookup(path: string): VulnLookup | null {
  let db: Database.Database | null = null;
  try {
    db = new Database(path, { readonly: true, fileMustExist: true });
    const metaVal = (k: string): string | null => {
      const r = db!.prepare('SELECT value FROM meta WHERE key = ?').get(k) as { value: string } | undefined;
      return r?.value ?? null;
    };
    if (metaVal('schema_version') !== String(NVD_SCHEMA_VERSION)) {
      db.close();
      return null;
    }
    const snapshotAt = metaVal('snapshot_at');
    const handle = db;
    const byProduct = handle.prepare(
      `SELECT cve_id, vendor, product, version, update_, start_incl, start_excl, end_incl, end_excl
         FROM cpe_match WHERE vendor = ? AND product = ?`);
    return {
      snapshotAt,
      cpeMatches: (vendor, product) => byProduct.all(vendor, product) as CpeMatchRow[],
      cveMeta: (ids) => {
        const out = new Map<string, CveMeta>();
        const stmt = handle.prepare(
          'SELECT cve_id, cvss, cvss_version, published, last_modified FROM cve WHERE cve_id = ?');
        for (const id of ids) {
          const r = stmt.get(id) as (CveMeta & { cve_id: string }) | undefined;
          if (r) out.set(id, { cvss: r.cvss, cvss_version: r.cvss_version, published: r.published, last_modified: r.last_modified });
        }
        return out;
      },
    };
  } catch {
    try { db?.close(); } catch { /* ignore */ }
    return null;
  }
}

/** The stored incremental cursor, or null when absent/empty/unreadable (partial builds have none). */
export function readSyncCursor(path: string): string | null {
  let db: Database.Database | null = null;
  try {
    db = new Database(path, { readonly: true, fileMustExist: true });
    const r = db.prepare("SELECT value FROM meta WHERE key = 'sync_cursor'").get() as { value: string } | undefined;
    return r?.value ? r.value : null;
  } catch {
    return null;
  } finally {
    try { db?.close(); } catch { /* ignore */ }
  }
}
