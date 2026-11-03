#!/usr/bin/env -S node --loader tsx
// nvd-sync: mirror the NVD 2.0 CVE feed into a local `nvd.db` (CPE matches +
// CVSS only) so version-match can run with no network at scan time.
//
// Full mode rebuilds from scratch; incremental mode copies the existing db and
// applies `lastModStartDate` windows (<=120 days each) since `meta.sync_cursor`.
// The new file is built at `<nvd-db>.tmp` and renamed over the old one only on
// success, so a failed sync never damages the previous snapshot.
//
// Rate limit: 5 req/30s without NVD_API_KEY, 50 req/30s with it.
import fs from 'node:fs';
import path from 'node:path';
import { NvdWriter, readSyncCursor, replaceAtomically, type NvdCveInput } from './lib/nvd-db.js';

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE_SIZE = 2000;
const WINDOW_MS = 119 * 24 * 3600 * 1000;   // NVD caps a lastMod range at 120 days
const REQUEST_TIMEOUT_MS = 60_000;

interface NvdPage { totalResults?: number; vulnerabilities?: Array<{ cve?: NvdCveInput }> }

export interface RetryOpts {
  fetchFn?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  maxAttempts?: number;
  baseDelayMs?: number;
}

class FatalHttp extends Error {
  constructor(status: number) { super(`HTTP ${status}`); }
}

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** GET a JSON page; back off and retry on HTTP 429/503 and on network errors/timeouts. */
export async function fetchWithRetry(
  url: string,
  headers: Record<string, string>,
  opts: RetryOpts = {},
): Promise<NvdPage> {
  const fetchFn = opts.fetchFn ?? fetch;
  const sleep = opts.sleep ?? realSleep;
  const maxAttempts = opts.maxAttempts ?? 6;
  const base = opts.baseDelayMs ?? 10_000;
  let lastErr: Error = new Error('no attempt made');
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), REQUEST_TIMEOUT_MS);
    let wait = base * 2 ** (attempt - 1);
    try {
      const r = await fetchFn(url, { headers, signal: ctl.signal });
      if (r.ok) return await r.json() as NvdPage;
      if (r.status !== 429 && r.status !== 503) throw new FatalHttp(r.status);
      lastErr = new Error(`HTTP ${r.status}`);
      const ra = Number(r.headers.get('retry-after'));
      if (Number.isFinite(ra) && ra > 0) wait = Math.max(wait, ra * 1000);
    } catch (e) {
      if (e instanceof FatalHttp) throw e;
      lastErr = e instanceof Error ? e : new Error(String(e));
    } finally {
      clearTimeout(timer);
    }
    if (attempt < maxAttempts) {
      console.error(`  ${lastErr.message}; retry ${attempt}/${maxAttempts - 1} in ${Math.round(wait / 1000)}s`);
      await sleep(wait);
    }
  }
  throw lastErr;
}

interface SyncOpts {
  nvdDb: string;
  full: boolean;
  since: string | null;
  limitPages: number | null;
}

function usage(): void {
  console.error(`Usage: nvd-sync [--nvd-db <path>] [--full] [--since <iso>] [--limit-pages N]

Mirrors NVD 2.0 CPE matches + CVSS into a SQLite file for offline version matching.

Options:
  --nvd-db <path>    output db (default: nvd.db); built at <path>.tmp then renamed
  --full             rebuild from scratch (also the default when no db exists)
  --since <iso>      incremental: fetch CVEs modified since this instant,
                     overriding the stored sync_cursor
  --limit-pages N    stop after N pages (testing); the result is marked partial
                     and has no sync_cursor, so the next run is a full rebuild

Set NVD_API_KEY in env for the higher 50-req/30s rate limit.
`);
}

function nvdDate(d: Date): string {
  return encodeURIComponent(d.toISOString().replace('Z', '+00:00'));
}

export async function runSync(o: SyncOpts): Promise<number> {
  const apiKey = process.env['NVD_API_KEY'];
  const pauseMs = apiKey ? 700 : 6500;
  const headers: Record<string, string> = { 'User-Agent': 'gen0sec-scan/nvd-sync' };
  if (apiKey) headers['apiKey'] = apiKey;
  console.error(`nvd rate: ${apiKey ? '50' : '5'}/30s (${pauseMs}ms pause)`);

  const startedAt = new Date();
  const existing = fs.existsSync(o.nvdDb);
  let cursor: string | null = o.since;
  if (!o.full && existing && !cursor) {
    cursor = readSyncCursor(o.nvdDb);
    if (!cursor) console.error('no sync_cursor in existing db; falling back to a full rebuild');
  }
  const incremental = !o.full && existing && cursor !== null;

  const windows: Array<string | null> = [];   // null = unfiltered full pull
  if (incremental) {
    let from = new Date(cursor!);
    if (Number.isNaN(from.getTime())) throw new Error(`bad cursor/--since: ${cursor}`);
    while (from < startedAt) {
      const to = new Date(Math.min(from.getTime() + WINDOW_MS, startedAt.getTime()));
      windows.push(`lastModStartDate=${nvdDate(from)}&lastModEndDate=${nvdDate(to)}`);
      from = to;
    }
  } else {
    windows.push(null);
  }
  console.error(`nvd-sync: ${incremental ? `incremental since ${cursor}` : 'full rebuild'}, ${windows.length} window(s)`);

  let pages = 0;
  let truncated = false;
  let cves = 0;
  let matches = 0;
  const t0 = Date.now();

  await replaceAtomically(o.nvdDb, async (tmp) => {
    if (incremental) fs.copyFileSync(o.nvdDb, tmp);
    const w = new NvdWriter(tmp);
    try {
      outer:
      for (const win of windows) {
        let startIndex = 0;
        let total = Infinity;
        while (startIndex < total) {
          if (o.limitPages !== null && pages >= o.limitPages) { truncated = true; break outer; }
          const url = `${NVD_URL}?resultsPerPage=${PAGE_SIZE}&startIndex=${startIndex}${win ? `&${win}` : ''}`;
          if (pages > 0) await realSleep(pauseMs);
          const page = await fetchWithRetry(url, headers);
          pages++;
          total = page.totalResults ?? 0;
          const vulns = page.vulnerabilities ?? [];
          for (const v of vulns) {
            if (v.cve) { w.upsertCve(v.cve); cves++; }
          }
          startIndex += PAGE_SIZE;
          if (vulns.length === 0) break;
          console.error(`  page ${pages}: ${Math.min(startIndex, total)}/${total}`);
        }
      }
      w.setMeta('snapshot_at', startedAt.toISOString());
      if (truncated) {
        w.setMeta('partial', '1');
        w.setMeta('sync_cursor', '');
      } else {
        w.setMeta('partial', '0');
        w.setMeta('sync_cursor', startedAt.toISOString());
      }
      matches = w.counts().matches;
      w.commit();
    } catch (e) {
      w.abort();
      throw e;
    }
  });

  console.error(
    `nvd-sync done: ${pages} page(s), ${cves} CVE(s) processed, ${matches} cpe_match rows total, ` +
    `${((Date.now() - t0) / 1000).toFixed(1)}s${truncated ? ' (PARTIAL: --limit-pages)' : ''}`);
  console.error(`  db: ${path.resolve(o.nvdDb)}`);
  return 0;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const o: SyncOpts = { nvdDb: 'nvd.db', full: false, since: null, limitPages: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h' || a === '--help') { usage(); process.exit(0); }
    else if (a === '--nvd-db') o.nvdDb = argv[++i]!;
    else if (a === '--full') o.full = true;
    else if (a === '--since') o.since = argv[++i]!;
    else if (a === '--limit-pages') o.limitPages = parseInt(argv[++i]!, 10);
    else { console.error(`unknown argument: ${a}`); usage(); process.exit(2); }
  }
  process.exit(await runSync(o));
}

// Only run when invoked directly, so tests can import the helpers above.
if (process.argv[1] && process.argv[1].endsWith('nvd-sync.ts')) {
  main().catch((err: unknown) => {
    console.error('FATAL:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
