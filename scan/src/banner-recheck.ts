#!/usr/bin/env -S node --loader tsx
// Second-pass Server-banner recovery. httpx's browser-like request profile makes
// some servers (e.g. MinIO) answer with a banner-less redirect, so http_probes
// holds a row with web_server NULL and synthesize-eol can never classify the
// host. Re-probe those hosts with a minimal request and insert a supplementary
// http_probes row carrying the recovered banner.
import { parseCommonCli, commonUsage, prepareTargets } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';

type FetchFn = (url: string, init: RequestInit) => Promise<Response>;

export interface BannerRecheckOpts {
  fetchFn?: FetchFn;
  concurrency?: number;
  timeoutSec?: number;
}

interface Candidate { target: string; url: string }

function loadNullBanner(db: Db, targets: readonly string[]): Candidate[] {
  if (!targets.length) return [];
  const placeholders = targets.map(() => '?').join(',');
  const rows = db.raw.prepare(
    `SELECT DISTINCT target, url FROM http_probes
     WHERE url LIKE 'http%' AND target IN (${placeholders})
       AND target NOT IN (SELECT target FROM http_probes WHERE web_server IS NOT NULL)`
  ).all(...targets) as Candidate[];
  // One url per target, https preferred.
  const byTarget = new Map<string, Candidate>();
  for (const r of rows) {
    const existing = byTarget.get(r.target);
    if (!existing || (!existing.url.startsWith('https://') && r.url.startsWith('https://'))) byTarget.set(r.target, r);
  }
  return [...byTarget.values()];
}

// Minimal on purpose: a browser-like profile is what makes MinIO drop the banner.
const MINIMAL_HEADERS = { 'User-Agent': 'banner-recheck/1.0' };

async function probe(fetchFn: FetchFn, url: string, method: 'HEAD' | 'GET', timeoutSec: number): Promise<{ status: number; server: string | null }> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutSec * 1000);
  try {
    const resp = await fetchFn(url, { method, redirect: 'manual', signal: ctl.signal, headers: MINIMAL_HEADERS });
    if (method === 'GET') await resp.body?.cancel().catch(() => undefined);
    const server = resp.headers.get('server')?.trim();
    return { status: resp.status, server: server ? server : null };
  } finally {
    clearTimeout(t);
  }
}

export async function runBannerRecheck(
  db: Db,
  targets: readonly string[],
  now: string,
  runId: number | null,
  opts: BannerRecheckOpts = {},
): Promise<{ candidates: number; recovered: number }> {
  const fetchFn: FetchFn = opts.fetchFn ?? ((u, i) => fetch(u, i));
  const concurrency = opts.concurrency ?? 20;
  const timeoutSec = opts.timeoutSec ?? 10;
  const candidates = loadNullBanner(db, targets);
  let recovered = 0;
  let idx = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const i = idx++;
      if (i >= candidates.length) return;
      const c = candidates[i]!;
      try {
        let r = await probe(fetchFn, c.url, 'HEAD', timeoutSec);
        if (!r.server) r = await probe(fetchFn, c.url, 'GET', timeoutSec);
        if (r.server) {
          db.insertHttpProbe({ target: c.target, url: c.url, status_code: r.status, web_server: r.server }, now, runId);
          recovered++;
        }
      } catch {
        // unreachable / timed out: leave no row
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, candidates.length) }, worker));
  return { candidates: candidates.length, recovered };
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let concurrency = 20;
  let timeoutSec = 10;
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    if (a === '--concurrency' || a === '-c') concurrency = parseInt(opts.extraArgs[++i]!, 10);
    else if (a === '--timeout') timeoutSec = parseInt(opts.extraArgs[++i]!, 10);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('banner-recheck', `
Re-probe hosts httpx recorded without a Server banner using a minimal HEAD
(GET fallback, redirects not followed) and insert a supplementary http_probes
row when a banner is recovered. Feeds synthesize-eol.

Requires --sqlite.

Wrapper flags (after '--'):
  --concurrency/-c <N>  parallel probes (default: 20)
  --timeout <s>         per-request timeout (default: 10)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  if (!opts.sqlite) { console.error('banner-recheck: --sqlite is required'); process.exit(1); }

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = openDb(opts.sqlite);
  const runId = db.startRun('banner-recheck', { targets: targets.length, concurrency, timeoutSec }, now);
  const { candidates, recovered } = await runBannerRecheck(db, targets, now, runId, { concurrency, timeoutSec });
  db.finishRun(runId, { targetsCount: candidates, findingsCount: 0, at: new Date().toISOString() });
  db.close();
  console.error(`banner-recheck done: ${recovered} banner(s) recovered from ${candidates} null-banner host(s), run #${runId}`);
}

if (process.argv[1]?.endsWith('banner-recheck.ts')) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
