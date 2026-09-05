#!/usr/bin/env -S node --loader tsx
// security-headers audit — HEAD each live HTTP URL and evaluate the modern
// security-header surface. Complements testssl's binary "security_headers: --"
// with proper per-header severity, and covers the fields testssl doesn't:
// CSP, HSTS-preload, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
// Permissions-Policy, COOP, COEP, CORP.
import { parseCommonCli, commonUsage, prepareTargets, requireTool, resolveOutputPath, writeLines } from './lib/runner.js';
import fs from 'node:fs';
import path from 'node:path';
import { openDb, type Db } from './lib/db.js';

interface LiveUrl { target: string; url: string; scheme: 'http' | 'https' }

function loadLive(db: Db, targets: readonly string[]): LiveUrl[] {
  if (!targets.length) return [];
  const placeholders = targets.map(() => '?').join(',');
  const rows = db.raw.prepare(
    `SELECT DISTINCT target, url FROM http_probes
     WHERE target IN (${placeholders})
       AND (url LIKE 'http://%' OR url LIKE 'https://%')`
  ).all(...targets) as { target: string; url: string }[];
  // Prefer HTTPS per target, but keep http entries when only http exists.
  const bySeed = new Map<string, LiveUrl>();
  for (const r of rows) {
    const scheme: 'http' | 'https' = r.url.startsWith('https://') ? 'https' : 'http';
    const existing = bySeed.get(r.target);
    if (!existing || (existing.scheme === 'http' && scheme === 'https')) {
      bySeed.set(r.target, { target: r.target, url: r.url, scheme });
    }
  }
  return [...bySeed.values()];
}

interface Verdict { severity: 'info' | 'low' | 'medium' | 'high'; title: string; meta?: Record<string, unknown> }

function auditHeaders(headers: Headers, scheme: 'http' | 'https'): Verdict[] {
  const out: Verdict[] = [];
  const H = (name: string): string | null => headers.get(name);

  // --- HSTS -----------------------------------------------------------------
  if (scheme === 'https') {
    const hsts = H('strict-transport-security');
    if (!hsts) {
      out.push({ severity: 'high', title: 'HSTS missing — attacker can strip TLS on first visit' });
    } else {
      const m = /max-age\s*=\s*(\d+)/i.exec(hsts);
      const age = m ? parseInt(m[1]!, 10) : 0;
      if (age < 31536000) {
        out.push({ severity: 'medium', title: `HSTS max-age too short (${age}s, need ≥ 31536000)`, meta: { header: hsts } });
      }
      if (!/includeSubDomains/i.test(hsts)) {
        out.push({ severity: 'low', title: 'HSTS lacks includeSubDomains', meta: { header: hsts } });
      }
      if (!/preload/i.test(hsts)) {
        out.push({ severity: 'info', title: 'HSTS lacks preload flag (browser preload list opt-in)', meta: { header: hsts } });
      }
    }
  }

  // --- CSP ------------------------------------------------------------------
  const csp = H('content-security-policy');
  if (!csp) {
    out.push({ severity: 'medium', title: 'Content-Security-Policy missing — no in-browser XSS containment' });
  } else {
    if (/unsafe-inline/i.test(csp)) {
      out.push({ severity: 'low', title: 'CSP allows unsafe-inline (weakens XSS containment)', meta: { header: csp.slice(0, 400) } });
    }
    if (/unsafe-eval/i.test(csp)) {
      out.push({ severity: 'low', title: 'CSP allows unsafe-eval', meta: { header: csp.slice(0, 400) } });
    }
    if (/(^|\s)\*(\s|$|;)/.test(csp) || /\bdefault-src\s+\*/i.test(csp)) {
      out.push({ severity: 'medium', title: 'CSP contains wildcard * source (permissive)', meta: { header: csp.slice(0, 400) } });
    }
  }

  // --- X-Frame-Options / frame-ancestors -----------------------------------
  const xfo = H('x-frame-options');
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !frameAncestors) {
    out.push({ severity: 'medium', title: 'X-Frame-Options / CSP frame-ancestors missing — clickjacking risk' });
  }

  // --- X-Content-Type-Options ---------------------------------------------
  const xcto = H('x-content-type-options');
  if (!xcto || xcto.trim().toLowerCase() !== 'nosniff') {
    out.push({ severity: 'low', title: 'X-Content-Type-Options missing (needs "nosniff")' });
  }

  // --- Referrer-Policy -----------------------------------------------------
  if (!H('referrer-policy')) {
    out.push({ severity: 'low', title: 'Referrer-Policy missing (default leaks Referer cross-origin)' });
  }

  // --- Permissions-Policy --------------------------------------------------
  if (!H('permissions-policy') && !H('feature-policy')) {
    out.push({ severity: 'info', title: 'Permissions-Policy missing (browser API surface not restricted)' });
  }

  // --- COOP / COEP / CORP --------------------------------------------------
  if (!H('cross-origin-opener-policy')) {
    out.push({ severity: 'info', title: 'Cross-Origin-Opener-Policy missing' });
  }
  if (!H('cross-origin-embedder-policy')) {
    out.push({ severity: 'info', title: 'Cross-Origin-Embedder-Policy missing' });
  }
  // CORP is server-side per-resource; only flag if the top-level page ships it
  // permissively.
  const corp = H('cross-origin-resource-policy');
  if (corp && /cross-origin/i.test(corp)) {
    out.push({ severity: 'info', title: 'CORP: cross-origin — resource embeddable from any origin', meta: { header: corp } });
  }

  // --- Server / X-Powered-By ---------------------------------------------
  const sv = H('server');
  if (sv && /\d/.test(sv)) {
    out.push({ severity: 'info', title: `Server banner leaks version: ${sv}`, meta: { header: sv } });
  }
  const xpb = H('x-powered-by');
  if (xpb) {
    out.push({ severity: 'info', title: `X-Powered-By header discloses stack: ${xpb}`, meta: { header: xpb } });
  }

  // --- Cookie hygiene (Set-Cookie) ---------------------------------------
  // Node's fetch collapses multiple Set-Cookie into a comma-joined string via
  // getSetCookie(); use that when available.
  const cookies: string[] =
    typeof (headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === 'function'
      ? (headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
      : (H('set-cookie') ? [H('set-cookie')!] : []);
  for (const c of cookies) {
    const secure = /;\s*Secure/i.test(c);
    const httpOnly = /;\s*HttpOnly/i.test(c);
    if (scheme === 'https' && !secure) {
      out.push({ severity: 'low', title: 'Cookie set without Secure flag on HTTPS', meta: { cookie: c.slice(0, 200) } });
    }
    if (!httpOnly) {
      out.push({ severity: 'low', title: 'Cookie set without HttpOnly flag', meta: { cookie: c.slice(0, 200) } });
    }
  }

  return out;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let concurrency = 20;
  let timeoutSec = 10;
  let liveOnly = true;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--concurrency' || a === '-c') concurrency = parseInt(nxt(), 10);
    else if (a === '--timeout') timeoutSec = parseInt(nxt(), 10);
    else if (a === '--no-live-only') liveOnly = false;
    else passthrough.push(a);
  }
  if (passthrough.length) { /* reserved for future flags */ }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('headers', `
Audit modern security headers for each live target's root URL.
Emits findings per missing / weak / permissive header — HSTS, CSP,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
COOP, COEP, CORP, plus cookie-flag hygiene and server-banner leakage.

Requires --sqlite (URL sample from http_probes).

Wrapper flags (before '--'):
  --concurrency/-c <N>  parallel HEAD requests (default: 20)
  --timeout <s>         per-request timeout (default: 10)
  --no-live-only        include hosts httpx never saw alive`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('curl'); // fetch is builtin, but keeping the same "external tool" convention no-ops
  if (!opts.sqlite) { console.error('headers: --sqlite is required'); process.exit(1); }

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = openDb(opts.sqlite);
  const runId = db.startRun('headers', { targets: targets.length, concurrency, liveOnly }, now);

  let urls: LiveUrl[];
  if (liveOnly) {
    urls = loadLive(db, targets);
  } else {
    urls = targets.map((t) => ({ target: t, url: `https://${t}`, scheme: 'https' as const }));
  }
  console.error(`headers audit: ${urls.length} live target URL(s)`);

  const outFile = resolveOutputPath(opts, runId, 'headers.jsonl');
  const wstream = fs.createWriteStream(outFile);

  let findings = 0;
  let idx = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const i = idx++;
      if (i >= urls.length) return;
      const u = urls[i]!;
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), timeoutSec * 1000);
      try {
        // HEAD first — many servers omit security headers on HEAD, so fall
        // back to a full GET if we get nothing back. Small perf cost, worth
        // it for coverage.
        let resp: Response;
        try {
          resp = await fetch(u.url, { method: 'HEAD', signal: ctl.signal, redirect: 'follow', headers: { 'User-Agent': 'headers-audit/1.0' } });
          if (![...resp.headers.keys()].length) {
            resp = await fetch(u.url, { method: 'GET', signal: ctl.signal, redirect: 'follow', headers: { 'User-Agent': 'headers-audit/1.0' } });
          }
        } catch {
          resp = await fetch(u.url, { method: 'GET', signal: ctl.signal, redirect: 'follow', headers: { 'User-Agent': 'headers-audit/1.0' } });
        }
        const verdicts = auditHeaders(resp.headers, u.scheme);
        wstream.write(JSON.stringify({ target: u.target, url: u.url, status: resp.status, findings: verdicts }) + '\n');
        for (const v of verdicts) {
          db.insertFinding({
            tool: 'headers',
            target: u.target,
            category: v.title.split(' ')[0]!.toLowerCase().replace(/[^a-z0-9]/g, '-'),
            severity: v.severity,
            title: v.title,
            cve: null,
            matched_at: u.url,
            meta: v.meta ?? { status: resp.status },
          }, now, runId);
          findings++;
        }
      } catch (e) {
        wstream.write(JSON.stringify({ target: u.target, url: u.url, error: e instanceof Error ? e.message : String(e) }) + '\n');
      } finally {
        clearTimeout(t);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, urls.length) }, worker));
  await new Promise<void>((res) => wstream.end(() => res()));

  db.finishRun(runId, { targetsCount: urls.length, findingsCount: findings, at: new Date().toISOString() });
  db.close();
  console.error(`headers done: +${findings} finding(s) across ${urls.length} target(s), run #${runId}`);
  console.error(`  sqlite: ${path.resolve(opts.sqlite)}`);
  void writeLines;   // silence unused-import linter — kept for cross-wrapper consistency
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
