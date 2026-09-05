#!/usr/bin/env -S node --loader tsx
// content-sigs: probe high-value paths (.git, .env, phpinfo, actuator/env, …)
// and match the RESPONSE BODY against content signatures — not status/length.
//
// Why: on this estate, WAFs / CDN error pages normalize every miss to a
// uniform-length 403 or 404. Path-existence probing via status/length is
// dead — every probe returns byte-identical to every other probe, and
// ffuf's dedup correctly drops the whole batch. Content-signature check
// is immune: `.git/HEAD` counts as a hit only if the body starts with
// `ref: refs/`, no matter what status code the server slapped on it.
//
// Each signature has an explicit severity mapped to the sensitivity of the
// exposed artefact: private keys → critical; source-control + env creds →
// high; server-info dumps → medium; benign well-known files → info.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Sig {
  path: string;
  sev: Sev;
  desc: string;
  // Matcher against the response body. First param is the raw body (string),
  // second is the raw first-few-hundred-bytes as a Buffer (for binary magic).
  // Return true if this body is a genuine hit (real artefact), not a WAF page.
  match: (body: string, head: Buffer) => boolean;
  // Optional method + body-cap override (default GET, 128 KB).
  method?: 'GET' | 'HEAD';
  maxBytes?: number;
}

// Curated set. Every signature is deliberately strict — we accept false
// negatives over false positives. Add new patterns only when you can point
// at a body substring or magic-byte sequence that WAFs won't accidentally
// produce.
const SIGS: Sig[] = [
  // ── source control (source-code leakage) ──────────────────────────────
  { path: '.git/HEAD', sev: 'high',
    desc: 'Git HEAD file — enables source-tree clone via .git/objects/*',
    match: (b) => /^ref:\s+refs\//m.test(b) || /^[0-9a-f]{40}\s*$/m.test(b) },
  { path: '.git/config', sev: 'high',
    desc: 'Git config — contains repo URLs and optionally credentials (url = https://user:pass@...)',
    match: (b) => /\[core\]/.test(b) && /repositoryformatversion/i.test(b) },
  { path: '.git/index', sev: 'high',
    desc: 'Git index — binary file listing every tracked path',
    match: (_b, head) => head.length >= 4 && head[0] === 0x44 && head[1] === 0x49 && head[2] === 0x52 && head[3] === 0x43 },   // "DIRC"
  { path: '.git/logs/HEAD', sev: 'high',
    desc: 'Git reflog — every commit + committer + timestamp',
    match: (b) => /^0{40}\s+[0-9a-f]{40}\s/m.test(b) },
  { path: '.svn/entries', sev: 'high',
    desc: 'SVN entries file — svn ≤ 1.6 metadata',
    match: (b) => /^\d+\s*$/m.test(b.split(/\r?\n/)[0] ?? '') || /svn:this_dir/.test(b) },
  { path: '.svn/wc.db', sev: 'high',
    desc: 'SVN 1.7+ working-copy database (SQLite)',
    match: (_b, head) => head.slice(0, 15).toString() === 'SQLite format 3' },
  { path: '.hg/hgrc', sev: 'high',
    desc: 'Mercurial repo config',
    match: (b) => /\[paths\]|\[ui\]|\[extensions\]/.test(b) },
  { path: '.bzr/branch/branch.conf', sev: 'high',
    desc: 'Bazaar branch config',
    match: (b) => /\bparent_location\b/i.test(b) },

  // ── environment / secrets ─────────────────────────────────────────────
  { path: '.env', sev: 'critical',
    desc: 'Environment file — likely leaks credentials / API tokens',
    match: (b) => envFileLooksReal(b) },
  { path: '.env.production', sev: 'critical', desc: '.env.production', match: (b) => envFileLooksReal(b) },
  { path: '.env.local',      sev: 'critical', desc: '.env.local',      match: (b) => envFileLooksReal(b) },
  { path: '.env.development', sev: 'high',    desc: '.env.development', match: (b) => envFileLooksReal(b) },
  { path: '.env.backup',      sev: 'critical', desc: '.env.backup',    match: (b) => envFileLooksReal(b) },
  { path: 'credentials',      sev: 'critical', desc: 'AWS-style credentials file',
    match: (b) => /\[(default|profile\s+\S+)\]/.test(b) && /aws_access_key_id/i.test(b) },
  { path: '.aws/credentials', sev: 'critical', desc: 'AWS credentials profile',
    match: (b) => /aws_access_key_id/i.test(b) && /aws_secret_access_key/i.test(b) },
  { path: 'id_rsa',     sev: 'critical', desc: 'RSA private key',
    match: (b) => /-----BEGIN (RSA |OPENSSH |ENCRYPTED |EC |DSA )?PRIVATE KEY-----/.test(b) },
  { path: 'id_dsa',     sev: 'critical', desc: 'DSA private key', match: (b) => /-----BEGIN DSA PRIVATE KEY-----/.test(b) },
  { path: 'server-key.pem', sev: 'critical', desc: 'TLS server private key',
    match: (b) => /-----BEGIN (RSA |EC )?PRIVATE KEY-----/.test(b) },
  { path: '.htpasswd', sev: 'high', desc: 'Apache htpasswd file (contains hashes)',
    match: (b) => /^[^\s:]+:\$(1|2[axy]?|5|6|apr1)\$/m.test(b) || /^[^\s:]+:\{SHA\}/m.test(b) },

  // ── framework config leaks ────────────────────────────────────────────
  { path: 'wp-config.php.bak', sev: 'critical',
    desc: 'WordPress wp-config backup — contains DB_PASSWORD + AUTH keys',
    match: (b) => /DB_PASSWORD/.test(b) || /AUTH_KEY/.test(b) },
  { path: 'wp-config.php~', sev: 'critical', desc: 'wp-config editor backup', match: (b) => /DB_PASSWORD/.test(b) },
  { path: 'wp-config.php.old', sev: 'critical', desc: 'wp-config .old', match: (b) => /DB_PASSWORD/.test(b) },
  { path: 'wp-config.php.swp', sev: 'critical', desc: 'wp-config vim .swp', match: (b) => /DB_PASSWORD/.test(b) || /table_prefix/.test(b) },
  { path: 'config.php.bak', sev: 'high', desc: 'PHP config backup',
    match: (b) => /^<\?php/.test(b) && /(password|secret|token)/i.test(b) },
  { path: 'app/config/parameters.yml', sev: 'high',
    desc: 'Symfony parameters.yml — DB creds + mailer + secret',
    match: (b) => /^parameters:/m.test(b) && /(password|secret)/i.test(b) },
  { path: 'config/database.yml', sev: 'high',
    desc: 'Rails database.yml',
    match: (b) => /(adapter|password|username):/m.test(b) && /(production|development):/m.test(b) },
  { path: 'settings.py.bak', sev: 'high',
    desc: 'Django settings.py backup',
    match: (b) => /SECRET_KEY\s*=/.test(b) && /INSTALLED_APPS/.test(b) },

  // ── build / package metadata (usually low-sev but stack disclosure) ──
  { path: 'composer.json', sev: 'low',
    desc: 'PHP composer manifest — dependency + version fingerprint',
    match: (b) => /^\s*\{[\s\S]*"require"/m.test(b) },
  { path: 'composer.lock', sev: 'low',
    desc: 'composer.lock — resolved versions (map to CVEs)',
    match: (b) => /"content-hash"/.test(b) && /"packages"/.test(b) },
  { path: 'package.json', sev: 'low',
    desc: 'Node package.json',
    match: (b) => /^\s*\{[\s\S]*"name"/m.test(b) && /"dependencies"|"devDependencies"|"scripts"/.test(b) },
  { path: 'package-lock.json', sev: 'low',
    desc: 'package-lock.json — resolved npm versions',
    match: (b) => /"lockfileVersion"/.test(b) },

  // ── build / test artefacts ────────────────────────────────────────────
  { path: 'phpinfo.php',   sev: 'medium', desc: 'phpinfo() output — full env + module list',
    match: (b) => /<title>phpinfo\(\)/i.test(b) || /PHP Version <\/td>/.test(b) },
  { path: 'info.php',      sev: 'medium', desc: 'phpinfo() alias',
    match: (b) => /<title>phpinfo\(\)/i.test(b) || /PHP Version <\/td>/.test(b) },
  { path: 'test.php',      sev: 'medium', desc: 'phpinfo dropped as test.php',
    match: (b) => /<title>phpinfo\(\)/i.test(b) },

  // ── server-status / server-info / metrics ────────────────────────────
  { path: 'server-status', sev: 'medium',
    desc: 'mod_status dump — live request table + child worker stats',
    match: (b) => /<title>Apache Status<\/title>/i.test(b) || /Apache Server Status for/i.test(b) },
  { path: 'server-info', sev: 'medium',
    desc: 'mod_info dump — loaded modules + directives + compile options',
    match: (b) => /<title>Apache Server Information<\/title>/i.test(b) || /Server Version:/i.test(b) },
  { path: 'nginx_status', sev: 'medium',
    desc: 'nginx stub_status',
    match: (b) => /Active connections:\s+\d+/.test(b) && /Reading:\s+\d+/.test(b) },
  { path: 'metrics', sev: 'medium',
    desc: 'Prometheus /metrics endpoint (Grafana, Kubernetes, Java, Go apps)',
    match: (b) => /^# HELP /m.test(b) && /^# TYPE /m.test(b) },

  // ── java/spring boot actuator ────────────────────────────────────────
  { path: 'actuator/env', sev: 'high',
    desc: 'Spring Boot /actuator/env — env vars + application properties',
    match: (b) => /"activeProfiles"/.test(b) || /"propertySources"/.test(b) },
  { path: 'actuator/health', sev: 'low',
    desc: 'Spring Boot /actuator/health — component health map (info-level unless UP + DB details)',
    match: (b) => /^\s*\{"status":"(UP|DOWN|OUT_OF_SERVICE)/.test(b) },
  { path: 'actuator/heapdump', sev: 'critical',
    desc: 'Spring Boot heap dump — object contents, likely creds in memory',
    match: (_b, head) => head.length >= 4 && head[0] === 0x1f && head[1] === 0x8b   // gzipped hprof
      || head.length >= 4 && head.slice(0, 4).toString() === 'JAVA' },
  { path: 'actuator/mappings', sev: 'medium', desc: 'Spring Boot request-mapping list',
    match: (b) => /"mappings"/.test(b) && /"handler"/.test(b) },
  { path: 'actuator/beans', sev: 'medium', desc: 'Spring Boot bean graph',
    match: (b) => /"contexts"/.test(b) && /"beans"/.test(b) },

  // ── swagger / openapi / graphql (spec disclosure is info; useful for kiterunner)
  { path: 'swagger.json',  sev: 'info', desc: 'Swagger spec',       match: (b) => /"swagger"|"openapi"/.test(b) },
  { path: 'openapi.json',  sev: 'info', desc: 'OpenAPI spec',       match: (b) => /"openapi"\s*:/.test(b) },
  { path: 'v1/swagger.json', sev: 'info', desc: 'Swagger v1',        match: (b) => /"swagger"|"openapi"/.test(b) },
  { path: 'v2/api-docs',   sev: 'info', desc: 'Springfox api-docs', match: (b) => /"swagger"|"openapi"/.test(b) },

  // ── .well-known ──────────────────────────────────────────────────────
  { path: '.well-known/security.txt', sev: 'info',
    desc: 'security.txt — recommended, only reported for coverage tracking',
    match: (b) => /^Contact:/im.test(b) || /^Expires:/im.test(b) },

  // ── misc leaky files ──────────────────────────────────────────────────
  { path: '.DS_Store', sev: 'medium',
    desc: 'macOS Finder metadata — directory listing leak (Bud1 magic)',
    match: (_b, head) => head.length >= 8 && head.slice(0, 4).toString('hex') === '00000001' && head.slice(4, 8).toString() === 'Bud1' },
  { path: '.bash_history', sev: 'high',
    desc: 'Shell history — often contains hostnames, args, credentials in argv',
    match: (b) => /^(ls|cd|ssh|scp|curl|wget|sudo|export|history)/m.test(b) },
  { path: '.npmrc', sev: 'high',
    desc: 'npm rc — often contains _authToken (npm private-registry credential)',
    match: (b) => /_authToken\s*=|registry\s*=/i.test(b) },
  { path: '.htaccess', sev: 'medium',
    desc: 'Apache .htaccess — rewrite rules + auth config',
    match: (b) => /RewriteEngine|AuthType|AuthUserFile|Deny from|Allow from/i.test(b) },
  { path: 'Dockerfile', sev: 'low',
    desc: 'Dockerfile — build recipe (base image, exposed ports, ENTRYPOINT)',
    match: (b) => /^FROM\s+/m.test(b) },
  { path: 'docker-compose.yml', sev: 'medium',
    desc: 'docker-compose — service topology, often env vars with secrets',
    match: (b) => /^services:/m.test(b) || /^version:\s+["']?[23]/m.test(b) },
];

function envFileLooksReal(b: string): boolean {
  // Reject obvious HTML/JSON/generic-error bodies.
  if (/<html|<title|<!DOCTYPE|"error":|"message":/i.test(b.slice(0, 400))) return false;
  // Require at least 2 lines that look like KEY=VALUE with an uppercase key
  // (dotenv convention) — cheap enough to be robust against WAF error pages
  // that occasionally include the string "PATH=..." somewhere.
  const lines = b.split(/\r?\n/).slice(0, 200);
  let kvCount = 0;
  for (const line of lines) {
    if (/^[A-Z][A-Z0-9_]{2,}\s*=/.test(line)) kvCount++;
    if (kvCount >= 2) return true;
  }
  return false;
}

interface LiveUrl { target: string; seed: string }

function loadLive(db: Db, targets: readonly string[]): LiveUrl[] {
  const filter = targets.length ? `AND target IN (${targets.map(() => '?').join(',')})` : '';
  const rows = db.raw.prepare(
    `SELECT DISTINCT target, url FROM http_probes
     WHERE (url LIKE 'http://%' OR url LIKE 'https://%') ${filter}`
  ).all(...targets) as { target: string; url: string }[];
  const bySeed = new Map<string, LiveUrl>();
  for (const r of rows) {
    const existing = bySeed.get(r.target);
    if (!existing || (existing.seed.startsWith('http://') && r.url.startsWith('https://'))) {
      bySeed.set(r.target, { target: r.target, seed: r.url.replace(/\/+$/, '') });
    }
  }
  return [...bySeed.values()];
}

interface Hit { target: string; url: string; sig: Sig; status: number; length: number }

async function probe(seed: string, sig: Sig, timeoutMs: number, maxBytes: number): Promise<{ status: number; body: string; head: Buffer } | null> {
  const url = `${seed}/${sig.path}`;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method: sig.method ?? 'GET',
      signal: ctl.signal,
      redirect: 'manual',   // don't chase — a redirect from /.git to a login page is a MISS, not a hit
      headers: { 'User-Agent': 'gen0sec-content-sigs/1.0' },
    });
    // Only bother reading the body for statuses that could plausibly ship
    // real content. 3xx / 401 without a body are always misses here.
    if (resp.status === 0) return null;
    if (!resp.body) return { status: resp.status, body: '', head: Buffer.alloc(0) };
    const cap = sig.maxBytes ?? maxBytes;
    const reader = resp.body.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      received += value.length;
      chunks.push(value);
      if (received >= cap) { await reader.cancel().catch(() => {}); break; }
    }
    const buf = Buffer.concat(chunks);
    return { status: resp.status, body: buf.toString('utf8'), head: buf.subarray(0, Math.min(buf.length, 512)) };
  } catch { return null; }
  finally { clearTimeout(timer); }
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let concurrency = 10;
  let hostConcurrency = 5;
  let timeoutSec = 8;
  let maxKb = 128;
  let liveOnly = true;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--concurrency' || a === '-c') concurrency = parseInt(nxt(), 10);
    else if (a === '--host-concurrency') hostConcurrency = parseInt(nxt(), 10);
    else if (a === '--timeout') timeoutSec = parseInt(nxt(), 10);
    else if (a === '--max-kb') maxKb = parseInt(nxt(), 10);
    else if (a === '--no-live-only') liveOnly = false;
    else passthrough.push(a);
  }
  if (passthrough.length) { /* reserved */ }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('content-sigs', `
Probe ${SIGS.length} known-artefact paths per live target and match the
response BODY against content signatures — not status/length. Immune to
WAF response-length normalization that killed ffuf on this estate.

Signatures cover: .git/.svn/.hg/.bzr, .env variants, private keys, wp-config
backups, framework configs (Symfony/Rails/Django), phpinfo dumps, Apache
server-status/info, nginx stub_status, Prometheus /metrics, Spring Boot
actuator (env/health/heapdump/mappings/beans), Swagger/OpenAPI, .DS_Store,
.htpasswd, .npmrc, .bash_history.

Requires --sqlite (reads http_probes for the live-only filter).

Wrapper flags (before '--'):
  --concurrency/-c <N>   parallel signature probes across all hosts (default: 10)
  --host-concurrency <N> parallel probes per host (default: 5)
  --timeout <s>          per-probe HTTP timeout (default: 8)
  --max-kb <N>           body-cap per probe (default: 128)
  --no-live-only         include hosts httpx never saw alive`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('curl');
  if (!opts.sqlite) { console.error('content-sigs: --sqlite is required'); process.exit(1); }

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = openDb(opts.sqlite);
  const runId = db.startRun('content-sigs', { targets: targets.length, sigs: SIGS.length, liveOnly }, now);

  const live = liveOnly ? loadLive(db, targets) : targets.map((t) => ({ target: t, seed: `https://${t}` }));
  console.error(`content-sigs: ${live.length} live target(s) × ${SIGS.length} signature(s) = ${live.length * SIGS.length} probes`);
  if (!live.length) {
    db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
    db.close();
    return;
  }

  const outFile = resolveOutputPath(opts, runId, 'content-sigs.jsonl');
  const wstream = fs.createWriteStream(outFile);
  const hits: Hit[] = [];
  let findings = 0;

  // Per-host worker fan-out: each host runs SIGS through its own bounded
  // pool (default 5) so we don't hammer a single host with 40 concurrent
  // requests. Global concurrency caps the number of active hosts.
  let hostIdx = 0;
  async function hostWorker(): Promise<void> {
    for (;;) {
      const i = hostIdx++;
      if (i >= live.length) return;
      const h = live[i]!;
      let sigIdx = 0;
      async function sigWorker(): Promise<void> {
        for (;;) {
          const j = sigIdx++;
          if (j >= SIGS.length) return;
          const sig = SIGS[j]!;
          const r = await probe(h.seed, sig, timeoutSec * 1000, maxKb * 1024);
          if (!r) continue;
          if (!sig.match(r.body, r.head)) continue;
          const url = `${h.seed}/${sig.path}`;
          const hit: Hit = { target: h.target, url, sig, status: r.status, length: r.body.length };
          hits.push(hit);
          wstream.write(JSON.stringify({ target: h.target, url, path: sig.path, sev: sig.sev, status: r.status, length: r.body.length, desc: sig.desc, snippet: r.body.slice(0, 200) }) + '\n');
          db.insertFinding({
            tool: 'content-sigs',
            target: h.target,
            category: `exposure-${sig.path.replace(/[^a-zA-Z0-9._-]/g, '_')}`,
            severity: sig.sev,
            title: `Exposed ${sig.path} (${sig.desc}) — ${r.status} ${r.body.length}b`,
            cve: null,
            matched_at: url,
            meta: { path: sig.path, status: r.status, length: r.body.length, desc: sig.desc, snippet: r.body.slice(0, 400) },
          }, now, runId);
          findings++;
          console.error(`  ★ ${h.target} ${sig.path} → ${sig.sev} (${r.status}, ${r.body.length}b)`);
        }
      }
      await Promise.all(Array.from({ length: Math.min(hostConcurrency, SIGS.length) }, sigWorker));
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, live.length) }, hostWorker));

  await new Promise<void>((res) => wstream.end(() => res()));
  db.finishRun(runId, { targetsCount: live.length, findingsCount: findings, at: new Date().toISOString() });
  db.close();
  console.error(`content-sigs done: +${findings} exposure(s) across ${live.length} host(s), run #${runId}`);
  console.error(`  sqlite: ${path.resolve(opts.sqlite)}`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
