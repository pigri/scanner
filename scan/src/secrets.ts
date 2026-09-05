#!/usr/bin/env -S node --loader tsx
// secrets: gitleaks against downloaded JS / JSON / config assets from the
// discovered_urls table. Finds embedded API keys, JWTs, DSNs, cloud creds in
// public web assets — a class of finding nothing else in the pipeline sees.
//
// Flow:
//   1. Query discovered_urls for likely-interesting extensions per target.
//   2. Fetch a bounded sample into runs/<id>/bundles/<host>/... (parallel).
//   3. Run `gitleaks dir` over the fetched tree.
//   4. Emit one finding per gitleaks hit, severity mapped from RuleID.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';

// Extensions we bother fetching. Anything not on this list either has no
// server-embedded secrets (images/fonts/video/audio) or is untrusted binary.
const INTERESTING_EXT = /\.(js|mjs|cjs|jsx|ts|tsx|json|jsonl|env|yml|yaml|toml|ini|conf|cfg|config|xml|txt|md|map|tf|sh|bash|zsh|properties|pem|key|crt)($|\?)/i;
// Rule → severity mapping. Keep it explicit — gitleaks emits a rule id per hit
// and unfamiliar ids get 'low' by default so nothing is silently dropped.
const HIGH_RULES = new Set([
  'aws-access-token', 'aws-secret-access-key', 'gcp-service-account',
  'gcp-api-key', 'azure-connection-string', 'stripe-access-token',
  'stripe-restricted-api-key', 'openai-api-key', 'anthropic-api-key',
  'private-key', 'rsa-private-key', 'jwt', 'twilio-api-key',
  'sendgrid-api-token', 'github-pat', 'github-oauth', 'gitlab-pat',
  'slack-bot-token', 'slack-user-token', 'slack-webhook-url',
  'discord-bot-token', 'discord-client-secret',
  'databricks-api-token', 'shopify-access-token', 'square-access-token',
  'mailchimp-api-key', 'mailgun-token',
]);
const MEDIUM_RULES = new Set([
  'generic-api-key', 'generic-password', 'basic-auth-header',
  'authorization-bearer', 'firebase-config-with-key',
  'facebook-access-token', 'facebook-secret',
  'twitter-bearer-token', 'twitter-secret',
]);
function severityForRule(id: string): 'high' | 'medium' | 'low' {
  if (HIGH_RULES.has(id)) return 'high';
  if (MEDIUM_RULES.has(id)) return 'medium';
  return 'low';
}

// No allowlist. Public-ness isn't a property of the key's shape — it's a
// property of the account-side restrictions on the key, which we can only
// discover by probing. See `gapi-key-check` (invoked at the end of this run
// for every AIza key found in the bundle tree) — it enumerates which
// Google APIs the key actually redeems from public egress. Non-Google
// public tokens (reCAPTCHA site keys, Stripe pk_*, Sentry DSN, PostHog
// write keys) also aren't allowlisted here — they'll surface as low-
// severity generic-api-key hits, which is honest signal for the operator.

interface FetchTask { target: string; url: string; localPath: string }

async function fetchOne(task: FetchTask, timeoutMs: number, maxBytes: number): Promise<boolean> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const resp = await fetch(task.url, {
      signal: ctl.signal,
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (secrets-scan)' },
    });
    if (!resp.ok || !resp.body) return false;
    // Enforce max-bytes without buffering the entire body.
    const reader = resp.body.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      received += value.length;
      if (received > maxBytes) { await reader.cancel().catch(() => {}); return false; }
      chunks.push(value);
    }
    fs.mkdirSync(path.dirname(task.localPath), { recursive: true });
    fs.writeFileSync(task.localPath, Buffer.concat(chunks));
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// Concurrency-limited runner.
async function fetchAll(tasks: FetchTask[], concurrency: number, timeoutMs: number, maxBytes: number): Promise<number> {
  let ok = 0;
  let idx = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const i = idx++;
      if (i >= tasks.length) return;
      const t = tasks[i]!;
      if (await fetchOne(t, timeoutMs, maxBytes)) ok++;
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));
  return ok;
}

function loadCandidates(db: Db, targets: readonly string[], perHostCap: number): FetchTask[] {
  if (!targets.length) return [];
  const placeholders = targets.map(() => '?').join(',');
  const rows = db.raw.prepare(
    `SELECT DISTINCT target, url FROM discovered_urls
     WHERE target IN (${placeholders})
     ORDER BY target, url`
  ).all(...targets) as { target: string; url: string }[];
  const perHost = new Map<string, FetchTask[]>();
  for (const r of rows) {
    if (!INTERESTING_EXT.test(r.url)) continue;
    if (!r.url.startsWith('http')) continue;
    let localPath: string;
    try {
      const u = new URL(r.url);
      // Flatten: <host>/<path-hash>.<ext-preserving suffix> so gitleaks scans
      // real filenames. Strip trailing '/', collapse to a safe path.
      const p = (u.pathname === '/' ? '/_root' : u.pathname).replace(/[^a-zA-Z0-9._/-]+/g, '_');
      localPath = path.join(u.hostname, p.replace(/^\//, ''));
    } catch { continue; }
    const bucket = perHost.get(r.target) ?? [];
    if (bucket.length >= perHostCap) continue;
    bucket.push({ target: r.target, url: r.url, localPath });
    perHost.set(r.target, bucket);
  }
  const out: FetchTask[] = [];
  for (const s of perHost.values()) out.push(...s);
  return out;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let perHostCap = 50;
  let batchCap = 500;
  let fetchConcurrency = 20;
  let fetchTimeoutSec = 15;
  let maxBytesKb = 500;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--per-host-cap') perHostCap = parseInt(nxt(), 10);
    else if (a === '--batch-cap') batchCap = parseInt(nxt(), 10);
    else if (a === '--concurrency' || a === '-c') fetchConcurrency = parseInt(nxt(), 10);
    else if (a === '--fetch-timeout') fetchTimeoutSec = parseInt(nxt(), 10);
    else if (a === '--max-kb') maxBytesKb = parseInt(nxt(), 10);
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('secrets', `
Fetch a bounded sample of JS/JSON/config URLs from discovered_urls for each
target, run gitleaks over the local tree, and persist each hit as a finding.
Severity mapped from RuleID (cloud/auth/private-key = high, generic = medium,
everything else = low).

Requires --sqlite (URL sample comes from discovered_urls). Katana/gau/wayback
have to have populated the URL table first.

Wrapper flags (before '--'):
  --per-host-cap <N>    max files per target FQDN (default: 50)
  --batch-cap <N>       max files across the whole batch (default: 500)
  --concurrency <N>     parallel HTTP fetchers (default: 20)
  --fetch-timeout <s>   per-file HTTP timeout (default: 15)
  --max-kb <N>          drop files bigger than N KB (default: 500)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  if (!opts.sqlite) { console.error('secrets: --sqlite is required'); process.exit(1); }
  await requireTool('gitleaks');
  await requireTool('trufflehog');

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('secrets', { targets: targets.length, perHostCap, batchCap, maxBytesKb }, now) : null;

  // Pick candidate URLs, cap total.
  let tasks = loadCandidates(db!, targets, perHostCap);
  if (tasks.length > batchCap) {
    console.error(`candidate URLs: ${tasks.length} → clamped to batch-cap ${batchCap}`);
    tasks = tasks.slice(0, batchCap);
  } else {
    console.error(`candidate URLs: ${tasks.length}`);
  }
  if (!tasks.length) {
    console.error('no candidate URLs (discovered_urls empty for these targets — run katana/gau first)');
    if (db && runId !== null) {
      db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
      db.close();
    }
    return;
  }

  // Bundle dir goes under the run's artefact tree so nothing is overwritten.
  const bundleDir = resolveOutputPath({ ...opts, outFile: null }, runId, 'bundles');
  fs.mkdirSync(bundleDir, { recursive: true });
  // Prefix each task's localPath with bundleDir.
  for (const t of tasks) t.localPath = path.join(bundleDir, t.localPath);

  console.error(`fetch: ${tasks.length} URLs × up to ${maxBytesKb}KB (concurrency ${fetchConcurrency})`);
  const fetched = await fetchAll(tasks, fetchConcurrency, fetchTimeoutSec * 1000, maxBytesKb * 1024);
  console.error(`fetch done: ${fetched}/${tasks.length} downloaded`);
  if (!fetched) {
    if (db && runId !== null) {
      db.finishRun(runId, { targetsCount: targets.length, findingsCount: 0, at: new Date().toISOString() });
      db.close();
    }
    return;
  }

  // Helper to attribute a local file path back to (target, url) via the task list.
  const attribute = (localAbs: string): { target: string; url: string | null } => {
    const task = tasks.find((t) => t.localPath === localAbs || localAbs.endsWith(t.localPath.replace(bundleDir + path.sep, '')));
    if (task) return { target: task.target, url: task.url };
    return { target: path.basename(path.dirname(localAbs)), url: null };
  };

  let findings = 0;

  // --- gitleaks pass -----------------------------------------------------
  const glFile = resolveOutputPath(opts, runId, 'gitleaks.json');
  const glArgs = ['dir', bundleDir, '-r', glFile, '-f', 'json', '--redact=100', '--exit-code', '0', ...passthrough];
  console.error(`gitleaks ${glArgs.join(' ')}`);
  const gl = await run('gitleaks', glArgs, { timeoutMs: 5 * 60 * 1000 });
  if (gl.code !== 0) console.error(`gitleaks exited ${gl.code}: ${gl.stderr.slice(0, 300)}`);
  if (db && runId !== null && fs.existsSync(glFile)) {
    const raw = fs.readFileSync(glFile, 'utf8').trim();
    if (raw.startsWith('[')) {
      const rows = JSON.parse(raw) as Array<{ RuleID?: string; Description?: string; File?: string; StartLine?: number; Match?: string }>;
      for (const hit of rows) {
        const rule = hit.RuleID ?? 'unknown';
        const localAbs = hit.File ?? '';
        const { target, url } = attribute(localAbs);
        db.insertFinding({
          tool: 'secrets',
          target,
          category: `gitleaks:${rule}`,
          severity: severityForRule(rule),
          title: `Secret leak (gitleaks:${rule}) in ${url ?? localAbs}${hit.StartLine ? `:${hit.StartLine}` : ''}`,
          cve: null,
          matched_at: url ?? localAbs,
          meta: { scanner: 'gitleaks', rule, description: hit.Description, match: hit.Match, file: localAbs, line: hit.StartLine, url },
        }, now, runId);
        findings++;
      }
    }
  }

  // --- trufflehog pass ---------------------------------------------------
  // Different ruleset + entropy scoring than gitleaks. Running both catches
  // secrets one alone misses (trufflehog tends to have more first-party
  // detectors for cloud/SaaS APIs; gitleaks has broader regex coverage of
  // private keys, DSNs, and generic patterns).
  const thFile = resolveOutputPath(opts, runId, 'trufflehog.jsonl');
  const thArgs = ['filesystem', bundleDir, '-j', '--no-update'];
  console.error(`trufflehog ${thArgs.join(' ')}`);
  const th = await run('trufflehog', thArgs, { timeoutMs: 5 * 60 * 1000 });
  // trufflehog writes findings AND log lines both to stdout, tagged by
  // presence of "level" (log) vs "DetectorName" (finding). Filter here.
  fs.writeFileSync(thFile, th.stdout);
  if (db && runId !== null) {
    for (const line of th.stdout.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('{"SourceMetadata"')) continue;
      try {
        const hit = JSON.parse(t) as {
          SourceMetadata?: { Data?: { Filesystem?: { file?: string; line?: number } } };
          DetectorName?: string;
          DetectorDescription?: string;
          Verified?: boolean;
          Redacted?: string;
          Raw?: string;
        };
        const localAbs = hit.SourceMetadata?.Data?.Filesystem?.file ?? '';
        const detector = (hit.DetectorName ?? 'unknown').toLowerCase();
        const { target, url } = attribute(localAbs);
        // Trufflehog's "Verified: true" means it live-tested the credential
        // and it works — treat as critical regardless of detector class.
        const severity: 'critical' | 'high' | 'medium' | 'low' =
          hit.Verified ? 'critical' :
          /aws|gcp|azure|stripe|openai|anthropic|slack|github|gitlab|twilio|sendgrid|private[-_]?key|jwt|shopify|square|databricks|discord/i.test(detector) ? 'high' :
          /generic|firebase|facebook|twitter/i.test(detector) ? 'medium' : 'low';
        db.insertFinding({
          tool: 'secrets',
          target,
          category: `trufflehog:${detector}`,
          severity,
          title: `Secret leak (trufflehog:${detector}${hit.Verified ? ' VERIFIED' : ''}) in ${url ?? localAbs}${hit.SourceMetadata?.Data?.Filesystem?.line ? `:${hit.SourceMetadata.Data.Filesystem.line}` : ''}`,
          cve: null,
          matched_at: url ?? localAbs,
          meta: {
            scanner: 'trufflehog',
            detector,
            description: hit.DetectorDescription,
            verified: hit.Verified,
            redacted: hit.Redacted,
            file: localAbs,
            line: hit.SourceMetadata?.Data?.Filesystem?.line,
            url,
          },
        }, now, runId);
        findings++;
      } catch { /* ignore */ }
    }
  }

  console.error(`secrets done: +${findings} finding(s) across ${fetched} file(s) (gitleaks + trufflehog)`);

  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: findings, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${findings} findings, run #${runId})`);
  }

  // --- gapi-key-check pass -----------------------------------------------
  // Sweep the just-fetched bundle tree for any Google API keys (AIza…) and
  // probe each against Google's API surface (Gemini, Maps, Places, Custom
  // Search, Geolocation, …). This is what actually distinguishes a benign
  // client-side embed from an unrestricted key that redeems billable APIs.
  // gapi-key-check writes one finding per enabled API per host directly
  // into scan.db, keyed on the host directory name in bundleDir.
  if (opts.sqlite) {
    console.error(`\ngapi-key-check --bundle-dir ${bundleDir}`);
    const gk = await run('npx', ['tsx', 'src/gapi-key-check.ts', '--bundle-dir', bundleDir, '--sqlite', opts.sqlite], { timeoutMs: 5 * 60 * 1000 });
    if (gk.code !== 0) console.error(`gapi-key-check exited ${gk.code}: ${gk.stderr.slice(0, 300)}`);
  }

  // --- vendor-key-enrich pass --------------------------------------------
  // For every trufflehog hit with Verified=true, call the vendor's read-only
  // "what can this credential do?" endpoint (GitHub /user + /user/orgs,
  // Slack auth.test, AWS STS GetCallerIdentity, OpenAI/Anthropic /v1/models,
  // etc.) and persist one finding per enumerated capability. Trufflehog by
  // itself only surfaces the binary "valid/invalid" — this fills in scope,
  // account, workspace, model reach so severity actually reflects blast
  // radius.
  if (opts.sqlite && fs.existsSync(thFile)) {
    console.error(`\nvendor-key-enrich --trufflehog-jsonl ${thFile}`);
    const vk = await run('npx', ['tsx', 'src/vendor-key-enrich.ts', '--trufflehog-jsonl', thFile, '--sqlite', opts.sqlite], { timeoutMs: 5 * 60 * 1000 });
    if (vk.code !== 0) console.error(`vendor-key-enrich exited ${vk.code}: ${vk.stderr.slice(0, 300)}`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
