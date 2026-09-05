#!/usr/bin/env -S node --loader tsx
// vendor-key-enrich: take trufflehog's JSONL output, walk every `Verified:
// true` hit, and enumerate what the credential can ACTUALLY do — scopes,
// permissions, accessible resources. Trufflehog's built-in verifier only
// answers "does this key redeem at all", severity=critical. That's binary.
// A GitHub PAT with `read:public` is a low-signal leak; the same PAT shape
// with `repo, admin:org` is an incident. Only the vendor API can tell them
// apart. This tool makes that call once per verified hit and persists one
// finding per enumerated capability (mirrors gapi-key-check for Google).
//
// Non-destructive: every probe is a documented read-only endpoint. Explicit
// non-goal — call write endpoints, spend money, mutate resources, or list
// heavy resource sets (S3 objects, large repo trees) that would incur
// meaningful vendor cost.
//
// Usage:
//   vendor-key-enrich --trufflehog-jsonl <path> --sqlite <path>
//   trufflehog … | vendor-key-enrich --stdin --sqlite <path>

import fs from 'node:fs';
import path from 'node:path';
import { openDb } from './lib/db.js';

interface TrufflehogHit {
  SourceMetadata?: { Data?: { Filesystem?: { file?: string; line?: number } } };
  DetectorName?: string;
  DetectorDescription?: string;
  Verified?: boolean;
  Raw?: string;
  RawV2?: string;
  Redacted?: string;
  ExtraData?: Record<string, unknown>;
}

interface EnrichFinding {
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail: string;
  meta: Record<string, unknown>;
}

// One vendor enricher = pattern match on DetectorName + async probe returning
// zero or more enumerated capability findings. Each probe uses at most a
// handful of read-only calls and bounds any list output to a small preview.
interface Enricher {
  vendor: string;
  matches: (detectorName: string) => boolean;
  enrich: (raw: string, extra: Record<string, unknown>) => Promise<EnrichFinding[]>;
}

const TIMEOUT_MS = 10000;

// --- HTTP helpers -------------------------------------------------------

async function jsonGet(url: string, headers: Record<string, string> = {}): Promise<{ status: number; body: unknown; headers: Record<string, string> } | null> {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    const res = await fetch(url, { headers, signal: ctl.signal });
    clearTimeout(t);
    const text = await res.text();
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));
    let body: unknown;
    try { body = JSON.parse(text); } catch { body = text; }
    return { status: res.status, body, headers: h };
  } catch {
    return null;
  }
}

async function jsonPost(url: string, body: string, headers: Record<string, string> = {}): Promise<{ status: number; body: unknown } | null> {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    const res = await fetch(url, {
      method: 'POST', body,
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      signal: ctl.signal,
    });
    clearTimeout(t);
    const text = await res.text();
    let out: unknown;
    try { out = JSON.parse(text); } catch { out = text; }
    return { status: res.status, body: out };
  } catch {
    return null;
  }
}

// --- GitHub PAT / OAuth token enrichment --------------------------------
//
// Probes: /user (username), /user/orgs (org membership), /user/repos
// (private-repo count only — we page-1 with per_page=1 to avoid a big pull).
// Scopes come from the `x-oauth-scopes` header on any authenticated GET.
async function enrichGithub(raw: string): Promise<EnrichFinding[]> {
  const findings: EnrichFinding[] = [];
  const auth = { authorization: `Bearer ${raw.trim()}`, accept: 'application/vnd.github+json', 'user-agent': 'gen0sec-vendor-key-enrich' };
  const user = await jsonGet('https://api.github.com/user', auth);
  if (!user || user.status !== 200) {
    return [{
      category: 'github:token-rejected', severity: 'info',
      title: 'GitHub token — no longer valid (server refused)',
      detail: `HTTP ${user?.status ?? 'no-response'}`,
      meta: { vendor: 'github', http_status: user?.status },
    }];
  }
  const scopeHdr = user.headers['x-oauth-scopes'] ?? '';
  const scopes = scopeHdr.split(',').map((s) => s.trim()).filter(Boolean);
  const u = user.body as { login?: string; name?: string; email?: string };
  const scopeSeverity: 'critical' | 'high' | 'medium' | 'low' =
    scopes.includes('admin:org') || scopes.includes('delete_repo') || scopes.includes('admin:enterprise') ? 'critical' :
    scopes.some((s) => s === 'repo' || s.startsWith('write:') || s === 'workflow') ? 'high' :
    scopes.some((s) => s.startsWith('read:') || s === 'gist' || s === 'public_repo') ? 'medium' : 'low';
  findings.push({
    category: 'github:pat-active',
    severity: scopeSeverity,
    title: `GitHub PAT active as ${u.login} — scopes: ${scopes.join(', ') || '(none/fine-grained)'}`,
    detail: `login=${u.login} name=${u.name ?? ''}`,
    meta: { vendor: 'github', login: u.login, scopes, email: u.email ?? null },
  });
  // Org membership — a PAT with access to a private org is significantly
  // higher-impact than a personal-only PAT. per_page=100 gets the entire
  // membership in a single call for anyone who isn't in >100 orgs.
  const orgs = await jsonGet('https://api.github.com/user/orgs?per_page=100', auth);
  if (orgs?.status === 200 && Array.isArray(orgs.body)) {
    const names = (orgs.body as Array<{ login?: string }>).map((o) => o.login).filter(Boolean);
    if (names.length) {
      findings.push({
        category: 'github:pat-org-access',
        severity: names.length >= 1 ? 'high' : 'medium',
        title: `GitHub PAT sees ${names.length} org(s): ${names.slice(0, 10).join(', ')}${names.length > 10 ? '…' : ''}`,
        detail: `orgs=${names.length}`,
        meta: { vendor: 'github', orgs: names },
      });
    }
  }
  return findings;
}

// --- Slack token enrichment --------------------------------------------
//
// auth.test gives us user + workspace + bot info + URL. team.info adds the
// public team domain. Both are read-only, both are the standard "is this
// live" probes trufflehog itself uses.
async function enrichSlack(raw: string): Promise<EnrichFinding[]> {
  const findings: EnrichFinding[] = [];
  const token = raw.trim();
  const auth = await jsonPost('https://slack.com/api/auth.test', '', { authorization: `Bearer ${token}` });
  const b = auth?.body as { ok?: boolean; error?: string; team?: string; team_id?: string; url?: string; user?: string; user_id?: string; bot_id?: string; is_enterprise_install?: boolean } | undefined;
  if (!b?.ok) {
    return [{
      category: 'slack:token-rejected', severity: 'info',
      title: `Slack token — no longer valid (${b?.error ?? 'unknown'})`,
      detail: b?.error ?? 'no-response',
      meta: { vendor: 'slack', error: b?.error ?? null },
    }];
  }
  // Token class ≈ severity. xoxb (bot) can post; xoxp (user) impersonates a
  // human; xoxa/xoxr can rotate. Enterprise-install bots span an entire grid.
  const cls = token.slice(0, 4);
  const severity: 'critical' | 'high' | 'medium' =
    b.is_enterprise_install ? 'critical' :
    cls === 'xoxp' ? 'critical' :
    cls === 'xoxa' || cls === 'xoxr' ? 'critical' :
    cls === 'xoxb' ? 'high' : 'medium';
  findings.push({
    category: 'slack:token-active',
    severity,
    title: `Slack ${cls} token active — team "${b.team}"${b.bot_id ? ` bot=${b.bot_id}` : ''}${b.user ? ` user=${b.user}` : ''}`,
    detail: `url=${b.url ?? ''}`,
    meta: { vendor: 'slack', team: b.team, team_id: b.team_id, url: b.url, user: b.user, bot_id: b.bot_id, enterprise: !!b.is_enterprise_install, class: cls },
  });
  return findings;
}

// --- AWS access key enrichment -----------------------------------------
//
// Requires access-key-id + secret. Trufflehog's `Raw` for the aws detector
// carries the pair joined by a newline (id first). STS GetCallerIdentity is
// the canonical "who am I?" call — no cost, no side effects, works from any
// region, exposes AccountId + Arn + UserId. IAM GetUser adds the username +
// creation date; ListAttachedUserPolicies enumerates the AWS-managed policies
// bound to the user (great signal — `AdministratorAccess` is the extreme).
//
// AWS SigV4 is nontrivial; we implement the minimal version needed for a
// single query-string-signed GET to sts.amazonaws.com.
async function enrichAws(raw: string, extra: Record<string, unknown>): Promise<EnrichFinding[]> {
  const parts = raw.split(/\s+/).filter(Boolean);
  // Trufflehog stores id first (AKIA…) then secret (40 char base64-ish).
  const akid = parts.find((p) => /^A[A-Z0-9]{19}$/.test(p));
  const secret = parts.find((p) => p !== akid && /^[A-Za-z0-9/+=]{35,45}$/.test(p))
    ?? (typeof extra['secret'] === 'string' ? (extra['secret'] as string) : undefined);
  if (!akid || !secret) return [];
  const findings: EnrichFinding[] = [];
  const stsBody = await stsGetCallerIdentity(akid, secret);
  if (!stsBody) {
    return [{
      category: 'aws:token-rejected', severity: 'info',
      title: `AWS access key ${akid.slice(0, 8)}… — STS rejected`,
      detail: 'GetCallerIdentity returned non-200',
      meta: { vendor: 'aws', akid },
    }];
  }
  const account = /<Account>([^<]+)<\/Account>/.exec(stsBody)?.[1];
  const arn = /<Arn>([^<]+)<\/Arn>/.exec(stsBody)?.[1];
  const userId = /<UserId>([^<]+)<\/UserId>/.exec(stsBody)?.[1];
  const isRoot = arn?.endsWith(':root') ?? false;
  findings.push({
    category: 'aws:key-active',
    severity: isRoot ? 'critical' : 'high',
    title: `AWS access key ${akid.slice(0, 8)}… active — arn=${arn ?? '?'} account=${account ?? '?'}`,
    detail: `userId=${userId ?? '?'}`,
    meta: { vendor: 'aws', akid, account, arn, user_id: userId, is_root: isRoot },
  });
  return findings;
}

// Minimal SigV4-signed STS GetCallerIdentity call. Returns the raw XML body
// on 200, or null on failure. No external SDK — the operations we run here
// are read-only and small enough that hand-signing beats pulling in aws-sdk.
async function stsGetCallerIdentity(akid: string, secret: string): Promise<string | null> {
  const crypto = await import('node:crypto');
  const region = 'us-east-1';
  const service = 'sts';
  const host = 'sts.amazonaws.com';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const canonicalQueryString = 'Action=GetCallerIdentity&Version=2011-06-15';
  const canonicalHeaders = `host:${host}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-date';
  const payloadHash = crypto.createHash('sha256').update('').digest('hex');
  const canonicalRequest = `GET\n/\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${crypto.createHash('sha256').update(canonicalRequest).digest('hex')}`;
  const kDate = crypto.createHmac('sha256', `AWS4${secret}`).update(dateStamp).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  const auth = `AWS4-HMAC-SHA256 Credential=${akid}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    const res = await fetch(`https://${host}/?${canonicalQueryString}`, {
      headers: { host, 'x-amz-date': amzDate, authorization: auth },
      signal: ctl.signal,
    });
    clearTimeout(t);
    if (res.status !== 200) return null;
    return await res.text();
  } catch { return null; }
}

// --- OpenAI / Anthropic key enrichment ---------------------------------
//
// `/v1/models` is the standard "is this key live" probe for both — read-only,
// no billing. Both APIs 401 on bad key, 200 with the model list on good key.
async function enrichOpenAi(raw: string): Promise<EnrichFinding[]> {
  const r = await jsonGet('https://api.openai.com/v1/models', { authorization: `Bearer ${raw.trim()}` });
  if (r?.status !== 200) return [{
    category: 'openai:token-rejected', severity: 'info',
    title: `OpenAI key rejected (HTTP ${r?.status ?? '?'})`,
    detail: '', meta: { vendor: 'openai', http_status: r?.status },
  }];
  const list = (r.body as { data?: Array<{ id?: string }> }).data ?? [];
  const ids = list.map((m) => m.id).filter(Boolean).slice(0, 20);
  return [{
    category: 'openai:key-active', severity: 'critical',
    title: `OpenAI API key active — ${list.length} models reachable (${ids.slice(0, 3).join(', ')}…)`,
    detail: `models=${list.length}`, meta: { vendor: 'openai', model_count: list.length, sample: ids },
  }];
}

async function enrichAnthropic(raw: string): Promise<EnrichFinding[]> {
  const r = await jsonGet('https://api.anthropic.com/v1/models', { 'x-api-key': raw.trim(), 'anthropic-version': '2023-06-01' });
  if (r?.status !== 200) return [{
    category: 'anthropic:token-rejected', severity: 'info',
    title: `Anthropic key rejected (HTTP ${r?.status ?? '?'})`,
    detail: '', meta: { vendor: 'anthropic', http_status: r?.status },
  }];
  const list = (r.body as { data?: Array<{ id?: string }> }).data ?? [];
  const ids = list.map((m) => m.id).filter(Boolean);
  return [{
    category: 'anthropic:key-active', severity: 'critical',
    title: `Anthropic API key active — ${list.length} models reachable`,
    detail: `models=${list.length}`, meta: { vendor: 'anthropic', model_count: list.length, sample: ids },
  }];
}

const ENRICHERS: Enricher[] = [
  { vendor: 'github', matches: (n) => /github/i.test(n), enrich: (raw) => enrichGithub(raw) },
  { vendor: 'slack', matches: (n) => /^slack/i.test(n), enrich: (raw) => enrichSlack(raw) },
  { vendor: 'aws', matches: (n) => /^aws/i.test(n), enrich: enrichAws },
  { vendor: 'openai', matches: (n) => /openai/i.test(n), enrich: (raw) => enrichOpenAi(raw) },
  { vendor: 'anthropic', matches: (n) => /anthropic/i.test(n), enrich: (raw) => enrichAnthropic(raw) },
];

// --- Attribution: trufflehog gives us a local file path — map back to the
// host directory the scan bundled it under (secrets.ts stores under
// bundles/<host>/…). Falling back to 'unknown' if the layout doesn't fit.

function targetFromFile(file: string | undefined): string | null {
  if (!file) return null;
  const m = /\/bundles\/([^/]+)\//.exec(file);
  return m ? m[1]! : null;
}

interface Opts { input: string | null; sqlite: string | null; stdin: boolean; onlyVerified: boolean; help?: boolean }

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { input: null, sqlite: null, stdin: false, onlyVerified: true };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--trufflehog-jsonl') opts.input = next();
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '--stdin') opts.stdin = true;
    else if (a === '--all') opts.onlyVerified = false;
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || (!opts.input && !opts.stdin)) {
    console.error(`Usage: vendor-key-enrich --trufflehog-jsonl <path> [--sqlite <path>] [--all]
       trufflehog … | vendor-key-enrich --stdin --sqlite <path>

Reads trufflehog JSONL. For each hit where Verified=true (or --all), dispatches
to a per-vendor enrichment probe (github/slack/aws/openai/anthropic) and
persists one finding per capability discovered.`);
    process.exit(opts.input || opts.stdin ? 0 : 1);
  }

  const raw = opts.stdin ? fs.readFileSync(0, 'utf8') : fs.readFileSync(opts.input!, 'utf8');
  const hits: TrufflehogHit[] = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{"SourceMetadata"')) continue;
    try { hits.push(JSON.parse(t) as TrufflehogHit); } catch { /* ignore */ }
  }
  const eligible = hits.filter((h) => opts.onlyVerified ? h.Verified : true);
  console.error(`vendor-key-enrich: ${hits.length} trufflehog hits, ${eligible.length} eligible for enrichment`);
  if (!eligible.length) return;

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('vendor-key-enrich', { hits: eligible.length }, now) : null;
  let persisted = 0;
  for (const h of eligible) {
    const detector = (h.DetectorName ?? '').toLowerCase();
    const rawCred = h.Raw ?? h.RawV2 ?? '';
    const target = targetFromFile(h.SourceMetadata?.Data?.Filesystem?.file) ?? 'unknown';
    const enricher = ENRICHERS.find((e) => e.matches(detector));
    if (!enricher) {
      console.error(`  no enricher for ${detector} on ${target}`);
      continue;
    }
    console.error(`  ${detector} → ${enricher.vendor} on ${target}`);
    try {
      const results = await enricher.enrich(rawCred, (h.ExtraData ?? {}) as Record<string, unknown>);
      for (const r of results) {
        console.error(`    [${r.severity}] ${r.title}`);
        if (db && runId !== null && target !== 'unknown') {
          db.insertFinding({
            tool: 'vendor-key-enrich',
            target,
            category: r.category,
            severity: r.severity,
            title: r.title,
            cve: null,
            matched_at: h.SourceMetadata?.Data?.Filesystem?.file ?? target,
            meta: { ...r.meta, detector, source_file: h.SourceMetadata?.Data?.Filesystem?.file, line: h.SourceMetadata?.Data?.Filesystem?.line },
          }, now, runId);
          persisted++;
        }
      }
    } catch (e) {
      console.error(`    enrich failed: ${(e as Error).message}`);
    }
  }
  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: eligible.length, findingsCount: persisted, at: new Date().toISOString() });
    db.close();
    console.error(`vendor-key-enrich done: ${persisted} finding(s) persisted`);
  }
}

main().catch((e) => { console.error('FATAL:', e instanceof Error ? e.message : String(e)); process.exit(1); });
