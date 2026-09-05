#!/usr/bin/env -S node --loader tsx
// cname-takeover: find dangling CNAMEs pointing at cloud/SaaS providers whose
// takeover pattern is publicly known. Cross-joins dns_records.CNAME rows
// against a curated provider list, then live-verifies by fetching the CNAME
// target and matching its response body for the well-known "no such
// site/app/bucket" fingerprint.
//
// Complements nuclei's takeover pack: nuclei checks by request-URL response
// signatures against ~130 templates; this checks by DNS+response against a
// curated 40-entry list, keyed by dns_records rather than the URL list.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';

// Sources: EdOverflow/can-i-take-over-xyz, projectdiscovery/nuclei-templates.
// Trimmed to providers whose vulnerable state is verifiable via a single GET
// against the CNAME target. Kept short so the live-verify pass stays quick.
interface Provider {
  name: string;
  cnameMatch: RegExp;
  fingerprint: RegExp;
  severity: 'high' | 'critical';
}
const PROVIDERS: Provider[] = [
  { name: 'github-pages',    cnameMatch: /\.github\.io\.?$/i,             fingerprint: /There isn't a GitHub Pages site here/i, severity: 'high' },
  { name: 'heroku',          cnameMatch: /\.herokuapp\.com\.?$/i,         fingerprint: /No such app|herokucdn\.com\/error-pages\/no-such-app/i, severity: 'high' },
  { name: 'azure-webapp',    cnameMatch: /\.azurewebsites\.net\.?$/i,     fingerprint: /404 Web Site not found|<title>Microsoft Azure App Service - Welcome/i, severity: 'high' },
  { name: 'azure-cloudapp',  cnameMatch: /\.cloudapp\.net\.?$/i,          fingerprint: /404 - File or directory not found/i, severity: 'high' },
  { name: 'azure-blob',      cnameMatch: /\.blob\.core\.windows\.net\.?$/i, fingerprint: /BlobNotFound|<Message>The specified blob does not exist/i, severity: 'high' },
  { name: 'aws-s3',          cnameMatch: /\.s3(\.[a-z0-9-]+)?\.amazonaws\.com\.?$/i, fingerprint: /NoSuchBucket|The specified bucket does not exist/i, severity: 'critical' },
  { name: 'aws-cloudfront',  cnameMatch: /\.cloudfront\.net\.?$/i,        fingerprint: /Bad request\.\s*ERROR: The request could not be satisfied/i, severity: 'high' },
  { name: 'aws-elasticbeans',cnameMatch: /\.elasticbeanstalk\.com\.?$/i,  fingerprint: /A page like this may indicate that|The application may have been terminated/i, severity: 'high' },
  { name: 'shopify',         cnameMatch: /\.myshopify\.com\.?$/i,         fingerprint: /Sorry, this shop is currently unavailable/i, severity: 'high' },
  { name: 'fastly',          cnameMatch: /\.fastly\.net\.?$/i,            fingerprint: /Fastly error: unknown domain/i, severity: 'high' },
  { name: 'zendesk',         cnameMatch: /\.zendesk\.com\.?$/i,           fingerprint: /Help Center Closed/i, severity: 'high' },
  { name: 'wordpress',       cnameMatch: /\.wordpress\.com\.?$/i,         fingerprint: /Do you want to register/i, severity: 'high' },
  { name: 'ghost',           cnameMatch: /\.ghost\.io\.?$/i,              fingerprint: /The thing you were looking for is no longer here/i, severity: 'high' },
  { name: 'squarespace',     cnameMatch: /\.squarespace\.com\.?$/i,       fingerprint: /Website Expired|No Such Account/i, severity: 'high' },
  { name: 'unbounce',        cnameMatch: /\.unbouncepages\.com\.?$/i,     fingerprint: /The requested URL was not found on this server/i, severity: 'high' },
  { name: 'tumblr',          cnameMatch: /\.tumblr\.com\.?$/i,            fingerprint: /Whatever you were looking for doesn.?t currently exist/i, severity: 'high' },
  { name: 'pantheon',        cnameMatch: /\.pantheonsite\.io\.?$/i,       fingerprint: /The gods are wise, but do not know of the site which you seek/i, severity: 'high' },
  { name: 'netlify',         cnameMatch: /\.netlify\.(app|com)\.?$/i,     fingerprint: /Not Found - Request ID/i, severity: 'high' },
  { name: 'vercel',          cnameMatch: /\.vercel\.app\.?$/i,            fingerprint: /The deployment could not be found on Vercel/i, severity: 'high' },
  { name: 'gitlab-pages',    cnameMatch: /\.gitlab\.io\.?$/i,             fingerprint: /The page you're looking for could not be found/i, severity: 'high' },
  { name: 'readthedocs',     cnameMatch: /\.readthedocs\.io\.?$/i,        fingerprint: /Unknown to Read the Docs/i, severity: 'high' },
  { name: 'firebaseapp',     cnameMatch: /\.firebaseapp\.com\.?$/i,       fingerprint: /Site Not Found|The specified bucket does not exist/i, severity: 'high' },
  { name: 'surge',           cnameMatch: /\.surge\.sh\.?$/i,              fingerprint: /project not found/i, severity: 'high' },
  { name: 'bitbucket',       cnameMatch: /\.bitbucket\.io\.?$/i,          fingerprint: /Repository not found/i, severity: 'high' },
  { name: 'launchrock',      cnameMatch: /\.launchrock\.com\.?$/i,        fingerprint: /HTTP 404 Not Found/i, severity: 'high' },
  { name: 'strikingly',      cnameMatch: /\.strikinglydns\.com\.?$/i,     fingerprint: /PAGE NOT FOUND/i, severity: 'high' },
  { name: 'tilda',           cnameMatch: /\.tilda\.(ws|cc)\.?$/i,         fingerprint: /Please renew your subscription/i, severity: 'high' },
  { name: 'uservoice',       cnameMatch: /\.uservoice\.com\.?$/i,         fingerprint: /This UserVoice subdomain is currently available/i, severity: 'high' },
  { name: 'wufoo',           cnameMatch: /\.wufoo\.com\.?$/i,             fingerprint: /Hmmm.\.\.the page you're looking for can't be found/i, severity: 'high' },
];

function matchProvider(cname: string): Provider | null {
  for (const p of PROVIDERS) if (p.cnameMatch.test(cname)) return p;
  return null;
}

interface Candidate { target: string; cname: string; provider: Provider }

function loadCandidates(db: Db, targets: readonly string[] | null): Candidate[] {
  const filter = targets && targets.length ? `AND target IN (${targets.map(() => '?').join(',')})` : '';
  const rows = db.raw.prepare(
    `SELECT DISTINCT target, value FROM dns_records
     WHERE type = 'CNAME' ${filter}`
  ).all(...(targets ?? [])) as { target: string; value: string }[];
  const out: Candidate[] = [];
  for (const r of rows) {
    const p = matchProvider(r.value);
    if (p) out.push({ target: r.target, cname: r.value, provider: p });
  }
  return out;
}

async function verify(c: Candidate, timeoutMs: number): Promise<{ hit: boolean; status?: number; error?: string }> {
  // Fetch the CNAME target's HTTPS root and look for the takeover fingerprint.
  // Some providers respond on HTTP only when the cert is missing; try HTTPS
  // first, fall back to HTTP.
  for (const scheme of ['https', 'http']) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const url = `${scheme}://${c.cname.replace(/\.$/, '')}/`;
      const resp = await fetch(url, {
        signal: ctl.signal,
        redirect: 'follow',
        headers: { 'User-Agent': 'gen0sec-cname-takeover/1.0' },
      });
      const body = await resp.text();
      if (c.provider.fingerprint.test(body)) {
        return { hit: true, status: resp.status };
      }
    } catch (e) {
      // fallthrough — try the other scheme
      if (scheme === 'http') return { hit: false, error: e instanceof Error ? e.message : String(e) };
    } finally {
      clearTimeout(timer);
    }
  }
  return { hit: false };
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let concurrency = 10;
  let timeoutSec = 10;
  let noTargetsFilter = false;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--concurrency' || a === '-c') concurrency = parseInt(nxt(), 10);
    else if (a === '--timeout') timeoutSec = parseInt(nxt(), 10);
    else if (a === '--all') noTargetsFilter = true;
    else passthrough.push(a);
  }
  if (passthrough.length) { /* reserved */ }

  if (opts.help) {
    console.error(commonUsage('cname-takeover', `
Cross-joins dns_records.CNAME rows against a curated list of takeover-prone
providers (github.io / heroku / azure / s3 / cloudfront / netlify / vercel /
shopify / fastly / ghost / squarespace / …). Live-verifies each candidate
by fetching the CNAME target and matching its body for the provider's
"no such site" fingerprint.

Requires --sqlite (reads dns_records). Restricts to --targets by default;
pass --all to check every CNAME the DB knows about.

Wrapper flags (before '--'):
  --concurrency/-c <N>  parallel HTTP verifies (default: 10)
  --timeout <s>         per-verify HTTP timeout (default: 10)
  --all                 ignore --targets filter, sweep the whole dns_records`));
    process.exit(0);
  }
  if (!opts.sqlite) { console.error('cname-takeover: --sqlite is required'); process.exit(1); }
  await requireTool('curl');   // fetch is builtin; keeping the tool-check convention

  const db = openDb(opts.sqlite);
  const now = new Date().toISOString();

  let targets: string[] | null = null;
  if (!noTargetsFilter) {
    if (!opts.targetsFile) { console.error('cname-takeover: need --targets or --all'); db.close(); process.exit(1); }
    targets = prepareTargets(opts).targets;
    if (!targets.length) { console.error('no in-scope targets'); db.close(); process.exit(1); }
  }

  const runId = db.startRun('cname-takeover', { targets: targets?.length ?? 'all', providers: PROVIDERS.length }, now);
  const outFile = resolveOutputPath(opts, runId, 'cname-takeover.jsonl');
  const wstream = fs.createWriteStream(outFile);

  const cands = loadCandidates(db, targets);
  console.error(`candidates: ${cands.length} CNAMEs matching ${PROVIDERS.length} providers`);
  if (!cands.length) {
    wstream.end();
    db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
    db.close();
    return;
  }

  let findings = 0;
  let idx = 0;
  const results: Array<{ c: Candidate; hit: boolean; status?: number; error?: string }> = [];
  async function worker(): Promise<void> {
    for (;;) {
      const i = idx++;
      if (i >= cands.length) return;
      const c = cands[i]!;
      const r = await verify(c, timeoutSec * 1000);
      results[i] = { c, ...r };
      console.error(`  ${c.target} -> ${c.cname} [${c.provider.name}] ${r.hit ? '★ TAKEOVER' : '· no fingerprint'}`);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, cands.length) }, worker));

  for (const { c, hit, status, error } of results) {
    wstream.write(JSON.stringify({ target: c.target, cname: c.cname, provider: c.provider.name, hit, status, error }) + '\n');
    if (hit) {
      db.insertFinding({
        tool: 'cname-takeover',
        target: c.target,
        category: `takeover-${c.provider.name}`,
        severity: c.provider.severity,
        title: `Dangling CNAME → ${c.provider.name} (takeover fingerprint matched at ${c.cname})`,
        cve: null,
        matched_at: c.cname,
        meta: { provider: c.provider.name, cname: c.cname, status },
      }, now, runId);
      findings++;
    }
  }
  await new Promise<void>((res) => wstream.end(() => res()));
  db.finishRun(runId, { targetsCount: cands.length, findingsCount: findings, at: new Date().toISOString() });
  db.close();
  console.error(`cname-takeover done: +${findings} takeover(s) across ${cands.length} candidate(s), run #${runId}`);
  console.error(`  sqlite: ${path.resolve(opts.sqlite)}`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
