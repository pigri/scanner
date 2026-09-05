#!/usr/bin/env -S node --loader tsx
// spf-chain: decompose SPF records into their full include tree, count DNS
// lookups against RFC 7208's limit of 10, flag third-party sender inclusion,
// and warn on permissive terminators (+all / ?all). Emits findings that
// checkdmarc's per-domain view doesn't cover (chain topology + provider
// exposure).
import fs from 'node:fs';
import path from 'node:path';
import { resolveTxt } from 'node:dns/promises';
import Database from 'better-sqlite3';

// Third-party sender providers whose SPF include indicates outsourced mail
// delivery. Not a vulnerability in itself, but a systemic-risk signal — a
// compromise in the provider spoofs every domain that includes them.
const THIRD_PARTY = [
  { re: /_spf\.google\.com/i,           name: 'google-workspace' },
  { re: /spf\.protection\.outlook\.com/i, name: 'microsoft-365' },
  { re: /sendgrid\.net/i,               name: 'sendgrid' },
  { re: /mailgun\.org/i,                name: 'mailgun' },
  { re: /amazonses\.com/i,              name: 'amazon-ses' },
  { re: /_spf\.mailjet\.com/i,          name: 'mailjet' },
  { re: /spf\.mandrillapp\.com/i,       name: 'mandrill' },
  { re: /_spf\.salesforce\.com/i,       name: 'salesforce' },
  { re: /zendesk\.com/i,                name: 'zendesk' },
  { re: /_spf\.qualtrics\.com/i,        name: 'qualtrics' },
  { re: /_spf\.constantcontact\.com/i,  name: 'constant-contact' },
  { re: /_spf\.mailchimp(app)?\.com/i,  name: 'mailchimp' },
  { re: /spf-.*\.hubspotemail\.net/i,   name: 'hubspot' },
  { re: /_spf\.freshdesk\.com/i,        name: 'freshdesk' },
  { re: /_spf\.intercom-mail\.com/i,    name: 'intercom' },
  { re: /_spf\.stripe\.com/i,           name: 'stripe' },
  { re: /_spf\.zoho(mail)?\.com/i,      name: 'zoho' },
] as const;

// A single SPF chain: each include/redirect follows to another TXT lookup.
// `lookups` counts every one of these — the RFC 7208 §4.6.4 limit is 10.
interface ChainNode { domain: string; record: string | null; children: ChainNode[]; error?: string }
interface ChainResult { root: ChainNode; lookups: number; providers: Set<string>; allQualifier: string | null; errors: string[] }

async function fetchSpf(domain: string): Promise<string | null> {
  try {
    const txts = await resolveTxt(domain);
    for (const chunks of txts) {
      const joined = chunks.join('');
      if (/^v=spf1\b/i.test(joined)) return joined;
    }
  } catch { /* NXDOMAIN / SERVFAIL — legit for many chain nodes */ }
  return null;
}

async function walk(domain: string, seen: Set<string>, depth: number, out: ChainResult): Promise<ChainNode> {
  const node: ChainNode = { domain, record: null, children: [] };
  if (seen.has(domain) || depth > 20) { node.error = 'cycle-or-depth-limit'; out.errors.push(`cycle at ${domain}`); return node; }
  seen.add(domain);
  const record = await fetchSpf(domain);
  node.record = record;
  if (!record) return node;

  // Detect provider inclusion by matching the raw record against known suffixes.
  for (const p of THIRD_PARTY) if (p.re.test(record)) out.providers.add(p.name);

  // Terminating `all` qualifier (last mechanism in the record).
  const m = /([~\-?+])all\b/.exec(record);
  if (m) out.allQualifier = m[0];

  const tokens = record.split(/\s+/);
  for (const tok of tokens) {
    let target: string | null = null;
    // These four mechanism types each count as one DNS lookup per RFC 7208 §4.6.4.
    if (/^include:/i.test(tok)) target = tok.split(':')[1] ?? null;
    else if (/^redirect=/i.test(tok)) target = tok.split('=')[1] ?? null;
    else if (/^a(:|$)/i.test(tok)) { out.lookups++; continue; }
    else if (/^mx(:|$)/i.test(tok)) { out.lookups++; continue; }
    else if (/^exists:/i.test(tok)) { out.lookups++; continue; }
    if (target) {
      out.lookups++;
      node.children.push(await walk(target.toLowerCase(), seen, depth + 1, out));
    }
  }
  return node;
}

async function analyze(target: string): Promise<ChainResult> {
  const result: ChainResult = { root: { domain: target, record: null, children: [] }, lookups: 0, providers: new Set(), allQualifier: null, errors: [] };
  result.root = await walk(target, new Set(), 0, result);
  return result;
}

function flattenChain(node: ChainNode, out: string[] = [], indent = 0): string[] {
  out.push('  '.repeat(indent) + (node.record ? `${node.domain}: ${node.record.slice(0, 120)}${node.record.length > 120 ? '…' : ''}` : `${node.domain}: <no SPF>${node.error ? ` (${node.error})` : ''}`));
  for (const c of node.children) flattenChain(c, out, indent + 1);
  return out;
}

function usage(): void {
  console.error(`Usage: spf-chain --sqlite <path> [--target <fqdn>] [--concurrency N]

Decomposes SPF records into their full include tree. Emits findings for:
  * DNS-lookup overflow (>10 per RFC 7208 §4.6.4) → high
  * Permissive terminator (+all)                  → critical
  * Neutral terminator (?all)                     → medium
  * No terminating all mechanism                  → medium
  * Third-party sender inclusion                  → low (per provider)

Sources targets from dns_records (TXT rows starting v=spf1). --target
restricts to one FQDN; otherwise sweeps every SPF-owning host.

Options:
  --sqlite <path>       default: scan.db
  --target <fqdn>       single-host mode
  --concurrency <N>     parallel domain analyses (default: 8)
`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let dbPath = 'scan.db';
  let focus: string | null = null;
  let concurrency = 8;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h' || a === '--help') { usage(); process.exit(0); }
    if (a === '--sqlite' || a === '--db') dbPath = argv[++i]!;
    else if (a === '--target') focus = argv[++i]!;
    else if (a === '--concurrency' || a === '-c') concurrency = parseInt(argv[++i]!, 10);
  }

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  const now = new Date().toISOString();
  const runId = Number((db.prepare('INSERT INTO runs(tool, started_at, args_json) VALUES(?,?,?)').run('spf-chain', now, JSON.stringify({ focus, concurrency }))).lastInsertRowid);

  const rows = focus
    ? db.prepare(`SELECT DISTINCT target FROM dns_records WHERE target = ? AND type='TXT' AND value LIKE 'v=spf1%'`).all(focus)
    : db.prepare(`SELECT DISTINCT target FROM dns_records WHERE type='TXT' AND value LIKE 'v=spf1%' ORDER BY target`).all();
  const targets = (rows as { target: string }[]).map((r) => r.target);
  console.error(`spf-chain: ${targets.length} SPF-owning target(s) to analyze`);

  const insertFinding = db.prepare(`
    INSERT INTO findings(tool, target, category, severity, title, cve, matched_at, meta_json, seen_at, run_id)
    VALUES('spf-chain', @target, @category, @severity, @title, NULL, @target, @meta, @seen_at, @run_id)
  `);
  let findings = 0;
  const emit = (target: string, category: string, severity: string, title: string, meta: unknown): void => {
    insertFinding.run({ target, category, severity, title, meta: JSON.stringify(meta), seen_at: now, run_id: runId });
    findings++;
  };

  const outLines: string[] = [];
  let idx = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const i = idx++;
      if (i >= targets.length) return;
      const t = targets[i]!;
      try {
        const chain = await analyze(t);
        outLines.push(`\n=== ${t} (lookups=${chain.lookups}, all=${chain.allQualifier ?? 'missing'}, providers=${[...chain.providers].join(',') || 'none'}) ===`);
        outLines.push(...flattenChain(chain.root));

        if (chain.lookups > 10) {
          emit(t, 'spf-lookups-over-limit', 'high',
            `SPF chain exceeds RFC 7208 10-lookup limit (${chain.lookups} lookups) — receivers may permerror`,
            { lookups: chain.lookups, providers: [...chain.providers] });
        }
        if (chain.allQualifier === '+all') {
          emit(t, 'spf-plus-all', 'critical', 'SPF terminates with +all — any sender authorized', { record: chain.root.record });
        } else if (chain.allQualifier === '?all') {
          emit(t, 'spf-neutral-all', 'medium', 'SPF terminates with ?all — neutral qualifier provides no protection', { record: chain.root.record });
        } else if (!chain.allQualifier && chain.root.record) {
          emit(t, 'spf-no-all', 'medium', 'SPF has no terminating all mechanism — implementation-defined fallback', { record: chain.root.record });
        }
        for (const provider of chain.providers) {
          emit(t, `spf-third-party-${provider}`, 'low',
            `SPF authorizes third-party sender: ${provider}`,
            { provider });
        }
        console.error(`  ${t}: lookups=${chain.lookups}, all=${chain.allQualifier ?? '-'}, providers=${chain.providers.size}`);
      } catch (e) {
        console.error(`  ${t}: analysis failed — ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker));

  const outDir = path.dirname(path.resolve(dbPath));
  const runDir = path.join(outDir, 'runs', String(runId));
  fs.mkdirSync(runDir, { recursive: true });
  fs.writeFileSync(path.join(runDir, 'spf-chain.txt'), outLines.join('\n') + '\n');

  db.prepare('UPDATE runs SET finished_at=?, targets_count=?, findings_count=? WHERE id=?')
    .run(new Date().toISOString(), targets.length, findings, runId);
  db.close();
  console.error(`spf-chain done: +${findings} finding(s) across ${targets.length} SPF-owning host(s), run #${runId}`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
