#!/usr/bin/env -S node --loader tsx
// checkdmarc: batch DNS-level email-security audit (SPF, DMARC, MTA-STS,
// DNSSEC, BIMI, SMTP-TLS-Reporting). Emits findings for missing / weak /
// invalid records — direct phishing-enablement signal for the estate.
//
// Slow-ish: MX SMTP probes tack ~7-8s per domain. Runs with --skip-tls
// by default because we've got other tools (testssl) for TLS auditing and
// the timeouts pile up per batch.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

interface CheckdmarcResult {
  domain?: string;
  base_domain?: string;
  dnssec?: boolean;
  spf?: { record?: string | null; valid?: boolean; warnings?: string[] };
  dmarc?: { record?: string | null; valid?: boolean; error?: string; location?: string };
  mta_sts?: { valid?: boolean; error?: string };
  smtp_tls_reporting?: { valid?: boolean; error?: string };
  bimi?: { record?: string | null; valid?: boolean; error?: string };
  mx?: { hosts?: Array<{ hostname?: string; preference?: number }>; warnings?: string[] };
}

// Extract the DMARC policy tag (`p=...`) from a DMARC record string.
function dmarcPolicy(rec: string | null | undefined): string | null {
  if (!rec) return null;
  const m = /\bp\s*=\s*(none|quarantine|reject)/i.exec(rec);
  return m ? m[1]!.toLowerCase() : null;
}

// Classify the SPF "all" mechanism at the end (~all, -all, ?all, +all, missing).
function spfAllQualifier(rec: string | null | undefined): '~all' | '-all' | '?all' | '+all' | 'missing' {
  if (!rec) return 'missing';
  const m = /([~\-?+])all\b/i.exec(rec);
  return m ? (m[0] as '~all' | '-all' | '?all' | '+all') : 'missing';
}

// checkdmarc reports SPF as missing when there is no TXT record at the exact
// name — but for CNAME'd domains (e.g. kormany.gov.hu → kormany.hu), real SPF
// receivers follow the CNAME and see the SPF at the target. This helper does
// the CNAME-chasing lookup with `dig` and returns the SPF record + the chain
// it traversed to find it, or null if no SPF exists at either the name or any
// CNAME target.
async function lookupSpfViaCname(domain: string): Promise<{ record: string; chain: string[] } | null> {
  // 1) Walk the CNAME chain to find the final canonical name.
  const chain = [domain];
  let current = domain;
  for (let hop = 0; hop < 5; hop++) {
    const r = await run('dig', ['+short', 'CNAME', current], { timeoutMs: 5000 });
    if (r.code !== 0) break;
    const target = r.stdout.trim().split('\n').filter(Boolean)[0];
    if (!target) break;
    const clean = target.replace(/\.$/, '').toLowerCase();
    if (clean === current || chain.includes(clean)) break;
    chain.push(clean);
    current = clean;
  }
  if (chain.length === 1) return null;   // no CNAME → checkdmarc's answer stands
  // 2) TXT query at the final canonical name — pull whole records, join
  //    multi-string TXTs (dnspython/dig wrap TXT strings in quotes).
  const tx = await run('dig', ['+short', 'TXT', current], { timeoutMs: 5000 });
  if (tx.code !== 0) return null;
  for (const line of tx.stdout.split('\n')) {
    const joined = line.replaceAll('" "', '').replaceAll('"', '').trim();
    if (/^v=spf1\b/i.test(joined)) return { record: joined, chain };
  }
  return null;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let skipTls = true;             // TLS probes to MX add ~8s per host; testssl covers TLS separately
  let timeout = 5;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--tls') skipTls = false;
    else if (a === '--timeout') timeout = parseInt(nxt(), 10);
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('checkdmarc', `
checkdmarc — validate SPF / DMARC / MTA-STS / DNSSEC / BIMI /
SMTP-TLS-Reporting per FQDN. Findings emitted per weak/missing record.

Default profile: --skip-tls --timeout 5. Runs all targets in one invocation
(checkdmarc parallelizes internally). --skip-tls kills the ~8s/host MX SMTP
TLS probe — testssl already audits TLS separately.

Wrapper flags (before '--'):
  --tls              re-enable MX SMTP TLS probe (slow; default is --skip-tls)
  --timeout <sec>    per-DNS-query timeout (default: 5)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('checkdmarc');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('checkdmarc', { targets: targets.length, skipTls }, now) : null;

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'checkdmarc-targets.txt');
  fs.writeFileSync(tmp, targets.join('\n') + '\n');
  const outFile = resolveOutputPath(opts, runId, 'checkdmarc.json');

  const args = [
    tmp,                    // domain positional (accepts file path)
    '-f', 'json',
    '-o', outFile,
    '-t', String(timeout),
    ...(skipTls ? ['--skip-tls'] : []),
    ...passthrough,
  ];
  console.error(`checkdmarc ${args.join(' ')}`);
  const r = await run('checkdmarc', args, { timeoutMs: Math.max(30 * targets.length, 300) * 1000 });
  console.error(`checkdmarc exited ${r.code}, output: ${outFile}`);
  if (r.code !== 0 && r.stderr) console.error(r.stderr.slice(0, 500));

  if (!db || runId === null || !fs.existsSync(outFile)) return;

  const parsed = JSON.parse(fs.readFileSync(outFile, 'utf8')) as CheckdmarcResult | CheckdmarcResult[];
  const rows: CheckdmarcResult[] = Array.isArray(parsed) ? parsed : [parsed];
  let findings = 0;
  const emit = (target: string, category: string, severity: string, title: string, meta: unknown): void => {
    // If the caller stuck `needs_review: true` into meta (see the CNAME-SPF
    // path), promote that to the DB column so `query review` finds it.
    const needsReview = !!(meta && typeof meta === 'object' && (meta as { needs_review?: boolean }).needs_review);
    db.insertFinding({
      tool: 'checkdmarc', target, category, severity, title, matched_at: target, meta, needsReview,
    }, now, runId);
    findings++;
  };

  for (const row of rows) {
    const t = row.domain;
    if (!t) continue;

    // Does the domain receive mail? MX presence changes the risk profile for
    // SPF/DMARC/MTA-STS: a mail-receiving domain is a live phishing target
    // and needs full authentication; a web-only subdomain (no MX) can still
    // be spoofed as a From: address but the impact is materially lower, and
    // the practical fix is different (publish `-all` SPF for hardening, or
    // inherit DMARC from the org domain).
    const hasMx = !!(row.mx && row.mx.hosts && row.mx.hosts.length);
    const mxNote = hasMx ? '' : ' (domain has no MX — receives no mail)';

    // ---- DMARC ------------------------------------------------------------
    const dmarc = row.dmarc ?? {};
    if (!dmarc.record) {
      // Even without MX, the domain can be spoofed as a From: address in
      // phishing. But DMARC on the organisational domain typically inherits
      // to subdomains, so an individual subdomain missing DMARC is less
      // urgent than a mail-receiving domain missing it. High → medium.
      emit(t, 'dmarc', hasMx ? 'high' : 'medium',
        `DMARC missing — domain can be spoofed directly${mxNote}`,
        { error: dmarc.error ?? null, has_mx: hasMx });
    } else if (dmarc.valid === false) {
      emit(t, 'dmarc', 'medium',
        'DMARC record present but invalid',
        { record: dmarc.record, error: dmarc.error ?? null, has_mx: hasMx });
    } else {
      const pol = dmarcPolicy(dmarc.record);
      if (pol === 'none') {
        emit(t, 'dmarc', 'medium',
          'DMARC p=none — monitor-only, no enforcement against spoofing',
          { record: dmarc.record, policy: pol, has_mx: hasMx });
      } else if (pol === 'quarantine' || pol === 'reject') {
        emit(t, 'dmarc', 'info',
          `DMARC p=${pol} — enforcing`,
          { record: dmarc.record, policy: pol, has_mx: hasMx });
      }
    }

    // ---- SPF -------------------------------------------------------------
    const spf = row.spf ?? {};
    if (!spf.record) {
      // checkdmarc queries at the exact record name. Domains that CNAME to
      // another zone (e.g. kormany.gov.hu → kormany.hu) legitimately hold
      // their SPF at the CNAME target — real receivers follow the chain and
      // see it, so "SPF missing" is a false positive on those. Do a native
      // CNAME-chasing TXT lookup as a second opinion: if we find v=spf1 at
      // the target, downgrade to info and mark needs_review so a human can
      // confirm the receiver-side behavior.
      const cnameSpf = await lookupSpfViaCname(t);
      if (cnameSpf) {
        emit(t, 'spf', 'info',
          `SPF present via CNAME chain (${cnameSpf.chain.join(' → ')}) — receivers that follow CNAMEs will see it`,
          {
            record: cnameSpf.record, has_mx: hasMx,
            cname_chain: cnameSpf.chain,
            needs_review: true,
            body_status: null,
            body_preview: `SPF found at CNAME target:\n${cnameSpf.record}`,
          });
      } else {
        // No MX means no one legitimately sends from here either (in practice
        // the org uses a central mailer under a different subdomain). Without
        // SPF, sender-IP verification just can't happen — that's a hardening
        // gap (publish `v=spf1 -all` to explicitly declare no senders), not a
        // live phishing enabler. High → low.
        emit(t, 'spf', hasMx ? 'high' : 'low',
          `SPF missing — recipients cannot verify sending IPs${mxNote}`,
          { warnings: spf.warnings ?? [], has_mx: hasMx });
      }
    } else {
      const qual = spfAllQualifier(spf.record);
      if (qual === '+all') {
        emit(t, 'spf', 'critical', 'SPF +all — any sender is authorized (open relay for spoofing)', { record: spf.record, has_mx: hasMx });
      } else if (qual === '?all') {
        emit(t, 'spf', 'medium', 'SPF ?all — neutral qualifier, no protection', { record: spf.record, has_mx: hasMx });
      } else if (qual === 'missing') {
        emit(t, 'spf', 'medium', 'SPF has no "all" mechanism — undefined fallback behavior', { record: spf.record, has_mx: hasMx });
      } else if (qual === '~all') {
        emit(t, 'spf', 'low', 'SPF ~all — soft-fail, most receivers will still accept', { record: spf.record, has_mx: hasMx });
      } else {
        // -all → good
        emit(t, 'spf', 'info', 'SPF -all — strict, unauthorized senders rejected', { record: spf.record, has_mx: hasMx });
      }
      if (spf.valid === false) {
        emit(t, 'spf', 'medium',
          'SPF record present but invalid (syntax / lookup limits)',
          { record: spf.record, warnings: spf.warnings ?? [], has_mx: hasMx });
      }
    }

    // ---- DNSSEC / MTA-STS / SMTP-TLS-Reporting / BIMI --------------------
    // DNSSEC applies regardless of mail — protects all DNS lookups for the zone.
    if (row.dnssec === false) {
      emit(t, 'dnssec', 'low', 'DNSSEC not enabled on domain', {});
    }
    // MTA-STS and TLS-RPT only apply to receiving mail. When there's no MX
    // the "missing" finding is essentially N/A → downgrade to info so it
    // doesn't clog the low-severity queue.
    if (row.mta_sts && row.mta_sts.valid === false) {
      emit(t, 'mta-sts', hasMx ? 'low' : 'info',
        `MTA-STS missing or invalid${mxNote}`,
        { error: row.mta_sts.error ?? null, has_mx: hasMx });
    }
    if (row.smtp_tls_reporting && row.smtp_tls_reporting.valid === false) {
      emit(t, 'smtp-tls-reporting', 'info', `SMTP TLS Reporting (TLS-RPT) missing or invalid${mxNote}`, { error: row.smtp_tls_reporting.error ?? null, has_mx: hasMx });
    }
    // BIMI is opt-in — only flag when present-but-invalid, not when absent.
    if (row.bimi && row.bimi.record && row.bimi.valid === false) {
      emit(t, 'bimi', 'info', 'BIMI record present but invalid', { record: row.bimi.record, error: row.bimi.error ?? null });
    }

    // ---- MX gotchas ------------------------------------------------------
    if (!hasMx) {
      emit(t, 'mx', 'info',
        'No MX records — domain does not receive mail (spoofing risk if brand still emails users)',
        { has_mx: false });
    }
  }

  db.finishRun(runId, { targetsCount: rows.length, findingsCount: findings, at: new Date().toISOString() });
  db.close();
  console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${findings} findings across ${rows.length} domains, run #${runId})`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
