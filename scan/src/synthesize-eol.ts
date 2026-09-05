#!/usr/bin/env -S node --loader tsx
// Post-process http_probes into synthetic findings for known-EOL software.
// Cheap heuristic pass — not a substitute for nuclei's CVE templates, but catches
// obvious outdated stack disclosures that a severity filter would miss.
import { openDb } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';

interface Opts { db: string; help?: boolean }
function parseArgs(argv: string[]): Opts {
  // DB path (--sqlite / --db alias) resolved by the shared helper.
  const opts: Opts = { db: resolveDbArg(argv) };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (isDbFlag(a)) { i++; continue; } // flag + value already consumed by resolveDbArg
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

// Rules: [regex, severity, category, title-fn]
type Rule = { re: RegExp; sev: string; cat: string; title: (m: RegExpMatchArray) => string };

const RULES: Rule[] = [
  // Microsoft IIS
  { re: /Microsoft-IIS\/([\d.]+)/i, sev: 'medium', cat: 'outdated-iis',
    title: (m) => `IIS ${m[1]} disclosed (map to Windows Server release notes for CVE exposure)` },
  // nginx (any explicit version disclosure is signal; specific-CVE mapping needs an external DB)
  { re: /nginx\/([\d.]+)/i, sev: 'low', cat: 'nginx-version',
    title: (m) => `nginx ${m[1]} version disclosed` },
  // Apache
  { re: /Apache\/([\d.]+)/i, sev: 'low', cat: 'apache-version',
    title: (m) => `Apache ${m[1]} version disclosed` },
  // OpenSSL — 1.0.x / 1.1.x are EOL
  { re: /OpenSSL\/(1\.0\.[\d]+[a-z]?|1\.1\.[\d]+[a-z]?)/i, sev: 'high', cat: 'eol-openssl',
    title: (m) => `EOL OpenSSL ${m[1]} disclosed (1.0/1.1 series are past EOL)` },
  // PHP EOL: <=7.4 is EOL, <=8.0 is EOL
  { re: /PHP\/(4\.|5\.|7\.|8\.0\.)([\d.]+)/i, sev: 'high', cat: 'eol-php',
    title: (m) => `EOL PHP ${m[1]}${m[2]} disclosed` },
];

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { console.error('Usage: synthesize-eol [--sqlite scan.db]'); process.exit(0); }
  const db = openDb(opts.db);
  const now = new Date().toISOString();
  const runId = db.startRun('synthesize-eol', {}, now);
  const rows = db.raw.prepare(
    'SELECT target, url, web_server, tech_json FROM http_probes WHERE web_server IS NOT NULL'
  ).all() as { target: string; url: string; web_server: string; tech_json: string | null }[];
  let added = 0;
  for (const r of rows) {
    const hay = r.web_server + ' ' + (r.tech_json ?? '');
    for (const rule of RULES) {
      const m = hay.match(rule.re);
      if (!m) continue;
      db.insertFinding({
        tool: 'synthesize-eol',
        target: r.target,
        category: rule.cat,
        severity: rule.sev,
        title: rule.title(m),
        cve: null,
        matched_at: r.url,
        meta: { web_server: r.web_server, tech: r.tech_json },
      }, now, runId);
      added++;
    }
  }
  db.finishRun(runId, { targetsCount: rows.length, findingsCount: added, at: new Date().toISOString() });
  db.close();
  console.error(`synthesized ${added} findings from ${rows.length} http_probes rows`);
}

main();
