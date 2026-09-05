#!/usr/bin/env -S node --loader tsx
// dnsx: ProjectDiscovery DNS query tool. Persists A/AAAA/CNAME/MX/TXT/NS/SOA
// per FQDN into the dns_records table. Useful for later scanning heuristics —
// wildcard detection, dangling CNAMEs (takeover candidates), SPF/DKIM/DMARC
// audits, and MX/mail-server inventory.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb, type DnsRecordRow } from './lib/db.js';

// Fields dnsx emits per JSON row when queried with -all.
interface DnsxRow {
  host?: string;
  ttl?: number;
  a?: string[];
  aaaa?: string[];
  cname?: string[];
  mx?: string[];
  ns?: string[];
  txt?: string[];
  ptr?: string[];
  srv?: string[];
  caa?: string[];
  soa?: Array<{ ns?: string; mailbox?: string; serial?: number } | string>;
  status_code?: string;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let resolvers: string | null = null;
  let rateLimit = 500;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--resolvers' || a === '-r') resolvers = nxt();
    else if (a === '--rate-limit') rateLimit = parseInt(nxt(), 10);
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('dnsx', `
ProjectDiscovery dnsx — batch DNS resolver. Queries A/AAAA/CNAME/MX/TXT/NS/
SOA per in-scope target and persists into dns_records (deduped by
(target, name, type, value)).

Default profile: -all -j -silent (system resolvers). Uses dnsx's built-in
concurrency + rate limiting.

Wrapper flags (before '--'):
  --resolvers/-r <list>  comma-separated resolvers or file (default: system)
  --rate-limit <N>       queries/sec (default: 500)

Everything after '--' passes to dnsx verbatim.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('dnsx');

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('dnsx', { targets: targets.length, resolvers, rateLimit }, now) : null;

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'dnsx-targets.txt');
  writeLines(tmp, targets);
  const outFile = resolveOutputPath(opts, runId, 'dnsx.jsonl');

  const args = [
    '-l', tmp,
    '-all',
    '-j', '-o', outFile,
    '-rl', String(rateLimit),
    ...(resolvers ? ['-r', resolvers] : []),
    '-silent',
    ...passthrough,
  ];
  console.error(`dnsx ${args.join(' ')}`);
  const r = await run('dnsx', args, { timeoutMs: 5 * 60 * 1000 });
  console.error(`dnsx exited ${r.code}, output: ${outFile}`);
  if (r.code !== 0 && r.stderr) console.error(r.stderr.slice(0, 500));

  if (db && runId !== null && fs.existsSync(outFile)) {
    let count = 0;
    const push = (t: string, name: string, type: string, value: string, ttl?: number): void => {
      const row: DnsRecordRow = { target: t, name, type, value };
      if (ttl !== undefined) row.ttl = ttl;
      db.insertDnsRecord(row, now, runId);
      count++;
    };
    for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        const row = JSON.parse(t) as DnsxRow;
        if (!row.host) continue;
        const target = row.host;
        for (const v of row.a ?? [])     push(target, target, 'A', v, row.ttl);
        for (const v of row.aaaa ?? [])  push(target, target, 'AAAA', v, row.ttl);
        for (const v of row.cname ?? []) push(target, target, 'CNAME', v, row.ttl);
        for (const v of row.mx ?? [])    push(target, target, 'MX', v, row.ttl);
        for (const v of row.ns ?? [])    push(target, target, 'NS', v, row.ttl);
        for (const v of row.txt ?? [])   push(target, target, 'TXT', v, row.ttl);
        for (const v of row.ptr ?? [])   push(target, target, 'PTR', v, row.ttl);
        for (const v of row.srv ?? [])   push(target, target, 'SRV', v, row.ttl);
        for (const v of row.caa ?? [])   push(target, target, 'CAA', v, row.ttl);
        for (const s of row.soa ?? []) {
          const val = typeof s === 'string' ? s : (s.ns ?? '');
          if (val) push(target, target, 'SOA', val, row.ttl);
        }
      } catch { /* ignore */ }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${count} records, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
