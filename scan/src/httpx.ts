#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('httpx', `
Runs projectdiscovery httpx. Probes BOTH schemes per target so hosts whose
HTTPS listener silently tarpits (common Big-IP pattern) still surface via
their HTTP endpoint. Default template:
  -sc -title -td -web-server -tech-detect -follow-host-redirects
  -threads 50 -timeout 10 -retries 2 (both http:// and https:// per target)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('httpx');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('httpx', { targets: targets.length, extraArgs: opts.extraArgs }, now) : null;

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'httpx-targets.txt');
  // Expand each bare hostname to explicit URLs so httpx probes each variant
  // independently:
  //   - http://foo, https://foo             (the 80/443 defaults)
  //   - http://foo:8080, https://foo:8443   (common alt-web ports)
  // The 8080/8443 expansion closes a real coverage gap: an August audit found
  // 7+ .mbfsz.gov.hu and hungarocontrol.hu hosts whose only web listener was
  // on 8443, invisible to the previous http:// + https:// pair. Extra cost is
  // 2 URLs/host — modest against the coverage win.
  // Emitting both http/https also defeats the HTTPS-tarpit pattern (Big-IP
  // accepts SYN, never completes handshake) that used to hide gov.hu dev
  // hosts entirely when httpx picked https:// first, timed out, and skipped.
  const expanded: string[] = [];
  for (const t of targets) {
    if (t.startsWith('http://') || t.startsWith('https://')) expanded.push(t);
    else {
      expanded.push(`http://${t}`);
      expanded.push(`https://${t}`);
      expanded.push(`http://${t}:8080`);
      expanded.push(`https://${t}:8443`);
    }
  }
  writeLines(tmp, expanded);
  const outFile = resolveOutputPath(opts, runId, 'httpx.jsonl');
  const args = [
    '-l', tmp, '-json', '-o', outFile,
    '-sc', '-title', '-td', '-web-server', '-tech-detect',
    // follow same-host redirects so a root 302 (nginx -> /ords/ etc.) resolves to
    // the real app's status/title/tech instead of a bare empty 302. Host-only to
    // stay in scope (won't chase an external redirect).
    '-follow-host-redirects', '-threads', '50',
    // -timeout 10s (default 5s) + -retries 2 catches slow-LB hosts that were
    // silently dropped before. Two schemes × two retries × 10s = at most
    // 40s per fully-dead host, worth the wait for the coverage win.
    '-timeout', '10', '-retries', '2',
    ...opts.extraArgs,
  ];
  console.error(`httpx ${args.join(' ')}`);
  const r = await run('httpx', args);
  console.error(`httpx exited ${r.code}, output: ${outFile}`);

  if (db && runId !== null && fs.existsSync(outFile)) {
    let count = 0;
    for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line) as {
          input?: string; url?: string; host?: string;
          status_code?: number; status?: number;
          title?: string; webserver?: string; 'web-server'?: string;
          tech?: string[]; technologies?: string[];
          content_length?: number; body_hash?: string; hash?: { body_sha256?: string };
        };
        // Normalize `target` to the bare hostname (matching scan_queue / ports).
        // We feed httpx expanded URLs (http://foo + https://foo), so row.input
        // is scheme-prefixed. Storing it verbatim broke every downstream join
        // (report-worker, risk.ts, sslyze/headers/ffuf live-only filters,
        // synthesize-eol, graph-export) because they all key on the bare host.
        const rawTarget = row.host ?? row.input ?? row.url ?? '';
        const target = rawTarget
          .replace(/^https?:\/\//i, '')
          .replace(/[/:?#].*$/, '')
          .replace(/\.$/, '')
          .toLowerCase();
        db.insertHttpProbe({
          target,
          url: row.url ?? '',
          status_code: row.status_code ?? row.status ?? null,
          title: row.title ?? null,
          web_server: row.webserver ?? row['web-server'] ?? null,
          tech: row.tech ?? row.technologies ?? null,
          content_length: row.content_length ?? null,
          hash_body: row.body_hash ?? row.hash?.body_sha256 ?? null,
        }, now, runId);
        count++;
      } catch { /* ignore malformed row */ }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${count} probes, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
