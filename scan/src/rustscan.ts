#!/usr/bin/env -S node --loader tsx
// Rustscan: very fast port sweep. By default hands the open-port set to nmap
// for service detection (rustscan's own `--` passthrough). We can also skip
// the nmap step with --no-nmap and just persist the port list.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { resolve4 } from 'node:dns/promises';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';
import { parseRustscanStdout } from './lib/rustscan-parse.js';

// Same rationale as masscan.ts: rustscan resolves FQDNs internally and only
// emits IPs in --greppable output, so we do our own resolution first and keep
// the ip→FQDN map so ports are keyed by target=FQDN (joins with findings /
// http_probes / everything else in the DB).
async function resolveTargets(targets: readonly string[]): Promise<{ ips: string[]; byIp: Map<string, string> }> {
  const ips: string[] = [];
  const byIp = new Map<string, string>();
  await Promise.all(targets.map(async (t) => {
    if (net.isIP(t)) { ips.push(t); byIp.set(t, t); return; }
    try {
      const addrs = await resolve4(t);
      for (const ip of addrs) { ips.push(ip); if (!byIp.has(ip)) byIp.set(ip, t); }
    } catch (e) {
      console.error(`  resolve failed: ${t} (${e instanceof Error ? e.message : String(e)})`);
    }
  }));
  return { ips, byIp };
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let ulimit = 5000;
  let rangeStart = 1;
  let rangeEnd = 65535;
  let ports: string | null = null;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--ulimit') ulimit = parseInt(nxt(), 10);
    else if (a === '--range') { const [s, e] = nxt().split('-'); rangeStart = parseInt(s!, 10); rangeEnd = parseInt(e!, 10); }
    else if (a === '--ports') ports = nxt();
    else if (a === '--no-nmap') { /* deprecated: greppable already skips the built-in nmap */ }
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('rustscan', `
Fast port sweep with rustscan (greppable mode — never invokes the built-in
nmap handoff; we run our own nmap stage separately).

Wrapper flags (before '--'):
  --ulimit <N>      fd limit (default: 5000)
  --range <a-b>     port range (default: 1-65535)
  --ports <list>    explicit port list, e.g. "22,80,443,3306"

Everything after '--' passes to rustscan as-is (post-scan command).`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('rustscan');

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('rustscan', { targets: targets.length, ulimit, ports }, now) : null;

  const { ips, byIp } = await resolveTargets(targets);
  if (!ips.length) {
    console.error('rustscan: no targets resolved to IPs, nothing to scan');
    if (db && runId !== null) {
      db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
      db.close();
    }
    return;
  }

  const tmpTargets = resolveOutputPath({ ...opts, outFile: null }, runId, 'rustscan-targets.txt');
  writeLines(tmpTargets, ips);
  const outFile = resolveOutputPath(opts, runId, 'rustscan.txt');

  const portArgs = ports ? ['-p', ports] : ['-r', `${rangeStart}-${rangeEnd}`];
  // -g/--greppable already suppresses the built-in nmap handoff, so no --no-nmap
  // is needed (and older versions of that flag were removed in rustscan >=2.4).
  const tail = passthrough.length ? ['--', ...passthrough] : [];
  const args = ['-a', ips.join(','), '--ulimit', String(ulimit), '--greppable', ...portArgs, ...tail];
  console.error(`rustscan ${args.join(' ')}`);

  const r = await run('rustscan', args);
  fs.writeFileSync(outFile, r.stdout);
  const hits = parseRustscanStdout(r.stdout);
  console.error(`rustscan exit ${r.code}, ${hits.length} open ports across ${new Set(hits.map((h) => h.ip)).size} hosts`);
  console.error(`  raw: ${outFile}`);

  if (db && runId !== null) {
    // Tarpit / decoy filter: real hosts don't listen on hundreds of TCP
    // ports across the whole range. When a target's port count crosses
    // TARPIT_PORT_THRESHOLD, it's overwhelmingly a firewall/LB/honeypot
    // that returns SYN-ACK to every probe. Persisting those rows pollutes
    // the ports table with garbage (adatcsere.posta.hu: 1163 rows for one
    // host including 65331/65332/65503 — clearly not real services).
    // Instead, insert one sentinel row per tarpitted host so it's still
    // visible for review but doesn't inflate scores or dashboards.
    const TARPIT_PORT_THRESHOLD = 150;
    const byTarget = new Map<string, typeof hits>();
    for (const h of hits) {
      const target = byIp.get(h.ip) ?? h.ip;
      const arr = byTarget.get(target) ?? [];
      arr.push(h);
      byTarget.set(target, arr);
    }
    let inserted = 0, tarpitted = 0, tarpitHosts = 0;
    for (const [target, hostHits] of byTarget) {
      if (hostHits.length >= TARPIT_PORT_THRESHOLD) {
        tarpitHosts++;
        tarpitted += hostHits.length;
        console.error(`  TARPIT DETECTED on ${target}: ${hostHits.length} ports — inserting sentinel row only`);
        db.insertPort({
          target, ip: hostHits[0]!.ip,
          port: 0, protocol: 'tcp',
          service: 'tarpit-decoy',
          product: null, version: null, tunnel: null,
          extrainfo: `rustscan flagged ${hostHits.length} ports on this host — firewall/LB SYN-ACK spray, not real services`,
        }, now, runId);
        continue;
      }
      for (const h of hostHits) {
        db.insertPort({ target, ip: h.ip, port: h.port, protocol: 'tcp' }, now, runId);
        inserted++;
      }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: inserted, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${inserted} ports, run #${runId}${tarpitHosts ? `, dropped ${tarpitted} from ${tarpitHosts} tarpit host(s)` : ''})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
