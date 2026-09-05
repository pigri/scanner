#!/usr/bin/env -S node --loader tsx
// naabu: ProjectDiscovery's port scanner. Alternative to masscan that works
// over L3-only transports (WireGuard/tun netns) because -scan-type=connect
// uses TCP connect() at the socket layer, no raw ethernet frames. Also
// handles FQDN targets natively (JSON output carries both `host` FQDN and
// `ip`), so no reverse-map dance like masscan/rustscan need.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  // Own flags (before --): --top-ports, --ports, --rate, --scan-type
  let topPorts: string | null = 'full';
  let ports: string | null = null;
  let rate = '2000';
  let scanType = 'c';           // connect scan — works over WG, no root
  let retries = '1';            // dedupe pressure: naabu re-checks by default
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--top-ports') { topPorts = nxt(); ports = null; }
    else if (a === '--ports') { ports = nxt(); topPorts = null; }
    else if (a === '--rate') rate = nxt();
    else if (a === '--scan-type') scanType = nxt();
    else if (a === '--retries') retries = nxt();
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('naabu', `
ProjectDiscovery naabu — fast port sweep, TCP-connect by default so it works
over any transport (including WG/tun netns where masscan can't).

Default profile: -tp full -scan-type c -rate 2000 -retries 1 -Pn -j -silent.
Emits JSON keyed by both FQDN and resolved IP — no reverse-map dance.

Wrapper flags (before '--'):
  --top-ports <n|full>  naabu -top-ports (default: full = all 65535)
  --ports <list>        explicit port list, e.g. "22,80,443,3306" (overrides --top-ports)
  --rate <N>            packets/sec across the whole run (default: 2000)
  --scan-type <c|s>     connect (default, no root) or SYN (needs root, WG-hostile)
  --retries <N>         per-port retries (default: 1)

Everything after '--' passes to naabu verbatim.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('naabu');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('naabu', { targets: targets.length, topPorts, ports, rate, scanType }, now) : null;

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'naabu-targets.txt');
  writeLines(tmp, targets);
  const outFile = resolveOutputPath(opts, runId, 'naabu.jsonl');

  const portArgs = ports ? ['-p', ports] : ['-tp', topPorts!];
  const args = [
    '-l', tmp,
    ...portArgs,
    '-scan-type', scanType,
    '-rate', rate,
    '-retries', retries,
    '-Pn',        // skip host discovery — behind WG we can't rely on ICMP
    '-j',
    '-o', outFile,
    '-silent',
    ...passthrough,
  ];
  console.error(`naabu ${args.join(' ')}`);
  const r = await run('naabu', args);
  console.error(`naabu exited ${r.code}, output: ${outFile}`);
  if (r.code !== 0 && r.stderr) console.error(r.stderr.slice(0, 500));

  if (db && runId !== null && fs.existsSync(outFile)) {
    // Two-pass: bucket by target first, dedupe within run, then apply the
    // tarpit filter before insertion. See rustscan.ts for the rationale —
    // any target with >= TARPIT_PORT_THRESHOLD open ports is almost
    // certainly a firewall/LB that SYN-ACKs every probe; we insert one
    // sentinel row instead of hundreds of noise ports.
    const TARPIT_PORT_THRESHOLD = 150;
    interface Hit { target: string; ip: string; port: number; protocol: string }
    const byTarget = new Map<string, Hit[]>();
    const seen = new Set<string>();
    for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        const row = JSON.parse(t) as { host?: string; ip?: string; port?: number; protocol?: string };
        if (!row.port || !row.ip) continue;
        const target = row.host ?? row.ip;
        const proto = row.protocol ?? 'tcp';
        const key = `${target}|${row.port}|${proto}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const arr = byTarget.get(target) ?? [];
        arr.push({ target, ip: row.ip, port: row.port, protocol: proto });
        byTarget.set(target, arr);
      } catch { /* ignore */ }
    }
    let count = 0, tarpitted = 0, tarpitHosts = 0;
    for (const [target, hits] of byTarget) {
      if (hits.length >= TARPIT_PORT_THRESHOLD) {
        tarpitHosts++;
        tarpitted += hits.length;
        console.error(`  TARPIT DETECTED on ${target}: ${hits.length} ports — inserting sentinel row only`);
        db.insertPort({
          target, ip: hits[0]!.ip,
          port: 0, protocol: 'tcp',
          service: 'tarpit-decoy',
          product: null, version: null, tunnel: null,
          extrainfo: `naabu flagged ${hits.length} ports on this host — firewall/LB SYN-ACK spray, not real services`,
        }, now, runId);
        continue;
      }
      for (const h of hits) {
        db.insertPort({ target: h.target, ip: h.ip, port: h.port, protocol: h.protocol }, now, runId);
        count++;
      }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${count} open ports, run #${runId}${tarpitHosts ? `, dropped ${tarpitted} from ${tarpitHosts} tarpit host(s)` : ''})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
