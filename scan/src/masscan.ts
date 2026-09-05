#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { resolve4 } from 'node:dns/promises';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

// Masscan can't discover its own default interface inside network namespaces
// with only a wireguard interface (no eth0 → 'could not determine default
// interface'). Read `ip route show default` and pick the dev out of it so we
// pass --interface explicitly. Returns null when detection fails; caller lets
// masscan try on its own.
async function detectDefaultInterface(): Promise<string | null> {
  const r = await run('ip', ['-o', 'route', 'show', 'default']);
  if (r.code !== 0) return null;
  const m = /\bdev\s+(\S+)/.exec(r.stdout);
  return m ? m[1]! : null;
}

// Resolve every FQDN target to one or more IPv4 addresses. Masscan operates on
// IPs/CIDRs and refuses hostnames; we do DNS here and remember the reverse map
// so the ports table can be keyed by the original FQDN target (keeping joins
// with findings/http_probes/etc. intact).
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
  // Own flags: --banners, --ports, --rate, --source-ip
  let banners = false;
  // Default to a wide sweep — that's masscan's differentiator vs. nmap's
  // top-1000+DB_PORTS default. Rate 2000 keeps the total under ~2 min per
  // 25-host batch even at full range, and stays polite through the VPN.
  let ports = '1-65535';
  let rate = '2000';
  let sourceIp: string | null = null;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--banners') banners = true;
    else if (a === '--ports') ports = nxt();
    else if (a === '--rate') rate = nxt();
    else if (a === '--source-ip') sourceIp = nxt();
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('masscan', `
Wide TCP sweep with masscan. Resolves FQDN targets to IPv4 first (masscan
itself does not resolve hostnames) and persists open ports against the
original FQDN so DB joins with findings/http_probes stay intact.

Default profile: -p1-65535 --rate 2000 (~2 min for a 25-host batch).
Needs sudo/CAP_NET_RAW — invoked via 'sudo masscan'.

Wrapper flags (before '--'):
  --banners            enable --banners (banner grabbing on open ports).
                       Requires --source-ip on some kernels.
  --ports <list>       override default port list (e.g. "1-1000,3306,6379")
  --rate <N>           packets/sec (default: 2000; safe over VPN)
  --source-ip <ip>     required when --banners is used with default routes`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('masscan');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('masscan', { targets: targets.length, ports, rate }, now) : null;

  // Refuse to run over a wireguard / tun interface: masscan crafts raw L2
  // frames and needs an ARP-resolvable next-hop. Point-to-point tunnels
  // silently swallow the outbound packets AND drop the returns, so the run
  // would just hang until --scan-timeout. Skip cleanly and let the operator
  // know why.
  const dev = await detectDefaultInterface();
  if (dev && /^(wg|tun|utun|nordlynx|proton|mullvad)/i.test(dev)) {
    console.error(`masscan: default interface '${dev}' is a point-to-point tunnel; masscan needs an L2 (ethernet) next-hop. Skipping.`);
    console.error(`         Run outside the netns / on an eth interface if you need masscan coverage.`);
    if (db && runId !== null) {
      db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
      db.close();
    }
    return;
  }

  const { ips, byIp } = await resolveTargets(targets);
  if (!ips.length) {
    console.error('masscan: no targets resolved to IPs, nothing to scan');
    if (db && runId !== null) {
      db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
      db.close();
    }
    return;
  }
  console.error(`masscan: resolved ${targets.length} host(s) → ${ips.length} IP(s)`);

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'masscan-targets.txt');
  writeLines(tmp, ips);
  const outFile = resolveOutputPath(opts, runId, 'masscan.jsonl');
  const bannerArgs: string[] = banners ? ['--banners'] : [];
  const srcArgs: string[] = sourceIp ? ['--source-ip', sourceIp] : [];
  // Auto-detect --interface unless the caller supplied one via passthrough.
  // Needed inside network namespaces (e.g. scanvpn/wgscan) where masscan can't
  // guess the default itself.
  const hasIface = passthrough.some((a) => a === '--interface' || a === '-e');
  const ifaceArgs: string[] = [];
  if (!hasIface) {
    const dev = await detectDefaultInterface();
    if (dev) ifaceArgs.push('--interface', dev);
  }
  const args = [
    '-iL', tmp, `-p${ports}`,
    '--rate', rate, '-oJ', outFile,
    ...ifaceArgs, ...bannerArgs, ...srcArgs,
    ...passthrough,
  ];
  console.error(`masscan ${args.join(' ')} (via sudo)`);
  const r = await run('sudo', ['-n', 'masscan', ...args]);
  console.error(`masscan exited ${r.code}, output: ${outFile}`);
  if (r.code !== 0 && r.stderr) console.error(r.stderr.slice(0, 500));

  if (db && runId !== null && fs.existsSync(outFile)) {
    let count = 0;
    for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
      const trimmed = line.trim().replace(/,$/, '');
      if (!trimmed || trimmed === '[' || trimmed === ']') continue;
      try {
        const row = JSON.parse(trimmed) as { ip?: string; ports?: { port?: number; proto?: string; status?: string }[] };
        if (!row.ip || !row.ports) continue;
        // Prefer the original FQDN that resolved to this IP so downstream joins
        // against findings/http_probes (also keyed by target=FQDN) work. Fall
        // back to the IP itself for direct-IP inputs.
        const target = byIp.get(row.ip) ?? row.ip;
        for (const p of row.ports) {
          if (p.status !== 'open' || !p.port) continue;
          db.insertPort({
            target, ip: row.ip,
            port: p.port, protocol: p.proto ?? 'tcp',
          }, now, runId);
          count++;
        }
      } catch { /* ignore */ }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${count} open ports, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
