import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanChildEnv } from './scan-all-runner.js';

// Liveness pre-filter for enqueue: probe candidate hosts with naabu across
// the top-100 TCP ports (default) and keep any host that answers on ANY of
// them. Used to be httpx-only, but that dropped hosts serving SSH, SMB,
// SMTP, VPN, ICS/SCADA, IPMI, MSSQL, RDP — every non-web service in the
// pipeline. Naabu -tp 100 covers the standard "is this machine alive at
// all" question without over-scanning.

/**
 * Extract the set of live host identifiers from naabu `-j` (JSONL) output.
 * Naabu emits one `{"host":"…","ip":"…","port":N,...}` per open port; a host
 * with N open ports produces N lines. We collapse to distinct host / IP
 * identifiers. Pure — unit-testable without spawning naabu.
 */
export function parseLiveHosts(stdout: string): Set<string> {
  const live = new Set<string>();
  for (const raw of stdout.split('\n')) {
    const line = raw.trim();
    if (!line || !line.startsWith('{')) continue;
    try {
      const row = JSON.parse(line) as { host?: string; ip?: string };
      const id = (row.host || row.ip || '').toLowerCase();
      if (id) live.add(id);
    } catch { /* skip malformed line */ }
  }
  return live;
}

export interface ProbeOpts { timeoutSec?: number; threads?: number }

/**
 * Run httpx over `targets` and return the set of live hostnames. Resolves to an
 * empty set for empty input. Rejects if httpx can't be spawned (caller decides
 * whether to fail open). Uses scanChildEnv so httpx resolves via $HOME/go/bin.
 */
export function probeLive(targets: readonly string[], opts: ProbeOpts = {}): Promise<Set<string>> {
  return new Promise((resolve, reject) => {
    if (!targets.length) { resolve(new Set()); return; }
    const tmp = path.join(os.tmpdir(), `enqueue-live-${process.pid}-${targets.length}.txt`);
    fs.writeFileSync(tmp, targets.join('\n') + '\n');
    // -tp 100 = top-100 TCP ports (SSH/SMTP/IMAP/RDP/SMB/HTTPS/DB/etc.).
    // -scan-type c = TCP connect scan (works over any transport, no root).
    // -Pn = skip host discovery (WG/tun doesn't carry ICMP anyway).
    // -j -silent = one JSON line per open port; nothing else on stdout.
    const args = [
      '-l', tmp,
      '-tp', '100',
      '-scan-type', 'c',
      '-rate', String((opts.threads ?? 50) * 40),
      '-retries', '1',
      '-Pn',
      '-timeout', String((opts.timeoutSec ?? 5) * 1000),
      '-j', '-silent',
    ];
    let out = '';
    // stdin MUST be 'ignore': naabu reads targets from stdin when it isn't a
    // TTY, so a default piped stdin blocks it forever waiting for EOF.
    const child = spawn('naabu', args, { env: scanChildEnv({}), stdio: ['ignore', 'pipe', 'ignore'] });
    child.stdout.on('data', (d: Buffer) => { out += d.toString(); });
    child.on('error', (err) => { try { fs.unlinkSync(tmp); } catch { /* ignore */ } reject(err); });
    child.on('close', () => { try { fs.unlinkSync(tmp); } catch { /* ignore */ } resolve(parseLiveHosts(out)); });
  });
}
