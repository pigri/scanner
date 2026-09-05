#!/usr/bin/env -S node --loader tsx
// NetExec (formerly CrackMapExec): SMB/WinRM/LDAP/MSSQL/RDP/SSH/FTP framework.
// This wrapper:
//   - Enforces the strict scope gate (--scope + --yes-i-am-authorized).
//   - Runs the tool with your credentials/protocol choice.
//   - Parses the standard `[+] host:port ... (Pwn3d!)` output into attempts + sessions.
//
// It does NOT auto-choose an attack mode. You pass the netexec verb + args
// after `--` verbatim, e.g.:
//   netexec --scope scope.txt --yes-i-am-authorized --sqlite attack.db \
//     -- smb hosts.txt -u admin -p 'Password1!' --continue-on-success
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { openDb } from './lib/db.js';
import { enforceGate } from './lib/gate.js';
import { parseNxcLines } from './lib/netexec-parse.js';

interface Opts {
  scopeFile: string | null;
  authorized: boolean;
  sqlite: string | null;
  targetsFile: string | null;
  extraArgs: string[];
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { scopeFile: null, authorized: false, sqlite: null, targetsFile: null, extraArgs: [] };
  let passthrough = false;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (passthrough) { opts.extraArgs.push(a); continue; }
    const next = () => argv[++i]!;
    if (a === '--') passthrough = true;
    else if (a === '--scope') opts.scopeFile = next();
    else if (a === '--yes-i-am-authorized') opts.authorized = true;
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '--targets') opts.targetsFile = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (!a.startsWith('-')) opts.extraArgs.push(a);
    else opts.extraArgs.push(a);
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: netexec --scope <file> --yes-i-am-authorized [--sqlite attack.db] -- <netexec args>

Gate:
  --scope <file>            required. Suffix + CIDR allowlist.
  --yes-i-am-authorized     required assertion of written authorization.

Data:
  --sqlite <path>           persist attempts + sessions + credentials.
  --targets <file>          hostname list for scope check
                            (netexec will still get its target list via its
                            own argv after '--').

Example:
  netexec --scope scope.txt --yes-i-am-authorized --sqlite attack.db \\
    --targets hosts.txt \\
    -- smb hosts.txt -u admin -p 'P@ssw0rd' --continue-on-success
`);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.extraArgs.length) { usage(); process.exit(opts.extraArgs.length ? 0 : 1); }

  const targets = opts.targetsFile
    ? fs.readFileSync(opts.targetsFile, 'utf8').split('\n').map((s) => s.trim()).filter((s) => s && !s.startsWith('#'))
    : [];
  enforceGate({ scopeFile: opts.scopeFile, authorized: opts.authorized, targets });

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('netexec', { args: opts.extraArgs }, opts.authorized, now) : null;

  console.error(`netexec ${opts.extraArgs.join(' ')}`);
  const out = await new Promise<string>((resolve) => {
    execFile('netexec', opts.extraArgs, { maxBuffer: 500 * 1024 * 1024, timeout: 6 * 60 * 60 * 1000 }, (_err, stdout, stderr) => {
      resolve((stdout || '') + (stderr || ''));
    });
  });

  const logFile = path.resolve(`netexec-${Date.now()}.log`);
  fs.writeFileSync(logFile, out);
  console.error(`raw log: ${logFile}`);

  if (db && runId !== null) {
    let attempts = 0, successes = 0;
    for (const r of parseNxcLines(out)) {
      db.insertAttempt({
        target: r.target, protocol: r.proto.toLowerCase(),
        username: r.user, password: r.pass, outcome: r.outcome,
        privilege: r.privilege, raw_line: r.raw,
      }, now, runId);
      attempts++;
      if (r.outcome === 'success') {
        successes++;
        if (r.privilege) {
          db.insertSession({ target: r.target, protocol: r.proto.toLowerCase(), username: r.user, privilege: r.privilege, notes: r.raw }, now, runId);
        }
      }
    }
    db.finishRun(runId, new Date().toISOString(), `${attempts} attempts · ${successes} success`);
    db.close();
    console.error(`sqlite: ${path.resolve(opts.sqlite!)} — ${attempts} attempts, ${successes} success (run #${runId})`);
  }
}

main().catch((err: unknown) => { console.error('FATAL:', err instanceof Error ? err.message : String(err)); process.exit(1); });
