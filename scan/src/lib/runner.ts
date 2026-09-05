import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { parseScope, checkTargets, type Scope } from './scope.js';
import { parseTargets } from './targets.js';

export interface RunToolOpts {
  targetsFile: string;
  scopeFile: string | null;
  outFile: string | null;
  strict: boolean;
}

export interface Prepared {
  targets: string[];
  outOfScope: string[];
  scope: Scope;
}

export function prepareTargets(opts: RunToolOpts): Prepared {
  const text = fs.readFileSync(opts.targetsFile, 'utf8');
  const raw = parseTargets(text);
  const scope = opts.scopeFile
    ? parseScope(fs.readFileSync(opts.scopeFile, 'utf8'))
    : parseScope('');
  const { inScope, outOfScope } = checkTargets(raw, scope);
  if (outOfScope.length) {
    const banner = opts.strict ? 'REFUSING' : 'WARNING';
    console.error(`[${banner}] ${outOfScope.length} out-of-scope target(s):`);
    for (const t of outOfScope.slice(0, 20)) console.error(`  - ${t}`);
    if (outOfScope.length > 20) console.error(`  ... +${outOfScope.length - 20} more`);
    if (opts.strict) process.exit(2);
  }
  return { targets: inScope, outOfScope, scope };
}

export interface SpawnResult {
  code: number;
  stdout: string;
  stderr: string;
}

export async function run(cmd: string, args: string[], opts: { timeoutMs?: number; stdin?: string } = {}): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.on('error', (err) => reject(err));
    child.on('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
    if (opts.timeoutMs) {
      setTimeout(() => { child.kill('SIGKILL'); }, opts.timeoutMs).unref();
    }
    if (opts.stdin !== undefined) {
      child.stdin.end(opts.stdin);
    } else {
      child.stdin.end();
    }
  });
}

/**
 * Ensure at least one of the candidate binaries is on PATH. Returns the resolved
 * command name that succeeded — call it back with `run(cmd, ...)`.
 */
export async function requireTool(...cmdCandidates: string[]): Promise<string> {
  for (const cmd of cmdCandidates) {
    const r = await run('which', [cmd]);
    if (r.code === 0) return cmd;
  }
  console.error(
    `FATAL: none of [${cmdCandidates.join(', ')}] found on PATH. ` +
    `Install first (see install-tools.sh in the skill).`
  );
  process.exit(3);
}

export function writeLines(file: string, lines: readonly string[]): void {
  fs.writeFileSync(file, lines.join('\n') + '\n');
}

export interface CommonCliOpts extends RunToolOpts {
  extraArgs: string[];
  sqlite: string | null;
  runDir: string | null;
  noRunDir: boolean;
  help?: boolean;
}

/**
 * Resolve where a wrapper should write a given output file.
 *
 * - Explicit `--out` (opts.outFile) always wins.
 * - Otherwise, when a `runId` is available and per-run dirs are enabled
 *   (default `runs/`, disabled with --no-run-dir), the file lands at
 *   `runs/<runId>/<defaultName>` — nothing overwritten between runs.
 * - Otherwise, falls back to cwd `defaultName`.
 *
 * Creates the target directory if it doesn't exist.
 */
export function resolveOutputPath(
  opts: CommonCliOpts,
  runId: number | null,
  defaultName: string
): string {
  if (opts.outFile) {
    const dir = path.dirname(path.resolve(opts.outFile));
    fs.mkdirSync(dir, { recursive: true });
    return path.resolve(opts.outFile);
  }
  if (runId !== null && !opts.noRunDir) {
    const base = path.resolve(opts.runDir ?? 'runs');
    const dir = path.join(base, String(runId));
    fs.mkdirSync(dir, { recursive: true });
    return path.join(dir, defaultName);
  }
  return path.resolve(defaultName);
}

export function parseCommonCli(argv: string[]): CommonCliOpts {
  const opts: CommonCliOpts = {
    targetsFile: '',
    scopeFile: null,
    outFile: null,
    strict: false,
    extraArgs: [],
    sqlite: null,
    runDir: null,
    noRunDir: false,
  };
  const rest: string[] = [];
  let passthrough = false;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (passthrough) { opts.extraArgs.push(a); continue; }
    const next = () => argv[++i]!;
    if (a === '--') passthrough = true;
    else if (a === '--targets') opts.targetsFile = next();
    else if (a === '--scope') opts.scopeFile = next();
    else if (a === '-o' || a === '--out') opts.outFile = next();
    else if (a === '--strict') opts.strict = true;
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '--run-dir') opts.runDir = next();
    else if (a === '--no-run-dir') opts.noRunDir = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  if (!opts.targetsFile && rest[0]) opts.targetsFile = rest[0];
  return opts;
}

export function commonUsage(tool: string, extras = ''): string {
  return `Usage: ${tool} --targets <file> [--scope scope.txt] [-o out] [--strict] [-- <tool-specific args>]

  --targets <file>   File with one hostname/IP per line
  --scope <file>     Optional scope file (suffixes + CIDRs). WARNING-only unless --strict.
  --strict           Refuse to run when any target is out of scope (exit 2)
  --sqlite <path>    Also persist findings/ports/probes to this SQLite DB
  --run-dir <path>   Base dir for per-run outputs (default: runs/)
                     When --sqlite is set + no --out, outputs land in
                     <run-dir>/<run_id>/<tool>.<ext> so nothing is overwritten
  --no-run-dir       Disable per-run dir; use cwd tool defaults (legacy)
  -o, --out <file>   Explicit output path (always wins over --run-dir)
  --                 Everything after is passed verbatim to ${tool}
${extras}`;
}
