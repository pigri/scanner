// Gate any attack-tool invocation on:
//  1. --scope <file> present   (strict by default; suffix + CIDR list)
//  2. --yes-i-am-authorized    (explicit confirmation flag)
//
// Refuses to run otherwise. Legal risk of attack-class tooling is materially
// different from recon — a false-positive nuclei probe is unlikely to draw a
// complaint; a NetExec spray or Responder poison against unauthorized infra
// is a felony in most jurisdictions.
//
// This module is split so tests can hit the refusal paths without spawning
// processes or exiting:
//   parseScope / inScope / classifyTargets / checkGate   → pure, testable
//   enforceGate                                          → I/O + process.exit
import fs from 'node:fs';

export interface Cidr { raw: string; family: 4 | 6; network: bigint; prefix: number }
export interface Scope { suffixes: string[]; cidrs: Cidr[] }

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function ipv4ToBigInt(a: string): bigint {
  const p = a.split('.').map((x) => BigInt(parseInt(x, 10)));
  return (p[0]! << 24n) | (p[1]! << 16n) | (p[2]! << 8n) | p[3]!;
}
function ipv6ToBigInt(a: string): bigint {
  const [h, t] = a.includes('::') ? a.split('::') : [a, ''];
  const hp = h ? h.split(':') : [];
  const tp = t ? t.split(':') : [];
  const fill = 8 - hp.length - tp.length;
  const g = [...hp, ...Array(Math.max(0, fill)).fill('0'), ...tp];
  let n = 0n;
  for (const x of g) n = (n << 16n) | BigInt(parseInt(x || '0', 16));
  return n;
}
function parseCidr(raw: string): Cidr | null {
  const [addr, mask] = raw.split('/');
  if (!addr || !mask) return null;
  const p = parseInt(mask, 10);
  if (isNaN(p)) return null;
  if (IPV4_RE.test(addr)) {
    const shift = BigInt(32 - p);
    return { raw, family: 4, network: (ipv4ToBigInt(addr) >> shift) << shift, prefix: p };
  }
  if (addr.includes(':') && IPV6_RE.test(addr)) {
    const shift = BigInt(128 - p);
    return { raw, family: 6, network: (ipv6ToBigInt(addr) >> shift) << shift, prefix: p };
  }
  return null;
}

export function parseScope(text: string): Scope {
  const suffixes: string[] = [];
  const cidrs: Cidr[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.includes('/')) { const c = parseCidr(line); if (c) cidrs.push(c); continue; }
    suffixes.push(line.toLowerCase().replace(/^\./, ''));
  }
  return { suffixes, cidrs };
}

export function inScope(target: string, s: Scope): boolean {
  const t = target.trim();
  const family: 4 | 6 | null = IPV4_RE.test(t) ? 4 : (t.includes(':') && IPV6_RE.test(t) ? 6 : null);
  if (family) {
    const ip = family === 4 ? ipv4ToBigInt(t) : ipv6ToBigInt(t);
    for (const c of s.cidrs) {
      if (c.family !== family) continue;
      const bits = family === 4 ? 32 : 128;
      const shift = BigInt(bits - c.prefix);
      if ((ip >> shift) << shift === c.network) return true;
    }
    return false;
  }
  const h = t.toLowerCase().replace(/^www\./, '');
  return s.suffixes.some((sfx) => h === sfx || h.endsWith(`.${sfx}`));
}

export interface Classified { inScope: string[]; outOfScope: string[] }

export function classifyTargets(targets: readonly string[], s: Scope): Classified {
  const inS: string[] = []; const out: string[] = [];
  for (const t of targets) (inScope(t, s) ? inS : out).push(t);
  return { inScope: inS, outOfScope: out };
}

export interface GateInput {
  scope: Scope;
  targets: readonly string[];
  authorized: boolean;
  scopeFileGiven: boolean;
}

export type GateResult =
  | { ok: true; targets: string[] }
  | { ok: false; reason: string };

/** Pure gate check — no I/O, no process.exit. Returns a Result. */
export function checkGate(input: GateInput): GateResult {
  if (!input.authorized) {
    return { ok: false, reason: 'not authorized: --yes-i-am-authorized was not passed' };
  }
  if (!input.scopeFileGiven) {
    return { ok: false, reason: 'no --scope <file> provided' };
  }
  if (input.scope.suffixes.length === 0 && input.scope.cidrs.length === 0) {
    return { ok: false, reason: 'scope is empty (only comments/blanks)' };
  }
  if (input.targets.length === 0) {
    return { ok: false, reason: 'no targets supplied' };
  }
  const classified = classifyTargets(input.targets, input.scope);
  if (classified.outOfScope.length) {
    const head = classified.outOfScope.slice(0, 5).join(', ');
    const rest = classified.outOfScope.length > 5 ? ` (+${classified.outOfScope.length - 5} more)` : '';
    return { ok: false, reason: `out-of-scope target(s): ${head}${rest}` };
  }
  return { ok: true, targets: classified.inScope };
}

export interface EnforceOpts {
  scopeFile: string | null;
  authorized: boolean;
  targets: string[];
}

/** I/O + process.exit wrapper around checkGate. Loads scope from disk. */
export function enforceGate(opts: EnforceOpts): string[] {
  const scopeFileGiven = !!opts.scopeFile;
  let scope: Scope = { suffixes: [], cidrs: [] };
  if (opts.scopeFile) {
    if (!fs.existsSync(opts.scopeFile)) {
      console.error(`REFUSED: scope file not found: ${opts.scopeFile}`);
      process.exit(4);
    }
    scope = parseScope(fs.readFileSync(opts.scopeFile, 'utf8'));
  }
  const r = checkGate({ scope, targets: opts.targets, authorized: opts.authorized, scopeFileGiven });
  if (!r.ok) {
    console.error(`REFUSED: ${r.reason}`);
    if (r.reason.startsWith('not authorized')) {
      console.error(`
Attack tools in this workspace can only run against infrastructure you have
written authorization to test. Passing --yes-i-am-authorized is your assertion
that you have that authorization for every target in --scope. Misuse against
unauthorized systems is a criminal offense under most jurisdictions'
computer-misuse statutes.`);
    }
    process.exit(4);
  }
  return r.targets;
}
