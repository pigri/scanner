#!/usr/bin/env -S node --loader tsx
// Pattern-expansion stage: mine the naming grammar of the corpus, permute it
// into candidate hostnames, validate by DNS then a per-zone CT oracle, and
// merge the corroborated ones. Runs host-side. Always exits 0: a quota wall or
// a network error degrades the result, it does not fail the stage.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { pool } from './lib/pool.js';
import { zoneOf } from './lib/hostname.js';
import { minePatterns } from './lib/patterns.js';
import { permute } from './lib/permute.js';
import { makeDomainFilter } from './lib/ddg.js';
import { wildcardProbeHosts, classifyWildcard } from './lib/wildcard.js';
import { classify, converged, type Tier } from './lib/expand-core.js';
import { loadKey, fetchSubdomains, usage } from './lib/ctlogs.js';
import { queryAll, type FetchImpl } from './lib/ct-fetch.js';
import { resolveHost, ResolverPool, DEFAULT_RESOLVERS } from './lib/resolve.js';

export interface ExpandOpts {
  domains: string;
  sidecar: string;
  dryRun: boolean;
  mergeTierC: boolean;
  /** Max candidates generated per zone. */
  perZone: number;
  /** Max candidates validated (DNS lookups) per run, across all zones. */
  maxCandidates: number;
  /** Max ctlogs.dev HTTP requests per run, across all zones. */
  ctBudget: number;
  concurrency: number;
  suffix: string | null;
  exclude: string[];
  timeoutMs: number;
}

export interface ExpandDeps {
  /** A/AAAA answers for a host; empty when it does not resolve. Must not throw. */
  resolveIps(host: string): Promise<string[]>;
  /** ctlogs.dev API key; throws when none is configured. */
  loadKey(): string;
  fetchImpl?: FetchImpl | undefined;
  /** Free CT fallback (crt.sh/certspotter): hosts known for a zone. */
  ctFallback(zone: string): Promise<string[]>;
  sleep?: ((ms: number) => Promise<void>) | undefined;
  log(s: string): void;
}

export interface ExpandResult {
  zones: Record<string, number>;
  candidates: number;
  ctRequests: number;
  tiers: Record<Tier, number>;
  converged: boolean;
}

function readLines(p: string): string[] {
  try {
    return fs.readFileSync(p, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function mergeInto(file: string, add: Iterable<string>): void {
  const merged = new Set([...readLines(file), ...add]);
  fs.writeFileSync(path.resolve(file), [...merged].sort().join('\n') + '\n');
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export async function runExpand(opts: ExpandOpts, deps: ExpandDeps): Promise<ExpandResult> {
  const { log } = deps;
  // SEED
  const names = [...new Set(readLines(opts.domains).map((s) => s.toLowerCase()))];
  const known = new Set(names);
  const corpusZones = new Set(names.map(zoneOf));

  // MINE + PERMUTE
  const keep = makeDomainFilter(opts.suffix, opts.exclude);
  const candidates = permute(minePatterns(names), known, { perZone: opts.perZone })
    .filter((c) => corpusZones.has(zoneOf(c)) && keep(c) === c)
    .slice(0, opts.maxCandidates);
  const byZone = new Map<string, string[]>();
  for (const c of candidates) {
    const z = zoneOf(c);
    byZone.set(z, [...(byZone.get(z) ?? []), c]);
  }
  const result: ExpandResult = {
    zones: Object.fromEntries([...byZone].map(([z, cs]) => [z, cs.length])),
    candidates: candidates.length,
    ctRequests: 0,
    tiers: { A: 0, B: 0, C: 0, D: 0 },
    converged: true,
  };

  if (opts.dryRun) {
    // Preview only: no DNS, no CT, no writes, so no quota is spent.
    for (const [z, n] of Object.entries(result.zones)) log(`  ${z}: ${n} candidates`);
    log(`dry-run: projected CT requests: ${Math.min(opts.ctBudget, byZone.size)} (budget ${opts.ctBudget}); no network calls made, nothing written`);
    return result;
  }

  // VALIDATE: DNS
  const ips = new Map<string, string[]>();
  await pool(candidates, opts.concurrency, async (c) => {
    ips.set(c, await deps.resolveIps(c));
  });

  // VALIDATE: per-zone wildcard and CT oracle
  let key: string | null = null;
  try {
    key = deps.loadKey();
  } catch {
    log('warning: no ctlogs key; using the crt.sh/certspotter fallback only');
  }
  if (key !== null) {
    try {
      const u = await usage({ key, fetchImpl: deps.fetchImpl, timeoutMs: opts.timeoutMs, maxRetries: 0, sleep: deps.sleep });
      log(`ctlogs usage: ${JSON.stringify(u.figures)}`);
    } catch (e) {
      log(`ctlogs usage unavailable: ${msg(e)}`);
    }
  }

  let budget = opts.ctBudget;
  const tierOf = new Map<string, Tier>();
  for (const [zone, cands] of byZone) {
    let wildIps = new Set<string>();
    try {
      const answers = await Promise.all(wildcardProbeHosts(zone).map((h) => deps.resolveIps(h)));
      const verdict = classifyWildcard(zone, answers);
      if (verdict.wildcard) wildIps = new Set(verdict.ips);
    } catch (e) {
      log(`  ${zone}: wildcard probe failed: ${msg(e)}`);
    }

    let ctHosts: Set<string> | null = null;
    if (key !== null) {
      try {
        const r = await fetchSubdomains(zone, {
          key, budget, fetchImpl: deps.fetchImpl, timeoutMs: opts.timeoutMs, sleep: deps.sleep,
        });
        budget -= r.requests;
        result.ctRequests += r.requests;
        if (r.ok) ctHosts = new Set(r.hosts.map((h) => h.toLowerCase()));
        else log(`  ${zone}: ctlogs ${r.reason}; degrading to fallback`);
      } catch (e) {
        log(`  ${zone}: ctlogs error: ${msg(e)}; degrading to fallback`);
      }
    }
    if (ctHosts === null) {
      try {
        ctHosts = new Set((await deps.ctFallback(zone)).map((h) => h.toLowerCase()));
      } catch (e) {
        log(`  ${zone}: fallback CT failed: ${msg(e)}; DNS-only`);
        ctHosts = new Set();
      }
    }

    for (const c of cands) {
      const answers = ips.get(c) ?? [];
      tierOf.set(c, classify({
        resolves: answers.length > 0,
        ctCorroborated: ctHosts.has(c),
        wildcardHit: wildIps.size > 0 && answers.every((a) => wildIps.has(a)),
      }));
    }
  }

  // CLASSIFY + MERGE
  const toDomains: string[] = [];
  const toSidecar: string[] = [];
  for (const [c, t] of tierOf) {
    result.tiers[t]++;
    if (t === 'A' || t === 'B') toDomains.push(c);
    else if (t === 'C') (opts.mergeTierC ? toDomains : toSidecar).push(c);
  }
  result.converged = converged({ admitted: toDomains.length });

  for (const [z, n] of Object.entries(result.zones)) log(`  ${z}: ${n} candidates`);
  log(`CT requests spent: ${result.ctRequests}/${opts.ctBudget}`);
  log(`tiers: A=${result.tiers.A} B=${result.tiers.B} C=${result.tiers.C} D=${result.tiers.D}`);
  if (toDomains.length) mergeInto(opts.domains, toDomains);
  if (toSidecar.length) mergeInto(opts.sidecar, toSidecar);
  log(`merged ${toDomains.length} into ${opts.domains}, ${toSidecar.length} into ${opts.sidecar}`);
  return result;
}

interface CliOpts extends ExpandOpts {
  help: boolean;
}

function parseArgs(argv: string[]): CliOpts {
  const opts: CliOpts = {
    domains: 'domains.txt',
    sidecar: 'expand-tier-c.txt',
    dryRun: false,
    mergeTierC: false,
    perZone: 50,
    maxCandidates: 5000,
    ctBudget: 50,
    concurrency: 20,
    suffix: null,
    exclude: [],
    timeoutMs: 30000,
    help: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    const int = (def: number) => {
      const n = parseInt(next(), 10);
      return Number.isFinite(n) && n >= 0 ? n : def;
    };
    if (a === '--domains') opts.domains = next();
    else if (a === '--sidecar') opts.sidecar = next();
    else if (a === '--dry-run') opts.dryRun = true;
    else if (a === '--merge-tier-c') opts.mergeTierC = true;
    else if (a === '--per-zone') opts.perZone = int(opts.perZone);
    else if (a === '--max-candidates') opts.maxCandidates = int(opts.maxCandidates);
    else if (a === '--ct-budget') opts.ctBudget = int(opts.ctBudget);
    else if (a === '--concurrency') opts.concurrency = Math.max(1, int(opts.concurrency));
    else if (a === '--suffix') opts.suffix = next().toLowerCase().replace(/^\./, '');
    else if (a === '--exclude') opts.exclude = next().split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    else if (a === '--timeout-ms') opts.timeoutMs = int(opts.timeoutMs);
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usageText(): void {
  console.error(`Usage: expand [options]

Mine naming patterns from the domains file, permute candidate hostnames, and
validate them by DNS and a per-zone CT oracle. CT-corroborated names (tier A/B)
merge into the domains file; resolving-only names (tier C) go to a sidecar.
Always exits 0.

Options:
  --domains <path>       Domains file to read and merge into (default: domains.txt)
  --sidecar <path>       Tier-C sidecar file (default: expand-tier-c.txt)
  --merge-tier-c         Also merge tier C into the domains file
  --dry-run              Print what would change; write nothing
  --per-zone <n>         Max candidates per zone (default: 50)
  --max-candidates <n>   Max candidates validated per run (default: 5000)
  --ct-budget <n>        Max ctlogs.dev requests per run (default: 50)
  --concurrency <n>      Parallel DNS lookups (default: 20)
  --suffix <domain>      Only keep candidates under this suffix
  --exclude <a,b,c>      Skip these apex domains + their subdomains
  --timeout-ms <n>       Per-request timeout (default: 30000)`);
}

export async function main(argv: string[] = process.argv): Promise<void> {
  const opts = parseArgs(argv);
  if (opts.help) {
    usageText();
    return;
  }
  const log = (s: string) => console.error(s);
  try {
    const resolvers = new ResolverPool(DEFAULT_RESOLVERS);
    const resolveOpts = { ipv6: true, maxTries: 2, timeoutMs: opts.timeoutMs };
    const crtshEnabled = process.env.CT_CRTSH_DISABLED !== '1';
    const token = process.env.CERTSPOTTER_TOKEN || undefined;
    await runExpand(opts, {
      resolveIps: async (h) => {
        const r = await resolveHost(h, resolvers, resolveOpts);
        return [...r.a, ...r.aaaa];
      },
      loadKey: () => loadKey(),
      ctFallback: async (zone) =>
        queryAll(`%.${zone}`, 'both', {
          timeoutMs: opts.timeoutMs,
          crtshEnabled,
          token,
          certspotterMaxRetries: token ? undefined : 0,
          log,
        }),
      log,
    });
  } catch (e) {
    log(`expand: ${msg(e)} (non-fatal)`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e: unknown) => console.error('expand:', msg(e)));
}
