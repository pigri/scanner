#!/usr/bin/env -S node --loader tsx
import Database from 'better-sqlite3';
import { computeScore, type TargetSignals } from './lib/risk.js';
import { loadRiskSignals } from './risk.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';

export interface DryRunOpts {
  discoveryDb: string | null;
  hostSuffix: string | null;
  bumps: number[];
  now: string;
  /** Names listed per delta bucket. */
  sample: number;
}

export interface Effect {
  /** Targets whose score changes. */
  changed: number;
  /** Targets that qualify (bump only): the ones that get the bump, even when the 100 cap eats it. */
  affected: number;
  /** Score delta -> number of targets, non-zero deltas only. */
  deltas: Record<number, number>;
  /** Targets that move to another 10-point step (the code defines no bands). */
  bandCrossings: number;
  /** Targets that were already at the cap. */
  capped: number;
  /** Score delta -> the first few target names, sorted. */
  samples: Record<number, string[]>;
}

export interface DryRunReport {
  targets: number;
  suffixSet: boolean;
  countrySource: Effect;
  bumps: (Effect & { bump: number })[];
}

const step = (score: number): number => Math.floor(score / 10);

function compare(
  names: readonly string[],
  before: Map<string, number>,
  after: Map<string, number>,
  qualifies: (t: string) => boolean,
  sample: number,
): Effect {
  const e: Effect = { changed: 0, affected: 0, deltas: {}, bandCrossings: 0, capped: 0, samples: {} };
  for (const t of [...names].sort()) {
    const b = before.get(t)!;
    const a = after.get(t)!;
    if (qualifies(t)) e.affected++;
    if (a === b) {
      if (qualifies(t) && b === 100) e.capped++;
      continue;
    }
    const d = a - b;
    e.changed++;
    e.deltas[d] = (e.deltas[d] ?? 0) + 1;
    if (step(a) !== step(b)) e.bandCrossings++;
    const l = (e.samples[d] ??= []);
    if (l.length < sample) l.push(t);
  }
  return e;
}

/** Score the db three ways with the real scoring code. Reads only: use a read-only handle. */
export function dryRun(raw: Database.Database, o: DryRunOpts): DryRunReport {
  const base = { discoveryDb: o.discoveryDb, hostSuffix: o.hostSuffix };
  const oldSig = loadRiskSignals(raw, { ...base, countrySource: 'discovery' }, o.now);
  const newSig = loadRiskSignals(raw, { ...base, countrySource: 'network' }, o.now);
  const scores = (m: Map<string, TargetSignals>, bump: number): Map<string, number> =>
    new Map([...m].map(([t, s]) => [t, computeScore(s, { networkChangedBump: bump }).score]));
  const names = [...newSig.keys()];
  const oldScores = scores(oldSig, 0);
  const newScores = scores(newSig, 0);
  const qualifies = (t: string): boolean => (newSig.get(t)?.networkChange?.count ?? 0) > 0;
  return {
    targets: names.length,
    suffixSet: o.hostSuffix !== null,
    countrySource: compare(names, oldScores, newScores, () => false, o.sample),
    bumps: o.bumps.map((bump) => ({
      bump,
      ...compare(names, newScores, scores(newSig, bump), qualifies, o.sample),
    })),
  };
}

const dist = (d: Record<number, number>): string => {
  const k = Object.keys(d).map(Number).sort((a, b) => a - b);
  return k.length ? k.map((x) => `${x > 0 ? '+' : ''}${x}: ${d[x]}`).join(', ') : 'none';
};

function effectLines(e: Effect): string[] {
  const out = [
    `  targets whose score changes: ${e.changed}`,
    `  delta distribution: ${dist(e.deltas)}`,
    `  10-point step crossings: ${e.bandCrossings}`,
  ];
  for (const k of Object.keys(e.samples).map(Number).sort((a, b) => a - b)) {
    out.push(`  sample ${k > 0 ? '+' : ''}${k}: ${e.samples[k]!.join(', ')}`);
  }
  return out;
}

export function formatReport(r: DryRunReport): string {
  const out = [`targets scored: ${r.targets}`, ''];
  out.push('(a) country source: current public IPs in target_network instead of the discovery db');
  if (!r.suffixSet) out.push('  no --suffix given: hostCountryCode only feeds the foreign +15, so no score can change');
  out.push(...effectLines(r.countrySource), '');
  for (const b of r.bumps) {
    out.push(`(b) networkChanged bump ${b.bump}: ${b.affected} targets qualify, ${b.capped} already at 100`);
    out.push(...effectLines(b), '');
  }
  out.push('The code defines no score bands; a crossing is a move to another 10-point step.');
  return out.join('\n');
}

const USAGE = 'Usage: risk-dry-run --sqlite <db> [--bumps 1,2,3,5] [--suffix gov.hu] [--discovery-db <db>] [--sample N]\n' +
  'Read-only. Prints to stdout only; the output names targets, so keep it out of the repo.';

/** Parses argv; throws an Error carrying the usage text on a bad value. -h is handled by main. */
export function parseDryRunArgs(argv: string[]): DryRunOpts & { db: string } {
  const bad = (why: string): Error => new Error(`${why}\n${USAGE}`);
  const o: DryRunOpts & { db: string } = {
    db: resolveDbArg(argv), discoveryDb: null, hostSuffix: null, bumps: [1, 2, 3, 5], now: new Date().toISOString(), sample: 5,
  };
  const value = (i: number, flag: string): string => {
    const v = argv[i];
    if (v === undefined || v === '') throw bad(`${flag} needs a value`);
    return v;
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (isDbFlag(a)) { i++; continue; }
    if (a === '--discovery-db') o.discoveryDb = value(++i, a);
    else if (a === '--suffix') o.hostSuffix = value(++i, a);
    else if (a === '--bumps') {
      const parts = value(++i, a).split(',');
      const nums = parts.map((p) => (p.trim() === '' ? NaN : Number(p)));
      if (nums.some((n) => !Number.isFinite(n))) throw bad('--bumps must be a comma-separated list of numbers');
      o.bumps = nums;
    } else if (a === '--sample') {
      const v = value(++i, a);
      if (!/^\d+$/.test(v)) throw bad('--sample must be a whole number');
      o.sample = Number(v);
    }
  }
  return o;
}

function main(): void {
  if (process.argv.includes('-h') || process.argv.includes('--help')) {
    console.error(USAGE);
    process.exit(0);
  }
  let o: DryRunOpts & { db: string };
  try {
    o = parseDryRunArgs(process.argv);
  } catch (e) {
    console.error((e as Error).message);
    process.exit(2);
  }
  const raw = new Database(o.db, { readonly: true, fileMustExist: true });
  raw.pragma('query_only = ON');
  console.log(formatReport(dryRun(raw, o)));
  raw.close();
}

if (process.argv[1] && process.argv[1].endsWith('risk-dry-run.ts')) main();
