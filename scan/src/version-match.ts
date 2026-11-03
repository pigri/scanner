#!/usr/bin/env -S node --loader tsx
// version-match: compare software versions seen in http_probes / ports with the
// offline NVD mirror (nvd.db) and emit one `cve` finding per matching CVE.
//
// Exit-code invariant: non-zero only for true fatals (scan.db can't be opened,
// bad arguments). A missing, unreadable, wrong-schema or stale nvd.db degrades
// to a warning plus a note on the run row, and the exit stays 0.
import fs from 'node:fs';
import { openDb, type Db } from './lib/db.js';
import { parseCommonCli, prepareTargets } from './lib/runner.js';
import { openNvdLookup, type VulnLookup } from './lib/nvd-db.js';
import { isSqliteBusy } from './cve-enrich.js';
import { resolveAlias } from './lib/cpe-aliases.js';
import {
  parseServerHeader, parseTechToken, evidenceFromPort, matchCves, severityForCvss,
  type Evidence, type CveMatch,
} from './lib/version-match.js';

export const DEFAULT_NVD_DB = '/storage/gen0sec-scan/nvd.db';
const DAY_MS = 24 * 3600 * 1000;

export interface VersionMatchOpts {
  db: Db;
  targets: string[];
  nvdDb: string;
  maxAgeDays: number;
  dryRun: boolean;
  now?: Date;
  /** Injected lookup, used instead of opening `nvdDb` (tests). */
  lookup?: VulnLookup | null;
  log?: (msg: string) => void;
}

export interface VersionMatchResult {
  exitCode: number;
  matched: number;
  inserted: number;
  skippedVersions: number;
  busySkipped: number;
  failedTargets: number;
}

interface Seen { evidence: Evidence; matchedAt: string; text: string }

function httpEvidence(db: Db, target: string): Seen[] {
  const rows = db.raw.prepare(
    `SELECT url, web_server, tech_json FROM (
       SELECT url, web_server, tech_json,
              ROW_NUMBER() OVER (PARTITION BY url ORDER BY seen_at DESC, id DESC) AS rn
         FROM http_probes WHERE target = ?)
      WHERE rn = 1 ORDER BY url`,
  ).all(target) as { url: string; web_server: string | null; tech_json: string | null }[];
  const out: Seen[] = [];
  for (const r of rows) {
    const fromHeader = r.web_server ? parseServerHeader(r.web_server) : [];
    const distro = fromHeader.find((e) => e.distro)?.distro ?? null;
    for (const e of fromHeader) out.push({ evidence: e, matchedAt: r.url, text: `${e.name}/${e.raw}` });
    let tech: unknown = [];
    try { tech = r.tech_json ? JSON.parse(r.tech_json) : []; } catch { /* malformed tech_json: header evidence still counts */ }
    for (const t of Array.isArray(tech) ? tech : []) {
      const e = typeof t === 'string' ? parseTechToken(t) : null;
      if (e) out.push({ evidence: { ...e, distro: e.distro ?? distro }, matchedAt: r.url, text: `${e.name}:${e.raw}` });
    }
  }
  return out;
}

function portEvidence(db: Db, target: string): Seen[] {
  const rows = db.raw.prepare(
    `SELECT port, product, version, extrainfo FROM (
       SELECT port, product, version, extrainfo,
              ROW_NUMBER() OVER (PARTITION BY port, protocol ORDER BY seen_at DESC, id DESC) AS rn
         FROM ports WHERE target = ?)
      WHERE rn = 1 ORDER BY port`,
  ).all(target) as { port: number; product: string | null; version: string | null; extrainfo: string | null }[];
  const out: Seen[] = [];
  for (const r of rows) {
    const e = evidenceFromPort(r.product, r.version, r.extrainfo);
    if (e) out.push({ evidence: e, matchedAt: `${target}:${r.port}`, text: `${e.name} ${e.raw}` });
  }
  return out;
}

/** One evidence per (vendor, product, version); a distro hint on any duplicate wins. */
function dedupe(seen: Seen[]): Seen[] {
  const byKey = new Map<string, Seen>();
  for (const s of seen) {
    const alias = resolveAlias(s.evidence.name);
    if (!alias) continue;
    const [vendor, product] = alias.pairs[0]!;
    const key = `${vendor}:${product}:${s.evidence.version}`;
    const prev = byKey.get(key);
    if (!prev) byKey.set(key, s);
    else if (!prev.evidence.distro && s.evidence.distro) prev.evidence = { ...prev.evidence, distro: s.evidence.distro };
  }
  return [...byKey.values()];
}

export async function runVersionMatch(opts: VersionMatchOpts): Promise<VersionMatchResult> {
  const log = opts.log ?? ((m: string) => console.error(m));
  const now = opts.now ?? new Date();
  const at = now.toISOString();
  const result: VersionMatchResult = { exitCode: 0, matched: 0, inserted: 0, skippedVersions: 0, busySkipped: 0, failedTargets: 0 };
  const { db } = opts;

  const runId = opts.dryRun ? null : db.startRun('version-match', { nvdDb: opts.nvdDb, maxAgeDays: opts.maxAgeDays }, at);
  const finish = (notes: string | undefined): void => {
    if (runId === null) return;
    db.finishRun(runId, { targetsCount: opts.targets.length, findingsCount: result.inserted, ...(notes !== undefined ? { notes } : {}), at: new Date().toISOString() });
  };

  const lookup = opts.lookup !== undefined ? opts.lookup : openNvdLookup(opts.nvdDb);
  if (!lookup) {
    const note = `nvd.db unavailable (${opts.nvdDb}): missing, unreadable or wrong schema; no version-match findings`;
    log(`WARN: ${note}`);
    finish(note);
    return result;
  }

  const notes: string[] = [];
  const snap = lookup.snapshotAt ? Date.parse(lookup.snapshotAt) : NaN;
  const stale = !Number.isFinite(snap) || now.getTime() - snap > opts.maxAgeDays * DAY_MS;
  if (stale) {
    const note = `nvd.db snapshot ${lookup.snapshotAt ?? 'unknown'} is older than ${opts.maxAgeDays} days`;
    log(`WARN: ${note}`);
    notes.push(note);
  }

  for (const target of opts.targets) {
    try {
      const evidence = dedupe([...httpEvidence(db, target), ...portEvidence(db, target)]);
      for (const s of evidence) {
        const { matches, skipped } = matchCves([s.evidence], lookup);
        result.skippedVersions += skipped;
        for (const m of matches) {
          result.matched++;
          if (opts.dryRun) {
            log(`${target}  ${m.cve}  cvss ${m.cvss}  ${m.display} ${m.evidence.version}  [${m.rule}] ${m.confidence}  ${s.matchedAt}`);
            continue;
          }
          if (insert(db, target, m, s, lookup.snapshotAt, stale, at, runId)) result.inserted++;
          else result.busySkipped++;
        }
      }
    } catch (e) {
      result.failedTargets++;
      log(`WARN: version-match failed for ${target}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  if (result.skippedVersions) notes.push(`${result.skippedVersions} evidence version(s) skipped (fewer than 2 numeric segments)`);
  if (result.busySkipped) notes.push(`${result.busySkipped} finding(s) skipped: scan.db busy`);
  if (result.failedTargets) notes.push(`${result.failedTargets} target(s) failed`);
  finish(notes.length ? notes.join('; ') : undefined);
  log(`version-match: ${result.matched} match(es), ${result.inserted} inserted, ${result.skippedVersions} skipped version(s), ${result.busySkipped} busy, ${result.failedTargets} failed target(s)${opts.dryRun ? ' (dry run)' : ''}`);
  return result;
}

/** Insert one finding. False when scan.db stayed locked past busy_timeout; other errors throw. */
function insert(
  db: Db, target: string, m: CveMatch, s: Seen,
  snapshotAt: string | null, stale: boolean, at: string, runId: number | null,
): boolean {
  try {
    db.insertFinding({
      tool: 'version-match',
      target,
      category: 'cve',
      severity: severityForCvss(m.cvss),
      title: `${m.cve} on ${m.display} ${m.evidence.version} (version match)`,
      cve: m.cve,
      matched_at: s.matchedAt,
      meta: {
        cvss: m.cvss,
        cvss_version: m.cvssVersion,
        confidence: m.confidence,
        evidence: s.text,
        cpe: m.cpe,
        matched_rule: m.rule,
        nvd_snapshot_at: snapshotAt,
        ...(stale ? { nvd_stale: true } : {}),
      },
      // needsReview until PR5 adds the version-match scoring tier
      needsReview: true,
    }, at, runId);
    return true;
  } catch (e) {
    if (isSqliteBusy(e)) return false;
    throw e;
  }
}

function usage(): void {
  console.error(`Usage: version-match --targets <file> --sqlite <scan.db> [--nvd-db <path>] [--max-age-days N] [--dry-run]

Matches versions in http_probes / ports against nvd.db and writes tool=version-match CVE findings.

  --nvd-db <path>       default: ${DEFAULT_NVD_DB}
  --max-age-days <N>    warn and mark findings nvd_stale when nvd.db is older (default: 14)
  --dry-run             print matches, write nothing
  --targets, --scope, --strict, --sqlite: as for the other wrappers`);
}

/** Pull this tool's own flags out of argv so parseCommonCli does not mistake their values for targets. */
function splitOwnFlags(argv: string[]): { rest: string[]; nvdDb: string; maxAgeDays: number; dryRun: boolean } {
  const rest = argv.slice(0, 2);
  let nvdDb = DEFAULT_NVD_DB, maxAgeDays = 14, dryRun = false;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--nvd-db') nvdDb = argv[++i] ?? '';
    else if (a === '--max-age-days') maxAgeDays = Number(argv[++i]);
    else if (a === '--dry-run') dryRun = true;
    else rest.push(a);
  }
  return { rest, nvdDb, maxAgeDays, dryRun };
}

async function main(): Promise<void> {
  const own = splitOwnFlags(process.argv);
  const opts = parseCommonCli(own.rest);
  if (opts.help) { usage(); process.exit(0); }
  if (!opts.targetsFile || !own.nvdDb || !Number.isFinite(own.maxAgeDays) || own.maxAgeDays < 0) { usage(); process.exit(2); }
  if (!fs.existsSync(opts.targetsFile)) { console.error(`FATAL: targets file not found: ${opts.targetsFile}`); process.exit(2); }
  const { targets } = prepareTargets(opts);
  const db = openDb(opts.sqlite ?? 'scan.db');
  try {
    const r = await runVersionMatch({ db, targets, nvdDb: own.nvdDb, maxAgeDays: own.maxAgeDays, dryRun: own.dryRun });
    process.exitCode = r.exitCode;
  } finally {
    db.close();
  }
}

// Only run when invoked directly, so tests can import runVersionMatch.
if (process.argv[1] && process.argv[1].endsWith('version-match.ts')) {
  main().catch((err: unknown) => {
    console.error('FATAL:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
