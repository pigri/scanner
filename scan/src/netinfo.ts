#!/usr/bin/env -S node --loader tsx
// netinfo: derive per-target network info (IP, version, class, ASN, country)
// from ports, dns_records and http_probes evidence into target_network. Local reads and one
// MMDB file: no network I/O except PTR lookups with --ptr. A missing MMDB still
// writes the IP rows.
import fs from 'node:fs';
import { parseCommonCli, commonUsage, prepareTargets } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';
import { openGeo, DEFAULT_MMDB, MMDB_STALE_DAYS } from './lib/geoip.js';
import { runNetinfo, runNetinfoPtr } from './lib/netinfo.js';

const DEFAULT_PTR_BUDGET_SEC = 60;

function usage(): void {
  console.error(commonUsage('netinfo', `
Writes one target_network row per (target, IP) found in ports / dns_records / http_probes.

  --all             derive rows for every scan_queue target (backfill; ignores --targets)
  --mmdb <path>     ip database (default: $GEOIP_MMDB, else ${DEFAULT_MMDB})
                    a missing or unreadable file is a warning: rows are written without geo
  --ptr             also resolve PTR names of public IPs (c-ares, the process's resolv.conf)
  --no-ptr          turn it off (default); the later of --ptr / --no-ptr wins
  --ptr-budget-sec <n>  stop starting PTR lookups after n seconds (default: ${DEFAULT_PTR_BUDGET_SEC})
  --targets, --scope, --strict, --sqlite: as for the other wrappers`));
}

/** Pull this tool's own flags out of argv, before or after `--`, so parseCommonCli does not mistake their values for targets. */
export function splitOwnFlags(argv: string[], env: NodeJS.ProcessEnv = process.env): { rest: string[]; all: boolean; mmdb: string; ptr: boolean; ptrBudgetSec: number } {
  const rest = argv.slice(0, 2);
  let all = false, mmdb = env.GEOIP_MMDB || DEFAULT_MMDB, ptr = false, ptrBudgetSec = DEFAULT_PTR_BUDGET_SEC;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--all') all = true;
    else if (a === '--mmdb') mmdb = argv[++i] ?? '';
    else if (a === '--ptr') ptr = true;
    else if (a === '--no-ptr') ptr = false;
    else if (a === '--ptr-budget-sec') {
      const v = argv[++i] ?? '';
      ptrBudgetSec = v.trim() !== '' && Number.isFinite(Number(v)) && Number(v) >= 0 ? Number(v) : NaN;
    }
    else rest.push(a);
  }
  return { rest, all, mmdb, ptr, ptrBudgetSec };
}

export function mmdbAgeWarning(buildAt: string | null, now: Date): string | null {
  if (!buildAt) return 'mmdb build time unknown; geo data may be stale';
  const ageDays = (now.getTime() - Date.parse(buildAt)) / 86_400_000;
  if (ageDays > MMDB_STALE_DAYS) return `mmdb build ${buildAt} is older than ${MMDB_STALE_DAYS} days`;
  return null;
}

/** Starts the run row. The first write on this connection, so it needs the long busy timeout. */
export function startNetinfoRun(db: Db, args: Parameters<Db['startRun']>[1], now: string): number {
  // Scan workers hold write locks for whole batches; openDb's 5s would lose that race.
  db.raw.pragma('busy_timeout = 60000');
  return db.startRun('netinfo', args, now);
}

async function main(): Promise<void> {
  const own = splitOwnFlags(process.argv);
  const opts = parseCommonCli(own.rest);
  if (opts.help) { usage(); process.exit(0); }
  if ((!own.all && !opts.targetsFile) || !own.mmdb || Number.isNaN(own.ptrBudgetSec)) { usage(); process.exit(2); }

  let targets: string[] | 'all' = 'all';
  if (!own.all) {
    if (!fs.existsSync(opts.targetsFile)) { console.error(`FATAL: targets file not found: ${opts.targetsFile}`); process.exit(2); }
    targets = prepareTargets(opts).targets;
  }

  let geoErr: unknown;
  const geo = await openGeo(own.mmdb, (e) => { geoErr = e; });
  if (!geo) console.error(`WARNING: cannot read mmdb ${own.mmdb} (${geoErr instanceof Error ? geoErr.message : String(geoErr)}); writing IP rows without geo`);
  else {
    const warn = mmdbAgeWarning(geo.buildAt, new Date());
    if (warn) console.error(`WARNING: ${warn}`);
  }

  const db = openDb(opts.sqlite ?? 'scan.db');
  try {
    const now = new Date().toISOString();
    const runId = startNetinfoRun(db, { mode: own.all ? 'all' : 'targets', mmdb: own.mmdb, geo: geo !== null, ptr: own.ptr }, now);
    const base = { db, targets, geo };
    const r = own.ptr
      ? await runNetinfoPtr({ ...base, ptr: { budgetMs: own.ptrBudgetSec * 1000 } })
      : runNetinfo(base);
    const p = r.ptr;
    db.finishRun(runId, {
      targetsCount: r.targets,
      findingsCount: r.rowsWritten,
      notes: `skipped_invalid=${r.skippedInvalid} geo_hits=${r.geoHits} geo_misses=${r.geoMisses}${own.ptr ? ` ptr_looked_up=${p.looked_up} ptr_found=${p.found} ptr_empty=${p.empty} ptr_failed=${p.failed} ptr_skipped_budget=${p.skipped_budget}` : ''}`,
      at: new Date().toISOString(),
    });
    console.error(`netinfo: ${r.targets} targets, ${r.rowsWritten} rows, ${r.skippedInvalid} invalid ips skipped, geo ${r.geoHits} hit / ${r.geoMisses} miss (run #${runId})`);
    console.error(own.ptr
      ? `netinfo: ptr: ${p.looked_up} looked up, ${p.found} found, ${p.empty} empty, ${p.failed} failed, ${p.skipped_budget} skipped by budget`
      : 'netinfo: ptr: off');
  } finally {
    db.close();
  }
}

// Only run when invoked directly, so tests can import mmdbAgeWarning.
if (process.argv[1] && process.argv[1].endsWith('netinfo.ts')) {
  main().catch((err: unknown) => {
    console.error('FATAL:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
