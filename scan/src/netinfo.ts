#!/usr/bin/env -S node --loader tsx
// netinfo: derive per-target network info (IP, version, class, ASN, country)
// from ports and dns_records evidence into target_network. Local reads and one
// MMDB file: no network I/O. A missing MMDB still writes the IP rows.
import fs from 'node:fs';
import { parseCommonCli, commonUsage, prepareTargets } from './lib/runner.js';
import { openDb } from './lib/db.js';
import { openGeo, DEFAULT_MMDB, MMDB_STALE_DAYS } from './lib/geoip.js';
import { runNetinfo } from './lib/netinfo.js';

function usage(): void {
  console.error(commonUsage('netinfo', `
Writes one target_network row per (target, IP) found in ports / dns_records.

  --all             derive rows for every scan_queue target (backfill; ignores --targets)
  --mmdb <path>     ip database (default: ${DEFAULT_MMDB})
                    a missing or unreadable file is a warning: rows are written without geo
  --targets, --scope, --strict, --sqlite: as for the other wrappers`));
}

/** Pull this tool's own flags out of argv, before or after `--`, so parseCommonCli does not mistake their values for targets. */
function splitOwnFlags(argv: string[]): { rest: string[]; all: boolean; mmdb: string } {
  const rest = argv.slice(0, 2);
  let all = false, mmdb = DEFAULT_MMDB;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--all') all = true;
    else if (a === '--mmdb') mmdb = argv[++i] ?? '';
    else rest.push(a);
  }
  return { rest, all, mmdb };
}

export function mmdbAgeWarning(buildAt: string | null, now: Date): string | null {
  if (!buildAt) return 'mmdb build time unknown; geo data may be stale';
  const ageDays = (now.getTime() - Date.parse(buildAt)) / 86_400_000;
  if (ageDays > MMDB_STALE_DAYS) return `mmdb build ${buildAt} is older than ${MMDB_STALE_DAYS} days`;
  return null;
}

async function main(): Promise<void> {
  const own = splitOwnFlags(process.argv);
  const opts = parseCommonCli(own.rest);
  if (opts.help) { usage(); process.exit(0); }
  if ((!own.all && !opts.targetsFile) || !own.mmdb) { usage(); process.exit(2); }

  let targets: string[] | 'all' = 'all';
  if (!own.all) {
    if (!fs.existsSync(opts.targetsFile)) { console.error(`FATAL: targets file not found: ${opts.targetsFile}`); process.exit(2); }
    targets = prepareTargets(opts).targets;
  }

  const geo = await openGeo(own.mmdb);
  if (!geo) console.error(`WARNING: cannot read mmdb ${own.mmdb}; writing IP rows without geo`);
  else {
    const warn = mmdbAgeWarning(geo.buildAt, new Date());
    if (warn) console.error(`WARNING: ${warn}`);
  }

  const db = openDb(opts.sqlite ?? 'scan.db');
  try {
    const now = new Date().toISOString();
    const runId = db.startRun('netinfo', { mode: own.all ? 'all' : 'targets', mmdb: own.mmdb, geo: geo !== null }, now);
    const r = runNetinfo({ db, targets, geo });
    db.finishRun(runId, {
      targetsCount: r.targets,
      findingsCount: r.rowsWritten,
      notes: `skipped_invalid=${r.skippedInvalid} geo_hits=${r.geoHits} geo_misses=${r.geoMisses}`,
      at: new Date().toISOString(),
    });
    console.error(`netinfo: ${r.targets} targets, ${r.rowsWritten} rows, ${r.skippedInvalid} invalid ips skipped, geo ${r.geoHits} hit / ${r.geoMisses} miss (run #${runId})`);
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
