#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { openDb } from './lib/db.js';
import type { EnrichedRow } from './lib/graph.js';

interface Opts {
  db: string;
  fromJsonl: string | null;
  timestamp: string | null;
  source: string;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    db: 'recon.db',
    fromJsonl: null,
    timestamp: null,
    source: 'backfill',
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--db') opts.db = next();
    else if (a === '--from-jsonl') opts.fromJsonl = next();
    else if (a === '--timestamp') opts.timestamp = next();
    else if (a === '--source') opts.source = next();
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: db-init [options]

Initialize the recon SQLite DB (creates the schema if missing) and optionally
backfill historical data from an enriched.jsonl produced by earlier runs.

Options:
  --db <path>            Target SQLite file (default: recon.db)
  --from-jsonl <path>    Optional enriched.jsonl to backfill
  --timestamp <iso>      Use this ISO timestamp for backfilled rows
                         (default: now)
  --source <name>        Provenance tag for backfilled hosts (default: backfill)
`);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  const db = openDb(opts.db);
  console.error(`db opened: ${path.resolve(opts.db)}`);

  if (opts.fromJsonl) {
    if (!fs.existsSync(opts.fromJsonl)) {
      console.error(`FATAL: ${opts.fromJsonl} not found`);
      process.exit(1);
    }
    const ts = opts.timestamp ?? new Date().toISOString();
    const runId = db.startRun('db-init', { source: opts.source, jsonl: opts.fromJsonl }, ts);
    let hosts = 0, ips = 0, resolutions = 0, ptrs = 0;
    for (const line of fs.readFileSync(opts.fromJsonl, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      const row = JSON.parse(line) as EnrichedRow;
      if (!row.addresses.length) continue;
      const hostId = db.upsertHost(row.domain, opts.source, ts);
      hosts++;
      for (const a of row.addresses) {
        db.upsertIp(a.ip, {
          family: a.version,
          asn: a.asn, as_name: a.as_name, as_domain: a.as_domain,
          country_code: a.country_code, country: a.country, continent_code: a.continent_code,
        }, ts);
        ips++;
        db.addResolution(hostId, a.ip, a.version, ts);
        resolutions++;
        for (const p of a.ptr) { db.addPtr(a.ip, p, ts); ptrs++; }
      }
    }
    db.finishRun(runId, { addedHosts: hosts, addedIps: ips, notes: `resolutions=${resolutions}, ptrs=${ptrs}`, at: new Date().toISOString() });
    console.error(`backfilled: ${hosts} hosts, ${ips} ips, ${resolutions} resolutions, ${ptrs} ptrs @ ${ts}`);
  }
  db.close();
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
