#!/usr/bin/env -S node --loader tsx
// Harvest in-scope SAN hostnames from the certificate inventory and feed them
// back into the discovery DB as new hosts (source='cert-san'). Certs routinely
// list sibling hostnames in their SANs — a cheap way to widen recon. Without
// --discovery-db it just prints the SANs (pipe them wherever you like).
import fs from 'node:fs';
import Database from 'better-sqlite3';
import { openDb } from './lib/db.js';
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';
import { harvestSans, type CertRecord } from './lib/testssl-cert.js';

interface Opts {
  db: string;
  discoveryDb: string | null;
  suffix: string;
  includeWildcards: boolean;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { db: resolveDbArg(argv), discoveryDb: null, suffix: 'gov.hu', includeWildcards: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (isDbFlag(a)) { i++; }
    else if (a === '--discovery-db') opts.discoveryDb = next();
    else if (a === '--suffix') opts.suffix = next();
    else if (a === '--include-wildcards') opts.includeWildcards = true;
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: export-cert-sans [--sqlite scan.db] [--discovery-db ../discovery/recon.db] [--suffix gov.hu]

Harvests SAN hostnames from the certificates table (matching --suffix, wildcards
skipped unless --include-wildcards). With --discovery-db, upserts them into the
discovery DB as hosts with source='cert-san'; otherwise prints them to stdout.`);
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  const db = openDb(opts.db);
  const rows = db.raw.prepare('SELECT common_name, san_json FROM certificates').all() as { common_name: string | null; san_json: string | null }[];
  const certs: CertRecord[] = rows.map((r) => ({
    certIndex: 1, port: null, commonName: r.common_name, san: r.san_json ? JSON.parse(r.san_json) as string[] : [],
    issuer: null, notBefore: null, notAfter: null, keyAlgo: null, keySize: null, sigAlgo: null, serial: null, fingerprintSha256: null, selfSigned: false,
  }));
  db.close();

  const sans = harvestSans(certs, opts.suffix, opts.includeWildcards);
  console.error(`harvested ${sans.length} in-scope SAN hostname(s) from ${rows.length} cert(s)`);

  if (!opts.discoveryDb) {
    for (const s of sans) process.stdout.write(s + '\n');
    return;
  }
  if (!fs.existsSync(opts.discoveryDb)) { console.error(`discovery DB not found: ${opts.discoveryDb}`); process.exit(1); }

  // Minimal upsert matching the discovery schema (hosts + sources).
  const rec = new Database(opts.discoveryDb);
  rec.pragma('busy_timeout = 5000');
  const now = new Date().toISOString();
  const insHost = rec.prepare('INSERT INTO hosts(name, first_seen, last_seen) VALUES(?, ?, ?) ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen RETURNING id');
  const insSrc = rec.prepare('INSERT INTO sources(host_id, source, seen_at) VALUES(?, ?, ?)');
  const existing = new Set((rec.prepare('SELECT name FROM hosts').all() as { name: string }[]).map((r) => r.name));
  let added = 0;
  const tx = rec.transaction(() => {
    for (const name of sans) {
      const wasNew = !existing.has(name);
      const id = (insHost.get(name, now, now) as { id: number }).id;
      insSrc.run(id, 'cert-san', now);
      if (wasNew) added++;
    }
  });
  tx();
  rec.close();
  console.error(`discovery DB: ${added} new host(s) added, ${sans.length - added} already known (source='cert-san')`);
}

main();
