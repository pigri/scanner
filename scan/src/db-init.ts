#!/usr/bin/env -S node --loader tsx
import path from 'node:path';
import { openDb } from './lib/db.js';

interface Opts { db: string; help?: boolean }

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { db: 'scan.db' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--db') opts.db = next();
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: db-init [--db scan.db]

Initialize the scan SQLite DB (creates the schema if missing).`);
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }
  const db = openDb(opts.db);
  db.close();
  console.error(`db ready: ${path.resolve(opts.db)}`);
}

main();
