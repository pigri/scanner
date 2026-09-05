#!/usr/bin/env -S node --loader tsx
import { openDb } from './lib/db.js';

interface Opts {
  db: string;
  cmd: 'new' | 'sources' | 'runs' | 'sql';
  since: string | null;
  until: string | null;
  sql: string;
  help?: boolean;
}

function normalizeDate(v: string, boundary: 'start' | 'end'): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) {
    return boundary === 'start' ? `${v}T00:00:00.000Z` : `${v}T23:59:59.999Z`;
  }
  return v;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    db: 'recon.db',
    cmd: 'new',
    since: null,
    until: null,
    sql: '',
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--db') opts.db = next();
    else if (a === '--since') opts.since = normalizeDate(next(), 'start');
    else if (a === '--until') opts.until = normalizeDate(next(), 'end');
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  if (rest[0] === 'new' || rest[0] === 'sources' || rest[0] === 'runs' || rest[0] === 'sql') {
    opts.cmd = rest[0];
    if (rest[0] === 'sql') opts.sql = rest.slice(1).join(' ');
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: query <cmd> [options]

Commands:
  new                 Hosts first_seen in the --since/--until window
  sources             Count of distinct hosts by source
  runs                Recent runs (last 20)
  sql "<query>"       Run arbitrary read-only SQL

Options:
  --db <path>         SQLite DB (default: recon.db)
  --since <iso>       ISO 8601 date, e.g. 2026-08-01 or 2026-08-01T00:00:00Z
  --until <iso>       ISO 8601 date

Examples:
  query new --since 2026-08-15
  query new --since 2026-08-01 --until 2026-08-15
  query sources
  query runs
  query sql "SELECT as_name, COUNT(*) FROM ips GROUP BY as_name ORDER BY 2 DESC LIMIT 10"
`);
}

function main(): void {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }
  const db = openDb(opts.db);

  if (opts.cmd === 'new') {
    const rows = db.hostsFirstSeenBetween(opts.since, opts.until);
    for (const r of rows) console.log(`${r.first_seen}\t${r.name}`);
    console.error(`\n${rows.length} host(s)`);
  } else if (opts.cmd === 'sources') {
    const rows = db.countBySource();
    for (const r of rows) console.log(`${String(r.n).padStart(6)}  ${r.source}`);
  } else if (opts.cmd === 'runs') {
    const rows = db.raw
      .prepare('SELECT id, tool, started_at, finished_at, added_hosts, added_ips FROM runs ORDER BY id DESC LIMIT 20')
      .all() as any[];
    for (const r of rows) {
      console.log(`#${r.id}  ${r.tool}  ${r.started_at} -> ${r.finished_at ?? '(running)'}  +${r.added_hosts}h/+${r.added_ips}ip`);
    }
  } else if (opts.cmd === 'sql') {
    if (!opts.sql) { console.error('sql command requires a query string'); process.exit(1); }
    try {
      const rows = db.raw.prepare(opts.sql).all();
      for (const row of rows) console.log(JSON.stringify(row));
      console.error(`\n${rows.length} row(s)`);
    } catch (e: unknown) {
      console.error('SQL error:', e instanceof Error ? e.message : String(e));
      process.exit(1);
    }
  }
  db.close();
}

main();
