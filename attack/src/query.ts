#!/usr/bin/env -S node --loader tsx
import { openDb } from './lib/db.js';

const cmd = process.argv[2] ?? '';
const dbPath = process.argv[3] ?? 'attack.db';
const db = openDb(dbPath);

if (cmd === 'attempts') {
  const rows = db.raw.prepare("SELECT seen_at, protocol, target, username, outcome, privilege FROM attempts ORDER BY id DESC LIMIT 50").all() as any[];
  for (const r of rows) console.log(`${r.seen_at}  ${r.outcome.padStart(7)}  ${r.protocol}  ${r.target}  ${r.username ?? ''}  ${r.privilege ?? ''}`);
} else if (cmd === 'credentials') {
  const rows = db.raw.prepare('SELECT seen_at, source, username, domain, hash_type FROM credentials ORDER BY id DESC LIMIT 50').all() as any[];
  for (const r of rows) console.log(`${r.seen_at}  ${r.source}  ${r.domain ?? ''}\\${r.username ?? ''}  ${r.hash_type ?? ''}`);
} else if (cmd === 'sessions') {
  const rows = db.raw.prepare('SELECT id, target, protocol, username, privilege, opened_at, closed_at FROM sessions ORDER BY id DESC LIMIT 50').all() as any[];
  for (const r of rows) console.log(`#${r.id}  ${r.target}  ${r.protocol}  ${r.username ?? ''}  ${r.privilege ?? ''}  ${r.opened_at} -> ${r.closed_at ?? '(open)'}`);
} else if (cmd === 'runs') {
  const rows = db.raw.prepare('SELECT id, tool, started_at, finished_at, scope_authorized, notes FROM runs ORDER BY id DESC LIMIT 20').all() as any[];
  for (const r of rows) console.log(`#${r.id}  ${r.tool}  ${r.started_at} -> ${r.finished_at ?? '(running)'}  auth=${r.scope_authorized}  ${r.notes ?? ''}`);
} else {
  console.error(`Usage: query <attempts|credentials|sessions|runs> [attack.db]`);
  process.exit(1);
}

db.close();
