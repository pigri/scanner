#!/usr/bin/env -S node --loader tsx
// frozen-pairs: read-only report of (target, tool) pairs whose newest stamp
// carries a partial_stamps marker and that have no tool_coverage row. Their
// watermark is the newest unmarked stamp, or '' when every stamp is marked, so
// their rows stay current and retention keeps them. See lib/current-findings.ts.
import { resolveDbArg, isDbFlag } from './lib/db-arg.js';
import { frozenReport, formatText, openReadOnly } from './lib/frozen-pairs.js';

function usage(): void {
  console.error(`Usage: frozen-pairs [--sqlite scan.db] [--json] [--top N]

Per tool: pairs whose newest stamp is marked partial, how many of those have
every stamp marked (watermark ''), finding rows they hold current, and the age
of the oldest marker. Sticky tools and pairs with a tool_coverage row are left
out. --top N lists the N biggest pairs. The DB is opened read-only.`);
}

function main(): void {
  const argv = process.argv;
  let json = false;
  let top = 0;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (isDbFlag(a)) i++;
    else if (a === '--json') json = true;
    else if (a === '--top') top = parseInt(argv[++i]!, 10);
    else if (a === '-h' || a === '--help') { usage(); return; }
  }
  if (!Number.isInteger(top) || top < 0) { usage(); process.exit(2); }
  const db = openReadOnly(resolveDbArg(argv));
  try {
    const r = frozenReport(db, top);
    process.stdout.write(json ? JSON.stringify(r) + '\n' : formatText(r));
  } finally {
    db.close();
  }
}

main();
