#!/usr/bin/env -S node --loader tsx
// Flag parent zones that answer for guaranteed-nonexistent subdomains (wildcard
// DNS). Reads parent zones from --parents <file> or stdin (one per line).
// Replaces the old wildcard-check.sh; logic lives in lib/wildcard.ts.
import fs from 'node:fs';
import { digShort } from './lib/dns.js';
import { wildcardProbeHosts, classifyWildcard } from './lib/wildcard.js';

interface Opts {
  parentsFile: string | null;
  resolver: string;
  timeoutSec: number;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { parentsFile: null, resolver: '1.1.1.1', timeoutSec: 3 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--parents') opts.parentsFile = next();
    else if (a === '--resolver') opts.resolver = next();
    else if (a === '--timeout') opts.timeoutSec = parseInt(next(), 10);
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: wildcard-check [--parents <file>] [--resolver 1.1.1.1] [--timeout 3]

Reads parent zones (one per line) from --parents <file> or stdin and prints
whether each answers for a nonexistent subdomain (i.e. has a wildcard record).

Output:  "WILDCARD <zone> -> <ip[,ip...]>"  or  "  clean  <zone>"`);
}

function readParents(file: string | null): string[] {
  const raw = file ? fs.readFileSync(file, 'utf8') : fs.readFileSync(0, 'utf8');
  return raw.split('\n').map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  const parents = readParents(opts.parentsFile);
  let wildcardCount = 0;
  for (const parent of parents) {
    const answers = await Promise.all(
      wildcardProbeHosts(parent).map((h) => digShort(h, opts.resolver, opts.timeoutSec))
    );
    const v = classifyWildcard(parent, answers);
    if (v.wildcard) {
      wildcardCount++;
      console.log(`WILDCARD ${v.parent} -> ${v.ips.join(',')}`);
    } else {
      console.log(`  clean  ${v.parent}`);
    }
  }
  console.error(`\n${wildcardCount}/${parents.length} zones have wildcard DNS`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
