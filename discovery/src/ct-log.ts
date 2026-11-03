#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { makeDomainFilter } from './lib/ddg.js';
import { openDb } from './lib/db.js';
import { queryAll, type CtSource } from './lib/ct-fetch.js';

interface Opts {
  patterns: string[];
  out: string;
  suffix: string | null;
  exclude: string[];
  merge: string | null;
  timeoutMs: number;
  source: CtSource;
  sqlite: string | null;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    patterns: [],
    out: 'ct-hosts.txt',
    suffix: null,
    exclude: [],
    merge: null,
    timeoutMs: 60000,
    source: 'both',
    sqlite: null,
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '-o' || a === '--out') opts.out = next();
    else if (a === '--suffix') opts.suffix = next().toLowerCase().replace(/^\./, '');
    else if (a === '--exclude') opts.exclude = next().split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    else if (a === '--merge') opts.merge = next();
    else if (a === '--timeout-ms') opts.timeoutMs = parseInt(next(), 10);
    else if (a === '--source') opts.source = next() as CtSource;
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  opts.patterns = rest;
  return opts;
}

function usage(): void {
  console.error(`Usage: ct-log <pattern...> [options]

Query certificate transparency logs (crt.sh + certspotter) for one or more
domain patterns and emit a deduplicated hostname list. Use '%' as a wildcard
in patterns (SQL LIKE style), e.g. '%.dtr.gov.hu' or '%.gov.hu'.

Options:
  -o, --out <path>       Output file, one host per line (default: ct-hosts.txt)
  --suffix <domain>      Only keep hosts ending in this suffix (e.g. gov.hu)
  --exclude <a,b,c>      Skip these apex domains + their subdomains
  --merge <path>         Merge into this existing hostname file (dedupe union)
  --timeout-ms <N>       Per-request timeout (default: 60000; crt.sh can be slow)
  --source <src>         crtsh | certspotter | both (default: both — union)
  --sqlite <path>        Also write hosts + source tags to this SQLite DB

Environment:
  CERTSPOTTER_TOKEN      Certspotter API token for higher rate limits (sent as
                         'Authorization: Bearer'). Without one, certspotter is
                         tried once with no backoff (retrying an anonymous 429
                         only wastes time); a token enables retries.
  CT_CRTSH_DISABLED=1    Skip crt.sh (escape hatch if it starts 502ing again).

Examples:
  ct-log '%.dtr.gov.hu' -o dtr-hosts.txt
  ct-log '%.gov.hu' --exclude nki.gov.hu,nbsz.gov.hu --merge domains.txt
`);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.patterns.length) {
    usage();
    process.exit(opts.patterns.length ? 0 : 1);
  }
  const crtshEnabled = process.env.CT_CRTSH_DISABLED !== '1';
  const token = process.env.CERTSPOTTER_TOKEN || undefined;
  const keep = makeDomainFilter(opts.suffix, opts.exclude);
  const existing = opts.merge
    ? new Set(
        fs.readFileSync(opts.merge, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
      )
    : new Set<string>();
  const seed = new Set(existing);
  const found = new Set<string>();

  const log = (s: string) => console.error(s);
  for (const pattern of opts.patterns) {
    console.error(`querying ${opts.source}: ${pattern}`);
    const hosts = await queryAll(pattern, opts.source, {
      timeoutMs: opts.timeoutMs,
      crtshEnabled,
      token,
      // Anonymous certspotter 429s are a steady-state limit; retrying wastes
      // time per parent. Only retry when a token lifts that limit.
      certspotterMaxRetries: token ? undefined : 0,
      log,
    });
    let kept = 0, newHosts = 0;
    for (const raw of hosts) {
      const filtered = keep(raw);
      if (!filtered) continue;
      kept++;
      if (!existing.has(filtered) && !found.has(filtered)) {
        found.add(filtered);
        newHosts++;
      }
    }
    console.error(`  ${hosts.length} raw union · ${kept} kept · ${newHosts} new`);
  }

  const merged = new Set([...seed, ...found]);
  const outPath = path.resolve(opts.out);
  fs.writeFileSync(outPath, [...merged].sort().join('\n') + '\n');

  if (opts.sqlite && found.size) {
    const db = openDb(opts.sqlite);
    const now = new Date().toISOString();
    const source = opts.source === 'both' ? 'ct-both' : `ct-${opts.source}`;
    const runId = db.startRun('ct-log', { patterns: opts.patterns, source: opts.source }, now);
    for (const h of found) db.upsertHost(h, source, now);
    db.finishRun(runId, { addedHosts: found.size, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite)} (+${found.size} hosts)`);
  }
  console.error(`wrote ${merged.size} hosts (${found.size} new) to ${outPath}`);

  if (opts.merge) {
    fs.writeFileSync(path.resolve(opts.merge), [...merged].sort().join('\n') + '\n');
    console.error(`merged back into ${opts.merge} (was ${seed.size}, now ${merged.size})`);
  }
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error('FATAL:', msg);
  process.exit(1);
});
