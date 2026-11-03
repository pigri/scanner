#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import os from 'node:os';
import { reclassify, loadState, saveState } from './lib/resolve-state.js';

interface Opts {
  parentsFile: string;
  suffix: string;
  domainsFile: string;
  seclist: string;
  ctSources: string;
  skipBrute: boolean;
  skipCt: boolean;
  skipEnrich: boolean;
  phantomThreshold: number;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    parentsFile: 'parents.txt',
    suffix: 'gov.hu',
    domainsFile: 'domains.txt',
    seclist: 'top-5000',
    ctSources: 'both',
    skipBrute: false,
    skipCt: false,
    skipEnrich: false,
    phantomThreshold: 3,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--parents') opts.parentsFile = next();
    else if (a === '--suffix') opts.suffix = next();
    else if (a === '--domains') opts.domainsFile = next();
    else if (a === '--seclist') opts.seclist = next();
    else if (a === '--ct-sources') opts.ctSources = next();
    else if (a === '--skip-brute') opts.skipBrute = true;
    else if (a === '--skip-ct') opts.skipCt = true;
    else if (a === '--skip-enrich') opts.skipEnrich = true;
    else if (a === '--phantom-threshold') opts.phantomThreshold = Math.max(1, parseInt(next(), 10) || 3);
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: refresh [options]

Runs one full discovery refresh cycle:
  1. ct-log:    crt.sh + certspotter for each parent, merge into --domains
  2. dns-brute: SecLists wordlist against each parent, merge into --domains
  3. enrich:    re-resolve domains + phantoms, reclassify (self-healing)

Options:
  --parents <file>         Parent domains list (default: parents.txt)
  --suffix <domain>        Only keep hosts under this suffix (default: gov.hu)
  --domains <file>         Master hostname file (default: domains.txt)
  --seclist <name>         SecLists variant (default: top-5000)
  --ct-sources <s>         CT source(s): crtsh | certspotter | both (default: both)
  --skip-brute             Skip DNS brute step
  --skip-ct                Skip CT log step
  --skip-enrich            Skip enrichment
  --phantom-threshold <N>  Consecutive failed runs before a host is binned (default: 3)
`);
}

function run(cmd: string, args: string[]): Promise<number> {
  return new Promise((resolve) => {
    console.error(`\n$ ${cmd} ${args.join(' ')}`);
    const child = spawn(cmd, args, { stdio: 'inherit' });
    child.on('close', (code) => resolve(code ?? 1));
  });
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }

  if (!fs.existsSync(opts.parentsFile)) {
    console.error(`FATAL: parents file ${opts.parentsFile} not found`);
    process.exit(1);
  }
  const parents = fs
    .readFileSync(opts.parentsFile, 'utf8')
    .split('\n').map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));

  const initialCount = fs.existsSync(opts.domainsFile)
    ? new Set(fs.readFileSync(opts.domainsFile, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)).size
    : 0;
  console.error(`refresh start: ${initialCount} hosts in ${opts.domainsFile}`);
  console.error(`  parents (${parents.length}): ${parents.slice(0, 5).join(', ')}${parents.length > 5 ? ' ...' : ''}`);

  if (!opts.skipCt) {
    console.error('\n=== stage 1: CT logs ===');
    for (const p of parents) {
      await run('npx', [
        'tsx', 'src/ct-log.ts', p,
        '--source', opts.ctSources,
        '--suffix', opts.suffix,
        '--merge', opts.domainsFile,
        '-o', `/tmp/ct-${p.replace(/[^a-z0-9._-]/gi, '_')}.txt`,
      ]);
    }
  }

  if (!opts.skipBrute) {
    console.error('\n=== stage 2: DNS brute ===');
    await run('npx', [
      'tsx', 'src/dns-brute.ts',
      '--parents', opts.parentsFile,
      '--seclist', opts.seclist,
      '--merge', opts.domainsFile,
      '-o', 'brute-hosts.txt',
    ]);
  }

  if (!opts.skipEnrich) {
    console.error('\n=== stage 3: enrich + phantom reclassify ===');
    const phantomsFile = 'phantoms.txt';
    const stateFile = 'resolve-state.json';
    const readLines = (f: string): string[] =>
      fs.existsSync(f)
        ? fs.readFileSync(f, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
        : [];
    // Re-test phantoms too (self-healing): a host wrongly binned on a past
    // transient failure returns automatically once it resolves again. A host
    // is only moved to phantoms after it fails --phantom-threshold runs in a
    // row, so a single transient miss never evicts a live host.
    const union = [...new Set([...readLines(opts.domainsFile), ...readLines(phantomsFile)])].sort();
    const unionFile = path.join(os.tmpdir(), `refresh-union-${process.pid}.txt`);
    fs.writeFileSync(unionFile, union.join('\n') + '\n');
    let code: number;
    try {
      code = await run('npx', ['tsx', 'src/enrich.ts', unionFile, '--concurrency', '40']);
    } finally {
      fs.rmSync(unionFile, { force: true });
    }

    // enriched.jsonl is truncate-on-open, so a non-zero exit means a partial
    // file whose final line may be truncated. Only parse it on a clean exit:
    // reclassify() throws on a non-zero code regardless of rows (before any of
    // the master lists are touched), so passing [] there keeps the abort while
    // avoiding a raw JSON-parse error that would mask reclassify's message.
    const rows: { domain: string; addresses: unknown[] }[] = [];
    if (code === 0 && fs.existsSync('enriched.jsonl')) {
      for (const line of fs.readFileSync('enriched.jsonl', 'utf8').split('\n')) {
        if (!line.trim()) continue;
        rows.push(JSON.parse(line));
      }
    }
    const { domains, phantoms, state } = reclassify(
      code,
      rows,
      loadState(stateFile),
      opts.phantomThreshold,
    );
    const resolved = rows.filter((r) => r.addresses.length > 0);
    fs.writeFileSync(opts.domainsFile, domains.join('\n') + '\n');
    fs.writeFileSync(phantomsFile, phantoms.join('\n') + '\n');
    saveState(stateFile, state);
    const grace = domains.length - resolved.length;
    console.error(
      `reclassified: ${resolved.length} resolved, ${grace} in grace, ${phantoms.length} phantoms (threshold ${opts.phantomThreshold})`,
    );
  }

  const finalCount = new Set(
    fs.readFileSync(opts.domainsFile, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
  ).size;
  console.error(`\ndone. ${initialCount} -> ${finalCount} (+${finalCount - initialCount})`);
  fs.writeFileSync('refresh-summary.json', JSON.stringify({
    at: new Date().toISOString(),
    parents: parents.length,
    seclist: opts.seclist,
    initial: initialCount,
    final: finalCount,
    delta: finalCount - initialCount,
  }, null, 2));
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
