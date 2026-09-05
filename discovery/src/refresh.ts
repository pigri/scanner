#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

interface Opts {
  parentsFile: string;
  suffix: string;
  domainsFile: string;
  seclist: string;
  ctSources: string;
  skipBrute: boolean;
  skipCt: boolean;
  skipEnrich: boolean;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    parentsFile: 'parents.txt',
    suffix: 'gov.hu',
    domainsFile: 'domains.txt',
    seclist: 'top-5000',
    ctSources: 'certspotter',
    skipBrute: false,
    skipCt: false,
    skipEnrich: false,
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
    else if (a === '-h' || a === '--help') opts.help = true;
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: refresh [options]

Runs one full discovery refresh cycle:
  1. ct-log:    crt.sh + certspotter for each parent, merge into --domains
  2. dns-brute: SecLists wordlist against each parent, merge into --domains
  3. enrich:    resolve every host + PTR + MMDB, filter phantoms

Options:
  --parents <file>     Parent domains list (default: parents.txt)
  --suffix <domain>    Only keep hosts under this suffix (default: gov.hu)
  --domains <file>     Master hostname file (default: domains.txt)
  --seclist <name>     SecLists variant (default: top-5000)
  --ct-sources <s>     CT source(s): crtsh | certspotter | both (default: certspotter)
  --skip-brute         Skip DNS brute step
  --skip-ct            Skip CT log step
  --skip-enrich        Skip enrichment
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
    console.error('\n=== stage 3: enrich + phantom filter ===');
    await run('npx', ['tsx', 'src/enrich.ts', opts.domainsFile, '--concurrency', '40']);
    // Filter phantoms. Phantoms accumulate across runs — if we overwrote the
    // file with only this run's failures, back-to-back runs would clobber
    // real phantoms whenever the second run's input already excludes them
    // (see loss chain: run1 moves H to phantoms, run2 sees 0 new failures
    // and would wipe the file). Union with the existing phantoms.txt.
    const rows: { domain: string; addresses: unknown[] }[] = [];
    for (const line of fs.readFileSync('enriched.jsonl', 'utf8').split('\n')) {
      if (!line.trim()) continue;
      rows.push(JSON.parse(line));
    }
    const resolved = rows.filter((r) => r.addresses.length > 0).map((r) => r.domain);
    const newPhantoms = rows.filter((r) => r.addresses.length === 0).map((r) => r.domain);
    const existingPhantoms = fs.existsSync('phantoms.txt')
      ? fs.readFileSync('phantoms.txt', 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
      : [];
    const allPhantoms = [...new Set([...existingPhantoms, ...newPhantoms])].sort();
    fs.writeFileSync(opts.domainsFile, [...new Set(resolved)].sort().join('\n') + '\n');
    fs.writeFileSync('phantoms.txt', allPhantoms.join('\n') + '\n');
    console.error(`filtered: ${resolved.length} resolvable, +${newPhantoms.length} new phantoms (${allPhantoms.length} total)`);
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
