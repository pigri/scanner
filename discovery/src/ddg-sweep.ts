#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import puppeteer, { type Browser, type Page } from 'puppeteer';
import { decodeDdgUrl, hostOf, makeDomainFilter, type DomainFilter } from './lib/ddg.js';
import { openDb, type Db } from './lib/db.js';

interface Opts {
  query: string;
  terms: string[];
  regions: string[];
  suffix: string | null;
  exclude: string[];
  out: string;
  log: string;
  maxPages: number;
  delayMs: number;
  cooldownMs: number;
  endpoint: string;
  rotateCmd: string | null;
  rotateWaitMs: number;
  rotateVerifyUrl: string | null;
  sqlite: string | null;
  help?: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = {
    query: '',
    terms: [],
    regions: ['wt-wt'],
    suffix: null,
    exclude: [],
    out: 'domains.txt',
    log: 'sweep.log',
    maxPages: 15,
    delayMs: 4000,
    cooldownMs: 90000,
    endpoint: 'https://lite.duckduckgo.com/lite/',
    rotateCmd: null,
    rotateWaitMs: 8000,
    rotateVerifyUrl: 'https://api.ipify.org?format=text',
    sqlite: null,
  };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--terms') opts.terms = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--regions') opts.regions = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--suffix') opts.suffix = next().toLowerCase().replace(/^\./, '');
    else if (a === '--exclude') opts.exclude = next().split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    else if (a === '--out') opts.out = next();
    else if (a === '--log') opts.log = next();
    else if (a === '--max-pages') opts.maxPages = parseInt(next(), 10);
    else if (a === '--delay-ms') opts.delayMs = parseInt(next(), 10);
    else if (a === '--cooldown-ms') opts.cooldownMs = parseInt(next(), 10);
    else if (a === '--rotate-cmd') opts.rotateCmd = next();
    else if (a === '--rotate-wait-ms') opts.rotateWaitMs = parseInt(next(), 10);
    else if (a === '--rotate-verify-url') opts.rotateVerifyUrl = next();
    else if (a === '--windscribe') opts.rotateCmd = 'windscribe-cli ip rotate';
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '--help' || a === '-h') opts.help = true;
    else rest.push(a);
  }
  opts.query = rest.join(' ');
  return opts;
}

function usage(): void {
  console.error(`Usage: ddg-sweep <query> [options]

Iterate DuckDuckGo /lite/ across query variants x region variants,
extract unique hostnames from every result, filter by suffix,
persist to a text file after every page (crash-safe).

Options:
  --terms <a,b,c>       Expansion terms appended to the base query, one per combo
  --regions <a,b,c>     DDG regions to rotate (default: wt-wt)
                        Common: wt-wt, us-en, hu-hu, de-de, at-de, uk-en
  --suffix <domain>     Only keep hostnames ending in this suffix (e.g. .gov.hu)
  --exclude <a,b,c>     Skip these apex domains and their subdomains
  --out <path>          Output file, one domain per line (default: domains.txt)
  --log <path>          Log file (default: sweep.log)
  --max-pages <N>       Max DDG pages per (query, region) combo (default: 15)
  --delay-ms <N>        Inter-page delay in ms (default: 4000)
  --cooldown-ms <N>     Cooldown after a rate-limit anomaly (default: 90000)
  --rotate-cmd <cmd>    Shell command to rotate the exit IP after an anomaly
  --windscribe          Shortcut for --rotate-cmd 'windscribe-cli ip rotate'
  --rotate-wait-ms <N>  Wait ms after the rotate command (default: 8000)
  --rotate-verify-url <url>  URL fetched to log/verify new egress IP
  --sqlite <path>       Also write hosts + source tags to this SQLite DB
`);
}

interface ShellResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runShell(cmd: string, timeoutMs = 60000): Promise<ShellResult> {
  return new Promise((resolve) => {
    execFile('sh', ['-c', cmd], { timeout: timeoutMs }, (err, stdout, stderr) => {
      const rawCode = err ? (err as { code?: unknown }).code : 0;
      const code = typeof rawCode === 'number' ? rawCode : rawCode ? 1 : 0;
      resolve({ code, stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
  });
}

async function fetchIp(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    return (await res.text()).trim();
  } catch {
    return null;
  }
}

interface Logger { (line: string): void }

interface RotateResult { ok: boolean; ip?: string | null }

async function rotateIp(cmd: string, waitMs: number, verifyUrl: string | null, log: Logger): Promise<RotateResult> {
  log(`  rotating IP: ${cmd}`);
  const before = verifyUrl ? await fetchIp(verifyUrl) : null;
  const r = await runShell(cmd);
  if (r.code !== 0) {
    log(`  rotate exit ${r.code}: ${(r.stderr || r.stdout).trim().slice(0, 200)}`);
    return { ok: false };
  }
  await new Promise((res) => setTimeout(res, waitMs));
  const after = verifyUrl ? await fetchIp(verifyUrl) : null;
  if (before && after && before === after) {
    log(`  IP unchanged (${after}) — rotate did not take effect`);
    return { ok: false, ip: after };
  }
  log(`  IP: ${before || '?'} -> ${after || '?'}`);
  return { ok: true, ip: after };
}

function loadExisting(file: string): Set<string> {
  try {
    return new Set(
      fs.readFileSync(file, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
    );
  } catch {
    return new Set();
  }
}

function persist(file: string, set: ReadonlySet<string>): void {
  fs.writeFileSync(file, [...set].sort().join('\n') + '\n');
}

interface ComboResult { stopped: 'anomaly' | 'end' | 'max_pages'; pages: number }

async function scrapeCombo(
  browser: Browser,
  endpoint: string,
  query: string,
  region: string,
  maxPages: number,
  delayMs: number,
  domains: Set<string>,
  keep: DomainFilter,
  log: Logger
): Promise<ComboResult> {
  const p: Page = await browser.newPage();
  try {
    await p.setUserAgent(
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
    );
    const url = `${endpoint}?q=${encodeURIComponent(query)}&kl=${encodeURIComponent(region)}`;
    await p.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });

    for (let page = 1; page <= maxPages; page++) {
      const state = await p.evaluate(() => {
        const rawLinks = Array.from(
          document.querySelectorAll<HTMLAnchorElement>('a[href*="/l/?uddg="], a[href^="http"]')
        )
          .map((a) => a.href)
          .filter((h) => !/duckduckgo\.com\/(?!l\/)/.test(h));
        const anomaly =
          !!document.querySelector('.anomaly-modal__title, .anomaly') ||
          /unusual traffic|are you a robot/i.test(document.body.innerText || '');
        return { rawLinks, anomaly };
      });

      if (state.anomaly) return { stopped: 'anomaly', pages: page - 1 };

      let added = 0;
      for (const raw of state.rawLinks) {
        const d = keep(hostOf(decodeDdgUrl(raw)));
        if (d && !domains.has(d)) {
          domains.add(d);
          added++;
        }
      }
      log(`  page ${page}: +${added} new (total ${domains.size})`);

      const hasNext = await p.$('form.next_form');
      if (!hasNext) return { stopped: 'end', pages: page };

      await Promise.all([
        p.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => null),
        p.evaluate(() => {
          const f = document.querySelector<HTMLFormElement>('form.next_form');
          if (f) f.submit();
        }),
      ]);
      await new Promise((r) => setTimeout(r, delayMs + Math.floor(Math.random() * 1500)));
    }
    return { stopped: 'max_pages', pages: maxPages };
  } finally {
    await p.close().catch(() => {});
  }
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.query) {
    usage();
    process.exit(opts.query ? 0 : 1);
  }

  const outFile = path.resolve(opts.out);
  const logFile = path.resolve(opts.log);
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  const log: Logger = (line) => {
    const ts = new Date().toISOString();
    fs.appendFileSync(logFile, `${ts} ${line}\n`);
    console.log(line);
  };

  const queries = opts.terms.length ? opts.terms.map((t) => `${opts.query} ${t}`) : [opts.query];
  const combos: { q: string; r: string }[] = [];
  for (const q of queries) for (const r of opts.regions) combos.push({ q, r });

  const domains = loadExisting(outFile);
  const keep = makeDomainFilter(opts.suffix, opts.exclude);
  const startedAt = Date.now();

  let db: Db | null = null;
  let runId: number | null = null;
  const runStartIso = new Date().toISOString();
  if (opts.sqlite) {
    db = openDb(opts.sqlite);
    runId = db.startRun('ddg-sweep', { query: opts.query, regions: opts.regions, terms: opts.terms }, runStartIso);
  }
  const seededSize = domains.size;

  log(`START — seeded ${domains.size} domains from ${outFile}`);
  log(
    `plan: ${queries.length} queries x ${opts.regions.length} regions = ${combos.length} combos, ${opts.maxPages} pages each`
  );
  if (opts.rotateVerifyUrl) {
    const ip = await fetchIp(opts.rotateVerifyUrl);
    log(`egress IP: ${ip || 'unknown'}${opts.rotateCmd ? ` (will rotate via: ${opts.rotateCmd})` : ''}`);
  }

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  try {
    let i = 0;
    for (const { q, r } of combos) {
      i++;
      const before = domains.size;
      log(`\n[${i}/${combos.length}] region=${r} q="${q}"`);
      const result = await scrapeCombo(
        browser,
        opts.endpoint,
        q,
        r,
        opts.maxPages,
        opts.delayMs,
        domains,
        keep,
        log
      );
      const delta = domains.size - before;
      log(`  -> ${result.stopped} after ${result.pages} pages, +${delta} domains this combo`);
      persist(outFile, domains);
      if (db && delta > 0) {
        const nowIso = new Date().toISOString();
        // The domain set is a Set<string>; new hosts are those added since 'before'.
        // We can't cheaply diff sets without O(n) — but n is small (delta), so scan.
        // Cheapest: iterate the whole set, upsertHost is idempotent + fast.
        for (const name of domains) db.upsertHost(name, 'ddg', nowIso);
      }

      if (result.stopped === 'anomaly' && opts.rotateCmd) {
        const rotated = await rotateIp(opts.rotateCmd, opts.rotateWaitMs, opts.rotateVerifyUrl, log);
        if (!rotated.ok) {
          log(`  falling back to cooldown ${opts.cooldownMs / 1000}s...`);
          await new Promise((r) => setTimeout(r, opts.cooldownMs));
        }
      } else if (result.stopped === 'anomaly') {
        log(`  cooldown ${opts.cooldownMs / 1000}s...`);
        await new Promise((r) => setTimeout(r, opts.cooldownMs));
      } else {
        await new Promise((r) => setTimeout(r, 3000 + Math.floor(Math.random() * 2000)));
      }
    }
  } finally {
    await browser.close();
  }

  const elapsed = ((Date.now() - startedAt) / 1000).toFixed(0);
  log(`\nDONE — ${domains.size} unique domains in ${outFile}, ${elapsed}s wall clock`);

  if (db && runId !== null) {
    db.finishRun(runId, { addedHosts: domains.size - seededSize, at: new Date().toISOString() });
    db.close();
    log(`sqlite: ${path.resolve(opts.sqlite!)}`);
  }
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error('FATAL:', msg);
  process.exit(1);
});
