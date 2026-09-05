#!/usr/bin/env -S node --loader tsx
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { openDb } from './lib/db.js';

function findChromeBinary(): string | null {
  const explicit = process.env['CHROME_PATH'];
  if (explicit && fs.existsSync(explicit)) return explicit;
  const candidates = [
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/snap/bin/chromium',
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  // fall back to newest Puppeteer-managed Chrome
  const cache = path.join(os.homedir(), '.cache', 'puppeteer', 'chrome');
  if (fs.existsSync(cache)) {
    const versions = fs.readdirSync(cache).filter((d) => d.startsWith('linux-')).sort().reverse();
    for (const v of versions) {
      const bin = path.join(cache, v, 'chrome-linux64', 'chrome');
      if (fs.existsSync(bin)) return bin;
    }
  }
  return null;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('gowitness', `
Runs 'gowitness file -f targets.txt' — screenshots every http(s) target.
Screenshots + SQLite DB land in the run dir (or ./screenshots).`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('gowitness');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('gowitness', { urls: targets.length }, now) : null;

  // The screenshot dir is derived from the run dir so it's isolated per-run.
  const dirPath = resolveOutputPath({ ...opts, outFile: null }, runId, 'screenshots');
  fs.mkdirSync(dirPath, { recursive: true });
  const urls = targets.flatMap((t) =>
    t.startsWith('http') ? [t] : [`https://${t}`, `http://${t}`]
  );
  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'gowitness-targets.txt');
  writeLines(tmp, urls);
  // gowitness v3 CLI: `gowitness scan file -f targets.txt`. v2 was `gowitness file`.
  const helpOut = await run('gowitness', ['--help'], { timeoutMs: 5000 });
  const isV3 = /scan\s+Perform various scans/.test(helpOut.stdout);
  const jsonlOut = path.join(path.dirname(dirPath), 'gowitness.jsonl');
  // gowitness v3 requires a system Chrome. Find it, or bail early with a clear message.
  const chromePath = isV3 ? findChromeBinary() : null;
  if (isV3 && !chromePath) {
    console.error(
      'FATAL: gowitness v3 needs Chrome/Chromium and none was found.\n' +
      '  Install one of:\n' +
      '    sudo apt install chromium-browser\n' +
      '  or set $CHROME_PATH to a chrome binary, or\n' +
      '  install Puppeteer once anywhere (`npx puppeteer browsers install chrome`).'
    );
    process.exit(4);
  }
  // --timeout bounds each page (default 60s); the run() timeoutMs is a hard cap
  // on the whole batch so a browser-level Chrome hang can't wedge scan-all
  // forever (root-caused a 2.7h stuck batch on edge-filtered hosts).
  const pageTimeout = '30';
  const scanTimeoutMs = 8 * 60 * 1000; // 8 min hard ceiling per gowitness batch
  const args = isV3
    ? [
        'scan', 'file', '-f', tmp, '-t', '20', '-s', dirPath,
        '--chrome-path', chromePath!, '--timeout', pageTimeout,
        '--write-jsonl', '--write-jsonl-file', jsonlOut,
        ...opts.extraArgs,
      ]
    : ['file', '-f', tmp, '--threads', '20', '--timeout', pageTimeout, '--screenshot-path', dirPath, ...opts.extraArgs];
  if (isV3 && chromePath) console.error(`  chrome: ${chromePath}`);
  console.error(`gowitness ${args.join(' ')} (hard cap ${scanTimeoutMs / 1000}s)`);
  const r = await run('gowitness', args, { timeoutMs: scanTimeoutMs });
  console.error(`gowitness exited ${r.code}, screenshots in ${dirPath}`);

  if (db && runId !== null) {
    let count = 0;
    for (const f of fs.readdirSync(dirPath)) {
      if (!/\.(png|jpg|jpeg|webp)$/i.test(f)) continue;
      db.insertScreenshot({ target: f, url: '', path: path.join(dirPath, f) }, now, runId);
      count++;
    }
    db.finishRun(runId, { targetsCount: urls.length, findingsCount: count, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${count} screenshots indexed, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
