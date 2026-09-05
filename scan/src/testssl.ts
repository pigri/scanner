#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { normalizeTestsslFinding } from './lib/testssl-parse.js';
import { parseCertificates } from './lib/testssl-cert.js';
import { openDb, type Db } from './lib/db.js';

interface TestsslFinding { id?: string; severity?: string; finding?: string; cve?: string; port?: string }

async function scanOne(
  testsslBin: string,
  host: string,
  tmpPath: string,
  extraArgs: string[],
  timeoutMs: number
): Promise<{ ok: boolean; findings: TestsslFinding[]; stderr: string; code: number; parseError?: string }> {
  const args = ['--jsonfile', tmpPath, '--parallel', '--fast', '--quiet', '--sneaky', '--warnings=off', ...extraArgs, host];
  const r = await run(testsslBin, args, { timeoutMs });
  if (!fs.existsSync(tmpPath)) return { ok: false, findings: [], stderr: r.stderr.slice(0, 300), code: r.code };
  const raw = fs.readFileSync(tmpPath, 'utf8').trim();
  if (!raw) return { ok: true, findings: [], stderr: '', code: r.code };
  try {
    // testssl.sh sometimes writes control characters or unescaped bytes in "finding" strings.
    // Fall back to lenient parsing if strict parse fails.
    return { ok: true, findings: JSON.parse(raw) as TestsslFinding[], stderr: '', code: r.code };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    // Best-effort: strip raw control bytes and retry.
    const scrubbed = raw.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
    try {
      return { ok: true, findings: JSON.parse(scrubbed) as TestsslFinding[], stderr: '', code: r.code, parseError: msg };
    } catch {
      return { ok: false, findings: [], stderr: `parse: ${msg}`, code: r.code, parseError: msg };
    }
  }
}

async function pool<T, R>(items: readonly T[], size: number, worker: (item: T, idx: number) => Promise<R>): Promise<(R | null)[]> {
  const results = new Array<R | null>(items.length);
  let i = 0;
  async function drain(): Promise<void> {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      try {
        results[idx] = await worker(items[idx]!, idx);
      } catch (e: unknown) {
        console.error(`\n[pool] worker for item ${idx} threw: ${e instanceof Error ? e.message : String(e)}`);
        results[idx] = null;
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, drain));
  return results;
}

function loadLiveHttpsTargets(db: Db): Set<string> {
  const set = new Set<string>();
  // https URLs seen by httpx
  const httpsRows = db.raw.prepare("SELECT DISTINCT target FROM http_probes WHERE url LIKE 'https://%'").all() as { target: string }[];
  for (const r of httpsRows) set.add(r.target);
  // hosts with port 443 in nmap/masscan
  const portRows = db.raw.prepare('SELECT DISTINCT target FROM ports WHERE port = 443').all() as { target: string }[];
  for (const r of portRows) set.add(r.target);
  return set;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  // Extra flags parsed from remaining args (parseCommonCli passes them through as extraArgs after --).
  // Custom flags we own here:
  let concurrency = 4;
  let liveOnly = false;
  let timeoutMs = 180_000;
  const passthroughForTool: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--concurrency') concurrency = Math.max(1, parseInt(nxt(), 10));
    else if (a === '--live-only') liveOnly = true;
    else if (a === '--host-timeout-ms') timeoutMs = parseInt(nxt(), 10);
    else passthroughForTool.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('testssl', `
Runs testssl.sh per in-scope host in parallel.
Default profile per host: --parallel --fast --quiet --sneaky --warnings=off.

Extra flags (before '--'):
  --concurrency <N>     parallel hosts scanned at once (default: 4)
  --live-only           filter targets to hosts we've seen listen on 443
                        (uses http_probes with https:// URLs OR ports table
                        with port=443). Requires --sqlite.
  --host-timeout-ms <N> per-host kill timeout (default: 180000)

Anything after '--' is passed to testssl.sh verbatim.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  const testsslBin = await requireTool('testssl.sh', 'testssl');
  let { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;

  // Live-only pre-filter — massive time saver, dead hosts otherwise burn 30-60s each.
  if (liveOnly) {
    if (!db) { console.error('--live-only requires --sqlite'); process.exit(1); }
    const live = loadLiveHttpsTargets(db);
    const before = targets.length;
    targets = targets.filter((t) => live.has(t.replace(/^https?:\/\//, '').split('/')[0]!));
    console.error(`--live-only filter: ${before} → ${targets.length} targets`);
    if (!targets.length) { console.error('no live https targets'); if (db) db.close(); process.exit(0); }
  }

  const runId = db ? db.startRun('testssl', { targets: targets.length, concurrency, liveOnly }, now) : null;
  const outFile = resolveOutputPath(opts, runId, 'testssl.jsonl');
  const wstream = fs.createWriteStream(outFile);
  const start = Date.now();
  let done = 0, findings = 0;

  console.error(`testssl: ${targets.length} hosts, concurrency=${concurrency}, timeout=${timeoutMs}ms`);

  await pool(targets, concurrency, async (target) => {
    const host = target.replace(/^https?:\/\//, '').split('/')[0]!;
    const tmp = resolveOutputPath(
      { ...opts, outFile: null },
      runId,
      `testssl-${host.replace(/[^a-z0-9._-]+/gi, '_')}.json`
    );
    const res = await scanOne(testsslBin, host, tmp, passthroughForTool, timeoutMs);
    if (res.ok) {
      wstream.write(JSON.stringify({ target: host, findings: res.findings }) + '\n');
      if (db && Array.isArray(res.findings)) {
        for (const f of res.findings) {
          // id is the check name, finding is its value — build the title from
          // both so it reads clearly (see lib/testssl-parse).
          const norm = normalizeTestsslFinding(f);
          if (!norm) continue;
          db.insertFinding({
            tool: 'testssl',
            target: host,
            category: norm.category,
            severity: norm.severity,
            title: norm.title,
            cve: norm.cve,
            matched_at: host,
            meta: f,
          }, now, runId);
          findings++;
        }
        // Structured certificate inventory from the full cert_* block.
        for (const cert of parseCertificates(res.findings)) {
          db.insertCertificate({ target: host, ...cert }, now, runId);
        }
      }
    } else {
      wstream.write(JSON.stringify({ target: host, error: res.stderr || 'no output', code: res.code }) + '\n');
    }
    done++;
    const rate = done / ((Date.now() - start) / 1000);
    if (done % 5 === 0 || done === targets.length) {
      process.stderr.write(`\r  ${done}/${targets.length} · ${rate.toFixed(2)} hosts/s`);
    }
  });
  process.stderr.write('\n');

  await new Promise<void>((r) => wstream.end(() => r()));
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.error(`testssl done in ${elapsed}s: ${done}/${targets.length}. Output: ${outFile}`);
  if (db && runId !== null) {
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: findings, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${findings} findings, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
