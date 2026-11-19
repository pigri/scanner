// Runs the wrapper scripts as subprocesses against fake tool binaries: no network, no real scanners.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';

const SCAN = path.resolve(__dirname, '..');
let dir: string;

beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wrapper-partial-')); fs.mkdirSync(path.join(dir, 'bin')); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

function fake(name: string, body: string): void {
  const p = path.join(dir, 'bin', name);
  fs.writeFileSync(p, `#!/bin/bash\n${body}\n`);
  fs.chmodSync(p, 0o755);
}

function runWrapper(script: string, targets: string[], env: Record<string, string> = {}): { notes: string | null; partialRows: number; status: number | null; stderr: string } {
  const tf = path.join(dir, 'targets.txt');
  fs.writeFileSync(tf, targets.join('\n') + '\n');
  const dbFile = path.join(dir, 'scan.db');
  const r = spawnSync(path.join(SCAN, 'node_modules/.bin/tsx'), [path.join(SCAN, 'src', script), '--targets', tf, '--sqlite', dbFile, '--run-dir', path.join(dir, 'runs')], {
    cwd: dir, encoding: 'utf8', env: { ...process.env, ...env, PATH: `${path.join(dir, 'bin')}:${process.env['PATH']}` },
  });
  const db = new Database(dbFile, { readonly: true });
  const run = db.prepare('SELECT id, notes, finished_at FROM runs ORDER BY id DESC LIMIT 1').get() as { id: number; notes: string | null; finished_at: string | null };
  const n = (db.prepare('SELECT COUNT(*) AS n FROM partial_stamps WHERE run_id = ?').get(run.id) as { n: number }).n;
  db.close();
  return { notes: run.notes, partialRows: n, status: r.status, stderr: r.stderr };
}

const wpJson = (extra: Record<string, unknown>) => JSON.stringify({
  interesting_findings: [{ to_s: 'readme', type: 'readme', url: 'https://a.example/readme.html' }], ...extra,
});
const wpFake = (json: string, code: number) => fake('wpscan', `cat <<'EOF'\n${json}\nEOF\nexit ${code}`);
const API_OK = { vuln_api: { plan: 'free', requests_done_during_scan: 1, requests_remaining: 20 } };

describe('wpscan partial runs', () => {
  it.each([
    ['an exception exit', 3, wpJson(API_OK)],
    ['an unfinished scan exit', 4, wpJson(API_OK)],
    ['an interrupt exit', 2, wpJson(API_OK)],
    ['a scan_aborted key on exit 0', 0, wpJson({ ...API_OK, scan_aborted: 'boom' })],
    ['an exhausted vuln api quota', 0, wpJson({ vuln_api: { plan: 'free', requests_done_during_scan: 25, requests_remaining: 0 } })],
    ['a vuln api http_error', 0, wpJson({ vuln_api: { http_error: 'HTTP 500' } })],
    ['a missing api token', 0, wpJson({ vuln_api: { error: 'No WPScan API Token given' } })],
  ])('is partial on %s', (_n, code, json) => {
    wpFake(json, code);
    const r = runWrapper('wpscan.ts', ['a.example']);
    expect(r.notes).toContain('partial run: 1 target(s) incomplete');
    expect(r.partialRows).toBeGreaterThan(0);
  });

  it('exit 5 (vulnerable) with a working api is complete', () => {
    wpFake(wpJson(API_OK), 5);
    const r = runWrapper('wpscan.ts', ['a.example']);
    expect(r.notes ?? '').not.toContain('partial');
    expect(r.partialRows).toBe(0);
  });

  it('exit 0 with a working api is complete', () => {
    wpFake(wpJson(API_OK), 0);
    const r = runWrapper('wpscan.ts', ['a.example']);
    expect(r.notes ?? '').not.toContain('partial');
    expect(r.partialRows).toBe(0);
  });

  it('a failure that wrote no rows is not partial', () => {
    wpFake(JSON.stringify({ scan_aborted: 'boom' }), 3);
    const r = runWrapper('wpscan.ts', ['a.example']);
    expect(r.notes ?? '').not.toContain('partial');
  });
});

describe('takeover partial runs', () => {
  const row = (host: string) => JSON.stringify({ 'template-id': 'x-takeover', info: { name: 'takeover', severity: 'high' }, host, 'matched-at': host });
  const nuclei = (rows: string[], stderr: string, code = 0) => fake('nuclei',
    `out=; while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\nprintf '%s\\n' ${rows.map((x) => `'${x}'`).join(' ')} > "$out"\necho '${stderr}' >&2\nexit ${code}`);

  it('is partial when a host nuclei skipped has rows', () => {
    nuclei([row('a.example')], '[INF] Skipped a.example from target list as found unresponsive 30 times');
    const r = runWrapper('takeover.ts', ['a.example', 'b.example']);
    expect(r.notes).toContain('partial run: 1 skipped host(s)');
    expect(r.partialRows).toBeGreaterThan(0);
  });

  it('is complete when the skipped host wrote no rows', () => {
    nuclei([row('b.example')], '[INF] Skipped a.example from target list as found unresponsive 30 times');
    const r = runWrapper('takeover.ts', ['a.example', 'b.example']);
    expect(r.notes ?? '').not.toContain('partial');
    expect(r.partialRows).toBe(0);
  });

  it('is complete on a clean exit', () => {
    nuclei([row('a.example')], '');
    const r = runWrapper('takeover.ts', ['a.example']);
    expect(r.notes ?? '').not.toContain('partial');
  });
});

describe('testssl partial runs', () => {
  const recs = (extra: unknown[]) => JSON.stringify([
    { id: 'TLS1', severity: 'HIGH', finding: 'offered' },
    { id: 'cipherlist_NULL', severity: 'CRITICAL', finding: 'offered' },
    ...extra,
  ]);
  const testssl = (json: string, code: number) => fake('testssl.sh',
    `out=; while [ $# -gt 0 ]; do [ "$1" = --jsonfile ] && out=$2; shift; done\ncat > "$out" <<'EOF'\n${json}\nEOF\nexit ${code}`);

  it.each([
    ['a scanProblem FATAL record', recs([{ id: 'scanProblem', severity: 'FATAL', finding: 'Scan interrupted' }]), 246],
    ['a Scan interrupted scanTime', recs([{ id: 'scanTime', severity: 'INFO', finding: 'Scan interrupted' }]), 0],
    ['an ERR_* exit code', recs([]), 250],
  ])('is partial on %s', (_n, json, code) => {
    testssl(json, code);
    const r = runWrapper('testssl.ts', ['a.example']);
    expect(r.notes).toContain('partial run: 1 host(s) incomplete');
    expect(r.partialRows).toBeGreaterThan(0);
  });

  it('is complete on a finished scan, even with findings exit codes', () => {
    testssl(recs([{ id: 'scanTime', severity: 'INFO', finding: '42' }]), 2);
    const r = runWrapper('testssl.ts', ['a.example']);
    expect(r.notes ?? '').not.toContain('partial');
    expect(r.partialRows).toBe(0);
  });
});
