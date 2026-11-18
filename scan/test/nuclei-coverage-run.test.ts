import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';

const scanDir = path.resolve(__dirname, '..');
const tsx = path.join(scanDir, 'node_modules', '.bin', 'tsx');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

const NOW = '2026-01-01T00:00:00.000Z';
const HOST = 'www.example.test';
const MISSED = 'skipped.example.test';

// A stand-in nuclei: copies $FAKE_ROWS to the file after -o and exits $FAKE_EXIT.
const FAKE_NUCLEI = `#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; fi
  if [ "$1" = "-elog" ]; then elog="$2"; fi
  shift
done
cp "$FAKE_ROWS" "$out"
[ -n "$FAKE_ELOG" ] && [ -n "$elog" ] && cp "$FAKE_ELOG" "$elog"
[ -n "$FAKE_STDERR" ] && printf '%s\\n' "$FAKE_STDERR" >&2
exit "\${FAKE_EXIT:-0}"
`;

const row = (type: string, matchedAt: string, host = HOST) => JSON.stringify({
  'template-id': 't-' + type, type, info: { name: 'T', severity: 'info' }, host, 'matched-at': matchedAt,
});

function runNuclei(extra: string[], rows: string[], exit = 0, opt: { trigger?: string; stderrLines?: string[]; elog?: string[] } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nuclei-cov-'));
  dirs.push(dir);
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'nuclei'), FAKE_NUCLEI, { mode: 0o755 });
  const rowsFile = path.join(dir, 'rows.jsonl');
  fs.writeFileSync(rowsFile, rows.join('\n') + '\n');
  const elogFile = path.join(dir, 'elog.jsonl');
  if (opt.elog) fs.writeFileSync(elogFile, opt.elog.join('\n') + '\n');
  const dbPath = path.join(dir, 'scan.db');
  const db = openDb(dbPath);
  for (const h of [HOST, MISSED]) {
    db.raw.prepare('INSERT INTO http_probes(target, url, status_code, seen_at) VALUES (?,?,?,?)').run(h, `https://${h}/`, 200, NOW);
    db.raw.prepare('INSERT INTO discovered_urls(target, url, source, status, seen_at) VALUES (?,?,?,?,?)')
      .run(h, `https://${h}/app/login`, 'katana', 200, NOW);
  }
  if (opt.trigger) db.raw.exec(opt.trigger);
  db.close();
  const targets = path.join(dir, 'targets.txt');
  fs.writeFileSync(targets, `${HOST}\n${MISSED}\n`);
  return new Promise<{ code: number | null; stderr: string; db: string }>((resolve) => {
    const child = spawn(tsx, ['src/nuclei.ts', '--targets', targets, '--sqlite', dbPath,
      '--run-dir', path.join(dir, 'runs'), '--', '--live-only', ...extra], {
      cwd: scanDir,
      env: { PATH: `${bin}:${process.env['PATH'] ?? ''}`, HOME: dir, FAKE_ROWS: rowsFile, FAKE_EXIT: String(exit), FAKE_ELOG: opt.elog ? elogFile : '', FAKE_STDERR: (opt.stderrLines ?? []).join('\n') },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (b) => (stderr += b));
    const timer = setTimeout(() => child.kill('SIGKILL'), 90_000);
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stderr, db: dbPath }); });
  });
}

const coverage = (dbPath: string) => {
  const db = openDb(dbPath);
  const rows = db.raw.prepare('SELECT target, tool, seen_at, run_id FROM tool_coverage ORDER BY target').all() as
    { target: string; tool: string; seen_at: string; run_id: number }[];
  const seen = db.raw.prepare('SELECT DISTINCT seen_at AS at FROM findings').all() as { at: string }[];
  const runIds = db.raw.prepare('SELECT DISTINCT run_id AS id FROM findings').all() as { id: number }[];
  const notes = db.raw.prepare("SELECT notes FROM runs WHERE tool LIKE 'nuclei%'").all() as { notes: string | null }[];
  db.close();
  return { rows, findingAts: seen.map((s) => s.at), findingRunIds: runIds.map((x) => x.id), notes: notes.map((n) => n.notes) };
};

describe('nuclei coverage', () => {
  it('records nothing on the host pass', async () => {
    const r = await runNuclei([], [row('ssl', `${HOST}:443`)]);
    expect(r.code, r.stderr).toBe(0);
    expect(coverage(r.db).rows).toEqual([]);
  }, 100_000);

  it('records only the host with a non-dns row, under nuclei-url, with the findings\' stamp', async () => {
    const r = await runNuclei(['--from-urls'], [
      row('ssl', `${HOST}:443`),
      row('dns', MISSED, MISSED),
    ]);
    expect(r.code, r.stderr).toBe(0);
    const c = coverage(r.db);
    expect(c.rows).toHaveLength(1);
    expect(c.rows[0]).toMatchObject({ target: HOST, tool: 'nuclei-url' });
    expect(c.findingAts).toHaveLength(1);
    expect(c.rows[0]!.seen_at).toBe(c.findingAts[0]);
    expect(c.findingRunIds).toHaveLength(1);
    expect(c.rows[0]!.run_id).toBe(c.findingRunIds[0]);
    expect(c.rows[0]!.seen_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  }, 100_000);

  it('covers a host through a URL-sample row', async () => {
    const r = await runNuclei(['--from-urls'], [row('http', `https://${HOST}/app/login`)]);
    expect(coverage(r.db).rows.map((x) => x.target)).toEqual([HOST]);
  }, 100_000);

  it('records nothing when nuclei exits non-zero', async () => {
    const r = await runNuclei(['--from-urls'], [row('ssl', `${HOST}:443`)], 2);
    expect(coverage(r.db).rows).toEqual([]);
  }, 100_000);

  it('records nothing for a host whose findings failed to store', async () => {
    const trigger = `CREATE TRIGGER fail_ins BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'database is locked'); END;`;
    const r = await runNuclei(['--from-urls'], [row('ssl', `${HOST}:443`)], 0, { trigger });
    expect(r.code, r.stderr).toBe(0);
    expect(coverage(r.db).rows).toEqual([]);
  }, 100_000);

  it('records nothing for a host that nuclei reports as skipped', async () => {
    const r = await runNuclei(['--from-urls'], [row('ssl', `${HOST}:443`), row('ssl', `${MISSED}:443`, MISSED)], 0,
      { stderrLines: [`[INF] Skipped ${MISSED}:443 from target list as found unresponsive 30 times`] });
    expect(coverage(r.db).rows.map((x) => x.target)).toEqual([HOST]);
  }, 100_000);

  it('records nothing for a host whose row failed before its insert', async () => {
    const bad = JSON.stringify({ 'template-id': 't', type: 'ssl', info: { classification: { 'cve-id': [5] } }, host: MISSED, 'matched-at': `${MISSED}:443` });
    const r = await runNuclei(['--from-urls'], [row('ssl', `${HOST}:443`), bad]);
    expect(coverage(r.db).rows.map((x) => x.target)).toEqual([HOST]);
  }, 100_000);

  it('records nothing for a host whose error log reaches the -mhe limit', async () => {
    const errs = Array.from({ length: 30 }, (_, i) => JSON.stringify({ template: 't.yaml', type: 'http', input: `https://${MISSED}/p${i}`, address: `${MISSED}:443`, error: 'cause="connection reset by peer"', kind: 'unknown-error' }));
    const r = await runNuclei(['--from-urls'], [row('ssl', `${HOST}:443`), row('ssl', `${MISSED}:443`, MISSED)], 0, { elog: errs });
    expect(coverage(r.db).rows.map((x) => x.target)).toEqual([HOST]);
  }, 100_000);

  it('records nothing for a host whose off-host match failed to store', async () => {
    const trigger = `CREATE TRIGGER fail_sso BEFORE INSERT ON findings WHEN NEW.matched_at LIKE '%sso.example.test%' BEGIN SELECT RAISE(ABORT, 'database is locked'); END;`;
    const r = await runNuclei(['--from-urls'], [row('ssl', `${HOST}:443`), row('http', 'https://sso.example.test/login', HOST)], 0, { trigger });
    expect(coverage(r.db).rows).toEqual([]);
  }, 100_000);

  it('records no coverage when an output line cannot be parsed, but still stores the findings', async () => {
    const r = await runNuclei(['--from-urls'], [row('ssl', `${HOST}:443`), '{"template-id": truncated']);
    const c = coverage(r.db);
    expect(c.rows).toEqual([]);
    expect(c.findingAts).toHaveLength(1);
    expect(c.notes.join(';')).toContain('coverage skipped: 1 unparseable nuclei row');
  }, 100_000);

  it('passes -elog to the URL pass only', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nuclei-cov-args-'));
    dirs.push(dir);
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'nuclei'), '#!/bin/sh\necho "$@" > "$ARGS_OUT"\n', { mode: 0o755 });
    const targets = path.join(dir, 'targets.txt');
    fs.writeFileSync(targets, `${HOST}\n`);
    const dbPath = path.join(dir, 'scan.db');
    const db = openDb(dbPath);
    db.raw.prepare('INSERT INTO discovered_urls(target, url, source, status, seen_at) VALUES (?,?,?,?,?)').run(HOST, `https://${HOST}/a`, 'katana', 200, NOW);
    db.close();
    const argsOut = path.join(dir, 'args.txt');
    for (const [flag, expected] of [['--from-urls', true], ['--urls-per-host', false]] as const) {
      const extra = flag === '--from-urls' ? [flag] : [flag, '5'];
      await new Promise<void>((resolve) => {
        const child = spawn(tsx, ['src/nuclei.ts', '--targets', targets, '--sqlite', dbPath, '--run-dir', path.join(dir, 'runs'), '--', ...extra], {
          cwd: scanDir, env: { PATH: `${bin}:${process.env['PATH'] ?? ''}`, HOME: dir, ARGS_OUT: argsOut }, stdio: 'ignore',
        });
        child.on('close', () => resolve());
      });
      expect(fs.readFileSync(argsOut, 'utf8').includes('-elog')).toBe(expected);
    }
  }, 100_000);
});
