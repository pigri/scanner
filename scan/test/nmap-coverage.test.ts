import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';
import { currentFindingsSelect, findingsRuleOpts } from '../src/lib/current-findings.js';

const scanDir = path.resolve(__dirname, '..');
const tsx = path.join(scanDir, 'node_modules', '.bin', 'tsx');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

const HOST = 'www.example.test';
const XML = `<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="${HOST}" type="user"/><hostname name="ptr.example.net" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="nginx" version="1.18.0"/>
<script id="vulners" output="x"><table key="cpe:/a:nginx:nginx:1.18.0"><table><elem key="id">CVE-2021-23017</elem><elem key="cvss">7.7</elem><elem key="type">cve</elem><elem key="is_exploit">false</elem></table></table></script>
</port></ports></host></nmaprun>`;

// A stand-in nmap that writes XML to the file after -oX and exits with EXIT.
const fakeNmap = (xml: string, exit: number) => `#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-oX" ]; then out="$2"; fi
  shift
done
cat > "$out" <<'XML'
${xml}
XML
exit ${exit}
`;

function runNmap(opts: { dir?: string; xml?: string; exit?: number; extra?: string[]; noSqlite?: boolean; seed?: (db: ReturnType<typeof openDb>) => void }): Promise<{ code: number | null; stderr: string; db: string; dir: string }> {
  const dir = opts.dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'nmap-cov-'));
  if (!opts.dir) dirs.push(dir);
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, 'nmap'), fakeNmap(opts.xml ?? XML, opts.exit ?? 0), { mode: 0o755 });
  const dbPath = path.join(dir, 'scan.db');
  const seedDb = openDb(dbPath);
  opts.seed?.(seedDb);
  seedDb.close();
  const targets = path.join(dir, 'targets.txt');
  fs.writeFileSync(targets, `${HOST}\n`);
  return new Promise((resolve) => {
    const child = spawn(tsx, ['src/nmap.ts', '--targets', targets, ...(opts.noSqlite ? [] : ['--sqlite', dbPath]),
      '--run-dir', path.join(dir, 'runs'), '--', ...(opts.extra ?? ['--vulners'])], {
      cwd: scanDir,
      env: { PATH: `${bin}:${process.env['PATH'] ?? ''}`, HOME: dir },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (b) => (stderr += b));
    const timer = setTimeout(() => child.kill('SIGKILL'), 90_000);
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stderr, db: dbPath, dir }); });
  });
}

const coverage = (dbPath: string) => {
  const db = openDb(dbPath);
  const cov = db.raw.prepare('SELECT target, tool, seen_at, run_id FROM tool_coverage').all() as
    { target: string; tool: string; seen_at: string; run_id: number }[];
  const f = db.raw.prepare("SELECT target, seen_at, run_id FROM findings WHERE tool = 'nmap-vulners'").all() as
    { target: string; seen_at: string; run_id: number }[];
  db.close();
  return { cov, findings: f };
};

const OLD = '2026-01-01T00:00:00.000Z';
const priorFinding = (port: number) => (db: ReturnType<typeof openDb>) => db.insertFinding({
  tool: 'nmap-vulners', target: HOST, category: 'cve', severity: 'high', title: `CVE-2020-0001 on nginx (${HOST}:${port})`,
  cve: 'CVE-2020-0001', matched_at: `${HOST}:${port}`, meta: { port },
}, OLD, null);

describe('nmap vulners coverage', () => {
  it('records coverage with the same target, stamp and run as its findings', async () => {
    const r = await runNmap({});
    expect(r.code, r.stderr).toBe(0);
    const { cov, findings } = coverage(r.db);
    expect(findings).toHaveLength(1);
    expect(cov).toEqual([{ target: findings[0]!.target, tool: 'nmap-vulners', seen_at: findings[0]!.seen_at, run_id: findings[0]!.run_id }]);
    expect(cov[0]!.target).toBe(HOST);
  }, 100_000);

  it('records nothing on a non-zero exit', async () => {
    const r = await runNmap({ exit: 1 });
    expect(coverage(r.db).cov).toEqual([]);
  }, 100_000);

  it('records nothing without --vulners', async () => {
    const r = await runNmap({ extra: [] });
    expect(r.code, r.stderr).toBe(0);
    expect(coverage(r.db).cov).toEqual([]);
  }, 100_000);

  it('records nothing for a host nmap timed out on', async () => {
    const r = await runNmap({ xml: XML.replace('<host>', '<host starttime="1" endtime="2" timedout="true">') });
    expect(r.code, r.stderr).toBe(0);
    expect(coverage(r.db).cov).toEqual([]);
  }, 100_000);

  it('records nothing when a port-narrowing flag is given', async () => {
    const forms = [
      ['--top-ports', '100'], ['--top-ports=100'], ['-top-ports', '100'], ['--no-db-ports'], ['--db-ports', '80'],
      ['-p', '80'], ['-p80'], ['-F'], ['--ports=80'], ['-exclude-ports', '22'], ['--exclude-ports=22'], ['--port-ratio=0.5'],
    ];
    for (const extra of forms.map((f) => ['--vulners', ...f])) {
      const r = await runNmap({ extra });
      expect(r.code, r.stderr).toBe(0);
      expect(coverage(r.db).cov, extra.join(' ')).toEqual([]);
    }
  }, 100_000);

  it('records nothing when a port with an open finding is no longer open', async () => {
    const r = await runNmap({ seed: priorFinding(8080) });
    expect(r.code, r.stderr).toBe(0);
    expect(coverage(r.db).cov).toEqual([]);
  }, 100_000);

  it('records coverage when the port of the open finding is still open', async () => {
    const r = await runNmap({ seed: priorFinding(80) });
    expect(r.code, r.stderr).toBe(0);
    expect(coverage(r.db).cov.map((c) => c.target)).toEqual([HOST]);
  }, 100_000);

  it('ignores a prior finding on a closed port once a later run already superseded it', async () => {
    const r = await runNmap({ seed: (db) => { priorFinding(8080)(db); db.recordCoverage('nmap-vulners', [HOST], '2026-01-02T00:00:00.000Z', null); } });
    const { cov, findings: all } = coverage(r.db);
    const findings = all.filter((f) => f.run_id !== null);
    // The seeded stamp (2026-01-02, no run) must have been replaced by this run's.
    expect(cov).toEqual([{ target: HOST, tool: 'nmap-vulners', seen_at: findings[0]!.seen_at, run_id: findings[0]!.run_id }]);
    expect(cov[0]!.seen_at > '2026-01-02T00:00:00.000Z').toBe(true);
    expect(cov[0]!.run_id).not.toBeNull();
  }, 100_000);

  it('keeps the run and skips coverage when reading the open findings fails', async () => {
    const r = await runNmap({
      seed: (db) => db.raw.prepare(
        "INSERT INTO findings(tool, target, title, meta_json, seen_at) VALUES ('nmap-vulners', ?, 'CVE-2020-0001 on nginx', 'not json', ?)",
      ).run(HOST, OLD),
    });
    expect(r.code, r.stderr).toBe(0);
    const { cov, findings } = coverage(r.db);
    expect(cov).toEqual([]);
    expect(findings).toHaveLength(2);
  }, 100_000);

  it('records no coverage when storing a finding fails, and the run fails', async () => {
    const r = await runNmap({ seed: (db) => db.raw.exec("CREATE TRIGGER t_lock BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'database is locked'); END") });
    expect(r.code).toBe(1);
    expect(coverage(r.db).cov).toEqual([]);
  }, 100_000);
});

describe('nmap partial runs', () => {
  const resolved = (dbPath: string, title: string) => {
    const db = openDb(dbPath);
    const rows = db.raw.prepare(currentFindingsSelect(findingsRuleOpts(db.raw))).all() as { title: string; resolved: number }[];
    db.close();
    return rows.find((r) => r.title === title)?.resolved;
  };
  const prior = (db: ReturnType<typeof openDb>) => priorFinding(8080)(db);
  const title = `CVE-2020-0001 on nginx (${HOST}:8080)`;

  it('keeps a prior finding open when nmap exits 1', async () => {
    const r = await runNmap({ exit: 1, seed: prior });
    expect(resolved(r.db, title)).toBe(0);
  }, 100_000);

  const TIMED_OUT = XML.replace('<host>', '<host starttime="1" endtime="2" timedout="true">');
  const state = (dbPath: string) => {
    const db = openDb(dbPath);
    const marks = db.raw.prepare('SELECT run_id FROM partial_stamps').all() as { run_id: number }[];
    const notes = (db.raw.prepare('SELECT notes FROM runs ORDER BY id DESC LIMIT 1').get() as { notes: string | null }).notes;
    db.close();
    return { marks, notes };
  };

  it('keeps a prior finding open and marks the run partial when a host timed out', async () => {
    const r = await runNmap({ xml: TIMED_OUT, seed: prior });
    expect(r.code, r.stderr).toBe(0);
    expect(resolved(r.db, title)).toBe(0);
    const st = state(r.db);
    expect(st.marks).toHaveLength(1);
    expect(st.notes).toContain('partial run: 1 timed-out host(s)');
  }, 100_000);

  it('keeps a prior finding open and marks the run partial when the port scan was narrowed', async () => {
    const r = await runNmap({ extra: ['--vulners', '-p', '80'], seed: prior });
    expect(r.code, r.stderr).toBe(0);
    expect(resolved(r.db, title)).toBe(0);
    const st = state(r.db);
    expect(st.marks).toHaveLength(1);
    expect(st.notes).toContain('partial run: narrowed port scan');
  }, 100_000);

  it('does not cover a host in a clean run that follows a partial one', async () => {
    const first = await runNmap({ exit: 1, seed: prior });
    const second = await runNmap({ dir: first.dir });
    expect(second.code, second.stderr).toBe(0);
    expect(coverage(second.db).cov).toEqual([]);
  }, 100_000);

  it('resolves the prior finding when nmap exits 0 (control)', async () => {
    const r = await runNmap({ seed: prior });
    expect(r.code, r.stderr).toBe(0);
    expect(resolved(r.db, title)).toBe(1);
  }, 100_000);
});
