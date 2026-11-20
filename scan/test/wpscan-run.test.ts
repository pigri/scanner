import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDb } from '../src/lib/db.js';

const scanDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

// Mimics wpscan 3.8: any WPSCAN_API_TOKEN in the environment, even empty,
// turns the vuln API on, and a bad token aborts the scan.
const FAKE = `#!/bin/sh
printf '%s\\n' "$@" > "$(dirname "$0")/args.txt"
if [ "\${WPSCAN_API_TOKEN+set}" = set ]; then
  echo '{"scan_aborted":"HTTP Error: https://wpscan.com/api/v3/status (status: 401)","target_url":"https://a.example.com/"}'
  exit 4
fi
echo '{"target_url":"https://a.example.com/","users":{"admin":{"id":1,"found_by":"Rss Generator (Passive Detection)"}}}'
exit 0
`;

function runWpscan(token: string): { rows: { title: string }[]; args: string[]; stderr: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wpscan-run-'));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, 'wpscan'), FAKE, { mode: 0o755 });
  fs.writeFileSync(path.join(dir, 'targets.txt'), 'a.example.com\n');
  const dbPath = path.join(dir, 'scan.db');
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/wpscan.ts', '--targets', path.join(dir, 'targets.txt'), '--sqlite', dbPath, '-o', path.join(dir, 'wpscan.jsonl')], {
    cwd: scanDir,
    env: { ...process.env, PATH: `${dir}:${process.env['PATH'] ?? ''}`, WPSCAN_API_TOKEN: token },
    encoding: 'utf8',
  });
  expect(r.status).toBe(0);
  const db = openDb(dbPath);
  const rows = db.raw.prepare("SELECT title FROM findings WHERE tool = 'wpscan'").all() as { title: string }[];
  db.close();
  return { rows, args: fs.readFileSync(path.join(dir, 'args.txt'), 'utf8').trim().split('\n'), stderr: r.stderr };
}

describe('wpscan run', () => {
  it('runs without the vuln API when the token is empty', () => {
    const { rows, args } = runWpscan('');
    expect(rows.map((r) => r.title)).toEqual(['WordPress users (1): admin']);
    expect(args).not.toContain('--api-token');
  });

  it('passes a real token on, and counts the API abort', () => {
    const { args, stderr } = runWpscan('tok123');
    expect(stderr).toContain('wpscan done: 0 ok, 1 aborted, 0 failed');
    expect(args.slice(args.indexOf('--api-token'), args.indexOf('--api-token') + 2)).toEqual(['--api-token', 'tok123']);
  });
});
