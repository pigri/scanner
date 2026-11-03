import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { openDb } from '../src/lib/db.js';

// Runs the CLI in --dry-run against a throwaway db and returns the count it
// reports for Check 2 (findings.cve rows missing from the cves rollup).
function check2Count(cves: string[]): number {
  const dir = mkdtempSync(path.join(tmpdir(), 'data-integrity-'));
  try {
    const dbPath = path.join(dir, 'scan.db');
    const db = openDb(dbPath);
    const ins = db.raw.prepare(
      `INSERT INTO findings (tool, target, title, cve, seen_at) VALUES ('nmap-vulners', 'a.example.com', 't', ?, '2026-01-01T00:00:00Z')`,
    );
    for (const c of cves) ins.run(c);
    db.raw.close();
    const res = spawnSync('npx', ['tsx', path.resolve('src/data-integrity.ts'), '--sqlite', dbPath, '--dry-run'], { encoding: 'utf8' });
    expect(res.status).toBe(0);
    const m = /\]\s+(\d+)\s+findings\.cve rows not represented in cves rollup/.exec(res.stdout);
    expect(m).not.toBeNull();
    return Number(m![1]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('data-integrity check 2', () => {
  it('does not report non-CVE finding ids as rollup drift', () => {
    expect(check2Count(['PACKETSTORM:ABC123', 'EDB-ID:50123', 'MSF:EXPLOIT-FOO', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'])).toBe(0);
  });

  it('still reports a real CVE finding missing from the rollup', () => {
    expect(check2Count(['CVE-2024-1234', 'PACKETSTORM:ABC123'])).toBe(1);
  });
});
