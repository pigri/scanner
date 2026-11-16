import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../deploy');
const UNITS = ['scan-worker.service', 'scan-worker@.service', 'scan-worker-hu@.service'];
const WORKER_GRACE_S = 60; // STOP_GRACE_MS in src/worker.ts

const read = (u: string): string => fs.readFileSync(path.join(dir, u), 'utf8');
const execStart = (u: string): string => read(u).split('\n').find((l) => l.startsWith('ExecStart=')) ?? '';

describe.each(UNITS)('%s stop path', (unit) => {
  it('drops privileges with setpriv, which execs in place', () => {
    const l = execStart(unit);
    expect(l).toContain('/usr/bin/setpriv');
    expect(l).toMatch(/--reuid=%u/);
    expect(l).toMatch(/--regid=%g/);
    expect(l).toContain('--init-groups');
    expect(l).toContain('HOME=%h');
  });

  it('has no runuser or su, whose watching parent SIGKILLs the worker 2 s after SIGTERM', () => {
    const l = execStart(unit);
    expect(l).not.toMatch(/runuser/);
    expect(l).not.toMatch(/(^|[\s/])su\s/);
  });

  it('uses KillMode=mixed and a stop timeout longer than the worker grace', () => {
    const t = read(unit);
    expect(t).toMatch(/^KillMode=mixed$/m);
    const m = /^TimeoutStopSec=(\d+)$/m.exec(t);
    expect(Number(m?.[1])).toBeGreaterThan(WORKER_GRACE_S);
  });
});
