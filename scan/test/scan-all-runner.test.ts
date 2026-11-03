import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanAllArgs, scanAllEnv, scanChildEnv, TUNED_SCAN_FLAGS } from '../src/lib/scan-all-runner.js';

const base = { targets: 'top100.txt', scope: 'scope.txt', sqlite: 'scan.db' };

describe('scanAllArgs', () => {
  it('builds the tsx scan-all invocation', () => {
    expect(scanAllArgs(base)).toEqual([
      'tsx', 'src/scan-all.ts',
      '--targets', 'top100.txt',
      '--scope', 'scope.txt',
      '--sqlite', 'scan.db',
    ]);
  });
});

describe('scanAllEnv', () => {
  it('appends goBin to PATH', () => {
    const env = scanAllEnv({ ...base, goBin: '/opt/go/bin' }, { PATH: '/usr/bin' });
    expect(env['PATH']).toBe('/usr/bin:/opt/go/bin');
  });

  it('does not duplicate goBin already on PATH', () => {
    const env = scanAllEnv({ ...base, goBin: '/opt/go/bin' }, { PATH: '/usr/bin:/opt/go/bin' });
    expect(env['PATH']).toBe('/usr/bin:/opt/go/bin');
  });

  it('sets stage flags from opts when absent in base env', () => {
    const env = scanAllEnv(
      { ...base, skip: 'httpx,nmap', testsslFlags: '--live-only', nucleiFlags: '-c 50' },
      { PATH: '/usr/bin' }
    );
    expect(env['SKIP']).toBe('httpx,nmap');
    expect(env['TESTSSL_FLAGS']).toBe('--live-only');
    expect(env['NUCLEI_FLAGS']).toBe('-c 50');
  });

  it('lets an existing env value win over the opts default (${VAR:-default})', () => {
    const env = scanAllEnv(
      { ...base, nucleiFlags: '-c 50' },
      { PATH: '/usr/bin', NUCLEI_FLAGS: '-c 10 --custom' }
    );
    expect(env['NUCLEI_FLAGS']).toBe('-c 10 --custom');
  });

  it('treats an empty-string env value as unset and applies the default', () => {
    const env = scanAllEnv({ ...base, skip: 'httpx' }, { PATH: '/usr/bin', SKIP: '' });
    expect(env['SKIP']).toBe('httpx');
  });

  it('derives goBin from HOME when not supplied', () => {
    const env = scanAllEnv(base, { PATH: '/usr/bin', HOME: '/home/x' });
    expect(env['PATH']).toBe('/usr/bin:/home/x/go/bin');
  });
});

describe('scanChildEnv (worker self-sufficiency)', () => {
  it('applies the tuned live-only defaults when env is unset', () => {
    const env = scanChildEnv({ ...TUNED_SCAN_FLAGS }, { PATH: '/usr/bin', HOME: '/home/x' });
    expect(env['TESTSSL_FLAGS']).toBe('--live-only --concurrency 6');
    expect(env['NUCLEI_FLAGS']).toContain('--live-only');
    expect(env['PATH']).toBe('/usr/bin:/home/x/go/bin'); // Go tools resolvable
  });

  it('lets an exported env var override the tuned default', () => {
    const env = scanChildEnv({ ...TUNED_SCAN_FLAGS }, { PATH: '/usr/bin', NUCLEI_FLAGS: '-c 5' });
    expect(env['NUCLEI_FLAGS']).toBe('-c 5');
  });
});

describe('scan-all stage order', () => {
  // A fake `npx` on PATH logs START/END per step, so the real scan-all.ts
  // orchestration runs without any scanner installed.
  const runPipeline = (skip: string): string[] => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-all-order-'));
    try {
      const log = path.join(dir, 'order.log');
      const bin = path.join(dir, 'bin');
      fs.mkdirSync(bin);
      fs.writeFileSync(path.join(bin, 'npx'), [
        '#!/bin/sh',
        'name=$(basename "$2" .ts)',
        `echo "START $name" >> "${log}"`,
        '[ "$name" = cve-rollup ] && sleep 1',
        '[ "$name" = nmap ] && sleep 1',
        '[ "$name" = version-match ] && sleep 1',
        `echo "END $name" >> "${log}"`,
        '',
      ].join('\n'), { mode: 0o755 });
      const targets = path.join(dir, 'targets.txt');
      fs.writeFileSync(targets, 'example.com\n');
      const r = spawnSync(
        path.resolve('node_modules/.bin/tsx'),
        ['src/scan-all.ts', '--targets', targets, '--sqlite', path.join(dir, 'scan.db')],
        { env: { ...process.env, PATH: `${bin}:${process.env['PATH']}`, SKIP: skip }, encoding: 'utf8' },
      );
      expect(r.status).toBe(0);
      return fs.readFileSync(log, 'utf8').trim().split('\n');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };

  const STAGE2 = 'httpx,nmap,rustscan,naabu,nmap-udp,masscan,nuclei,takeover,testssl,gowitness,katana,gau,waybackurls,dnsx,checkdmarc';
  const STAGE3 = 'wpscan,nuclei-urls,kiterunner,secrets,headers,ffuf,content-sigs,sslyze,cname-takeover,smb';

  it('runs version-match after stage 2 finishes and before cve-rollup starts', () => {
    const stage2NoNmap = STAGE2.replace('nmap,', '');
    const order = runPipeline(`${stage2NoNmap},${STAGE3},data-integrity`);
    expect(order).toEqual([
      'START nmap', 'END nmap',
      'START version-match', 'END version-match',
      'START cve-rollup', 'END cve-rollup',
    ]);
  });

  it('SKIP=version-match turns it off', () => {
    const order = runPipeline(`${STAGE2},${STAGE3},data-integrity,version-match`);
    expect(order).toEqual(['START cve-rollup', 'END cve-rollup']);
  });

  it('starts data-integrity only after cve-rollup has finished', () => {
    const order = runPipeline(`${STAGE2},${STAGE3},version-match`);
    expect(order).toEqual([
      'START cve-rollup', 'END cve-rollup',
      'START data-integrity', 'END data-integrity',
    ]);
  });

  it('SKIP=data-integrity still skips it', () => {
    const order = runPipeline(`${STAGE2},${STAGE3},data-integrity,version-match`);
    expect(order).toEqual(['START cve-rollup', 'END cve-rollup']);
  });
});
