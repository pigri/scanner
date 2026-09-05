import { describe, it, expect } from 'vitest';
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
