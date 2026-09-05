import { describe, it, expect } from 'vitest';
import { parseNxcLines } from '../src/lib/netexec-parse.js';

describe('parseNxcLines', () => {
  it('parses a successful auth with Pwn3d', () => {
    const line = 'SMB    10.10.10.5     445    HOST     [+] CORP\\admin:P@ss (Pwn3d!)';
    const rows = parseNxcLines(line);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      proto: 'SMB', target: '10.10.10.5', user: 'CORP\\admin', pass: 'P@ss',
      outcome: 'success',
    });
    expect(rows[0]!.privilege).toMatch(/Pwn3d/i);
  });

  it('parses a failed auth', () => {
    const line = 'SMB    10.10.10.5     445    HOST     [-] CORP\\admin:bad STATUS_LOGON_FAILURE';
    const rows = parseNxcLines(line);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      proto: 'SMB', target: '10.10.10.5', user: 'CORP\\admin', pass: 'bad',
      outcome: 'fail', privilege: null,
    });
  });

  it('handles a plain user:pass (no domain)', () => {
    const line = 'SSH    10.10.10.6     22     HOST     [+] root:toor';
    const rows = parseNxcLines(line);
    expect(rows[0]).toMatchObject({ proto: 'SSH', user: 'root', pass: 'toor', outcome: 'success' });
  });

  it('strips ANSI color codes', () => {
    const line = '\x1b[92mSMB\x1b[0m    10.10.10.5     445    HOST     \x1b[92m[+]\x1b[0m CORP\\admin:x (admin)';
    const rows = parseNxcLines(line);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.outcome).toBe('success');
    expect(rows[0]!.privilege).toMatch(/admin/i);
  });

  it('ignores banner / progress lines', () => {
    const stdout = `
SMB     10.10.10.5     445    HOST     [*] Windows 10.0 (name:HOST) (domain:CORP)
SMB     10.10.10.5     445    HOST     [+] CORP\\admin:P@ss (Pwn3d!)
[*] enumerated 1 host
`;
    const rows = parseNxcLines(stdout);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.outcome).toBe('success');
  });

  it('empty input → []', () => {
    expect(parseNxcLines('')).toEqual([]);
  });
});
