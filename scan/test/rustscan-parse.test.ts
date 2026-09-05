import { describe, it, expect } from 'vitest';
import { parseRustscanStdout } from '../src/lib/rustscan-parse.js';

describe('parseRustscanStdout', () => {
  it('parses the greppable single-line format', () => {
    const stdout = `
Open 10.0.0.1:22
Open 10.0.0.1:80
10.0.0.1 -> [22,80,443]
10.0.0.2 -> [8443]
`;
    expect(parseRustscanStdout(stdout)).toEqual([
      { ip: '10.0.0.1', port: 22 },
      { ip: '10.0.0.1', port: 80 },
      { ip: '10.0.0.1', port: 443 },
      { ip: '10.0.0.2', port: 8443 },
    ]);
  });

  it('accepts hostnames', () => {
    expect(parseRustscanStdout('foo.example.com -> [22]')).toEqual([
      { ip: 'foo.example.com', port: 22 },
    ]);
  });

  it('ignores banner + noise lines', () => {
    const stdout = `
[~] Automatically increasing ulimit value to 5000.
[!] Notice: Some data left out
1.2.3.4 -> [443]
`;
    expect(parseRustscanStdout(stdout)).toEqual([{ ip: '1.2.3.4', port: 443 }]);
  });

  it('returns [] for empty input', () => {
    expect(parseRustscanStdout('')).toEqual([]);
  });

  it('skips malformed numbers in the port list', () => {
    expect(parseRustscanStdout('9.9.9.9 -> [22,foo,80]')).toEqual([
      { ip: '9.9.9.9', port: 22 },
      { ip: '9.9.9.9', port: 80 },
    ]);
  });
});
