import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { parseWpscanStdout, wpscanCve } from '../src/lib/wpscan-parse.js';

const fixture = (name: string): string => fs.readFileSync(path.join(__dirname, 'fixtures/wpscan', name), 'utf8');

describe('parseWpscanStdout', () => {
  it('parses the pretty-printed document of a WordPress target', () => {
    const p = parseWpscanStdout(fixture('wordpress-pretty.json')) as { version: { number: string }; interesting_findings: unknown[] };
    expect(p.version.number).toBe('6.4.2');
    expect(p.interesting_findings).toHaveLength(4);
  });

  it('parses the document of a target that is not WordPress', () => {
    expect(parseWpscanStdout(fixture('not-wordpress-pretty.json'))).toMatchObject({ scan_aborted: expect.any(String) });
  });

  it('skips text before the document', () => {
    expect(parseWpscanStdout('warning: something\n{\n  "a": 1\n}\n')).toEqual({ a: 1 });
  });

  it('throws on output with no JSON object', () => {
    expect(() => parseWpscanStdout('boom\n')).toThrow();
    expect(() => parseWpscanStdout('  \n')).toThrow();
  });
});

describe('wpscanCve', () => {
  it.each([
    [{ references: { cve: ['2014-4663'] } }, 'CVE-2014-4663'],
    [{ references: { cve: '2014-4663' } }, 'CVE-2014-4663'],
    [{ references: { cve: ['CVE-2014-4663'] } }, 'CVE-2014-4663'],
    [{ references: {} }, null],
    [{}, null],
  ])('%j -> %s', (v, want) => { expect(wpscanCve(v)).toBe(want); });
});
