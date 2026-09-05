import { describe, it, expect } from 'vitest';
import { resolveDbArg, isDbFlag, DEFAULT_DB } from '../src/lib/db-arg.js';

// argv as the entrypoints see it: [node, script, ...flags]
const argv = (...flags: string[]) => ['node', 'script', ...flags];

describe('isDbFlag', () => {
  it('recognizes both the canonical flag and the alias', () => {
    expect(isDbFlag('--sqlite')).toBe(true);
    expect(isDbFlag('--db')).toBe(true);
  });
  it('rejects everything else', () => {
    for (const a of ['--sql', '--database', '-d', 'scan.db', '--sqlite=x', '']) {
      expect(isDbFlag(a)).toBe(false);
    }
  });
});

describe('resolveDbArg', () => {
  it('defaults to scan.db when no flag is present', () => {
    expect(resolveDbArg(argv('--top', '10'))).toBe(DEFAULT_DB);
    expect(DEFAULT_DB).toBe('scan.db');
  });

  it('honors a custom fallback', () => {
    expect(resolveDbArg(argv('--top', '10'), 'other.db')).toBe('other.db');
  });

  // The exact regression this guards: --sqlite must not be silently ignored.
  it('resolves --sqlite and --db to the identical path', () => {
    const viaSqlite = resolveDbArg(argv('--sqlite', 'scan-e2e.db'));
    const viaDb = resolveDbArg(argv('--db', 'scan-e2e.db'));
    expect(viaSqlite).toBe('scan-e2e.db');
    expect(viaDb).toBe('scan-e2e.db');
    expect(viaSqlite).toBe(viaDb);
  });

  it('picks up the flag regardless of position among other args', () => {
    expect(resolveDbArg(argv('--breakdown', '--sqlite', 'a.db', '--top', '5'))).toBe('a.db');
    expect(resolveDbArg(argv('--top', '5', '--db', 'b.db'))).toBe('b.db');
  });

  it('last occurrence wins', () => {
    expect(resolveDbArg(argv('--db', 'first.db', '--sqlite', 'second.db'))).toBe('second.db');
  });

  it('ignores a trailing flag with no value', () => {
    expect(resolveDbArg(argv('--sqlite'))).toBe(DEFAULT_DB);
  });
});
