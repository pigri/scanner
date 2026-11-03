import { describe, it, expect } from 'vitest';
import { parseArgs, shouldSkip } from '../src/enqueue.js';

const argv = (...a: string[]) => ['node', 'enqueue.ts', '--db', ':memory:', ...a];

describe('parseArgs --include-archived', () => {
  it('defaults to skipping archived hosts', () => {
    expect(parseArgs(argv()).includeArchived).toBe(false);
  });
  it('sets includeArchived', () => {
    expect(parseArgs(argv('--include-archived')).includeArchived).toBe(true);
  });
});

describe('shouldSkip', () => {
  const scanned = new Set(['scanned.example']);
  const archived = new Set(['dead.example']);

  it('skips archived hosts by default', () => {
    const opts = parseArgs(argv());
    expect(shouldSkip('dead.example', opts, scanned, archived)).toBe(true);
    expect(shouldSkip('live.example', opts, scanned, archived)).toBe(false);
  });
  it('--include-archived bypasses the archived skip', () => {
    const opts = parseArgs(argv('--include-archived'));
    expect(shouldSkip('dead.example', opts, scanned, archived)).toBe(false);
  });
  it('skips archived hosts under --requeue unless --include-archived', () => {
    expect(shouldSkip('dead.example', parseArgs(argv('--requeue')), new Set(), archived)).toBe(true);
    expect(shouldSkip('dead.example', parseArgs(argv('--requeue', '--include-archived')), new Set(), archived)).toBe(false);
  });
  it('keeps the scanned skip behaviour', () => {
    expect(shouldSkip('scanned.example', parseArgs(argv()), scanned, archived)).toBe(true);
    expect(shouldSkip('scanned.example', parseArgs(argv('--include-scanned')), scanned, archived)).toBe(false);
  });
});
