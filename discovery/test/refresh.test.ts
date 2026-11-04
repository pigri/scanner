import { describe, it, expect } from 'vitest';
import { parseArgs } from '../src/refresh.js';

describe('refresh parseArgs', () => {
  it('defaults expand to false', () => {
    expect(parseArgs(['node', 'refresh']).expand).toBe(false);
  });

  it('--expand sets expand to true', () => {
    expect(parseArgs(['node', 'refresh', '--expand']).expand).toBe(true);
  });
});
