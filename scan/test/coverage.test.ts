import { describe, it, expect } from 'vitest';
import { coveredTargets } from '../src/lib/coverage.js';

describe('coveredTargets', () => {
  it('returns targets with at least one outcome and none failed', () => {
    expect(coveredTargets([
      { target: 'a.example', ok: true },
      { target: 'b.example', ok: true },
      { target: 'b.example', ok: false },
      { target: 'c.example', ok: false },
    ])).toEqual(['a.example']);
  });

  it('returns each target once, in first-seen order', () => {
    expect(coveredTargets([
      { target: 'b.example', ok: true },
      { target: 'a.example', ok: true },
      { target: 'b.example', ok: true },
    ])).toEqual(['b.example', 'a.example']);
  });

  it('returns nothing for no outcomes', () => {
    expect(coveredTargets([])).toEqual([]);
  });
});
