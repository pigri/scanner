import { describe, it, expect } from 'vitest';
import { classify, converged, type Signals } from '../src/lib/expand-core.js';

const s = (resolves: boolean, ctCorroborated: boolean, wildcardHit: boolean): Signals => ({
  resolves,
  ctCorroborated,
  wildcardHit,
});

describe('classify', () => {
  it('A: CT-corroborated and resolves', () => expect(classify(s(true, true, false))).toBe('A'));
  it('A: CT corroboration wins over wildcard noise', () => expect(classify(s(true, true, true))).toBe('A'));
  it('B: CT-corroborated but NXDOMAIN', () => expect(classify(s(false, true, false))).toBe('B'));
  it('B: CT-corroborated, no resolve, wildcard flag irrelevant', () => expect(classify(s(false, true, true))).toBe('B'));
  it('C: resolves, no CT, not wildcard', () => expect(classify(s(true, false, false))).toBe('C'));
  it('D: resolves, no CT, wildcard hit', () => expect(classify(s(true, false, true))).toBe('D'));
  it('D: no resolve, no CT', () => expect(classify(s(false, false, false))).toBe('D'));
  it('D: no resolve, no CT, wildcard flag', () => expect(classify(s(false, false, true))).toBe('D'));
});

describe('converged', () => {
  it('is true when a pass admitted nothing', () => expect(converged({ admitted: 0 })).toBe(true));
  it('is false when a pass admitted something', () => expect(converged({ admitted: 3 })).toBe(false));
});
