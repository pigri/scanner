import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { classify, loadState, saveState } from '../src/lib/resolve-state.js';

const T = 3;

describe('classify (self-healing phantom policy)', () => {
  it('keeps a resolved host in domains and drops it from state', () => {
    const r = classify({ 'h.gov.hu': 2 }, ['h.gov.hu'], [], T);
    expect(r.domains).toContain('h.gov.hu');
    expect(r.phantoms).not.toContain('h.gov.hu');
    expect(r.state['h.gov.hu']).toBeUndefined();
  });

  it('gives a newly-failing host grace: stays in domains, counter = 1', () => {
    const r = classify({}, [], ['x.gov.hu'], T);
    expect(r.domains).toContain('x.gov.hu');
    expect(r.phantoms).not.toContain('x.gov.hu');
    expect(r.state['x.gov.hu']).toBe(1);
  });

  it('bins a host once it reaches the threshold', () => {
    const r = classify({ 'x.gov.hu': 2 }, [], ['x.gov.hu'], T); // 2 -> 3
    expect(r.phantoms).toContain('x.gov.hu');
    expect(r.domains).not.toContain('x.gov.hu');
    expect(r.state['x.gov.hu']).toBe(3);
  });

  it('keeps a long-dead host binned and keeps incrementing', () => {
    const r = classify({ 'x.gov.hu': 5 }, [], ['x.gov.hu'], T);
    expect(r.phantoms).toContain('x.gov.hu');
    expect(r.state['x.gov.hu']).toBe(6);
  });

  it('self-heals: a binned host that resolves returns and resets', () => {
    const r = classify({ 'x.gov.hu': 9 }, ['x.gov.hu'], [], T);
    expect(r.domains).toContain('x.gov.hu');
    expect(r.phantoms).not.toContain('x.gov.hu');
    expect(r.state['x.gov.hu']).toBeUndefined();
  });

  it('returns sorted, de-duplicated domains (resolved + grace)', () => {
    const r = classify({}, ['b.gov.hu', 'a.gov.hu', 'a.gov.hu'], ['z.gov.hu'], T);
    expect(r.domains).toEqual(['a.gov.hu', 'b.gov.hu', 'z.gov.hu']);
  });

  it('clamps a threshold below 1 so it never mass-bins on first miss with grace', () => {
    // threshold 0 would bin everything immediately; clamp to 1 (one miss = bin,
    // but still one real miss, never zero-miss eviction).
    const r = classify({}, [], ['x.gov.hu'], 0);
    expect(r.phantoms).toContain('x.gov.hu');
    expect(r.state['x.gov.hu']).toBe(1);
  });

  it('resolved wins if a host appears in both lists', () => {
    const r = classify({ 'x.gov.hu': 2 }, ['x.gov.hu'], ['x.gov.hu'], T);
    expect(r.domains).toContain('x.gov.hu');
    expect(r.phantoms).not.toContain('x.gov.hu');
    expect(r.state['x.gov.hu']).toBeUndefined();
  });
});

describe('loadState / saveState', () => {
  it('round-trips and returns {} for a missing or garbage file', () => {
    const f = path.join(os.tmpdir(), `rs-test-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
    expect(loadState(f)).toEqual({});
    saveState(f, { 'a.gov.hu': 2 });
    expect(loadState(f)).toEqual({ 'a.gov.hu': 2 });
    fs.writeFileSync(f, 'not json');
    expect(loadState(f)).toEqual({});
    fs.rmSync(f, { force: true });
  });
});
