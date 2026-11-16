import { describe, it, expect } from 'vitest';
import { sanitizePtrNames, lookupPtrs } from '../src/lib/ptr.js';

const err = (code: string): Error => Object.assign(new Error(code), { code });

describe('sanitizePtrNames', () => {
  it('lowercases, strips one trailing dot and keeps order', () => {
    expect(sanitizePtrNames(['Host-1.Example.NET.', 'b.example'])).toEqual(['host-1.example.net', 'b.example']);
  });
  it('strips only one trailing dot', () => {
    expect(sanitizePtrNames(['a.example..'])).toEqual([]);
  });
  it('drops invalid labels', () => {
    expect(sanitizePtrNames(['-a.example', 'a-.example', 'a..example', '.example', '', 'a b.example', 'a_b.example', 'ü.example'])).toEqual([]);
  });
  it('drops overlong labels and names', () => {
    const l63 = 'a'.repeat(63);
    expect(sanitizePtrNames([`${l63}.example`])).toEqual([`${l63}.example`]);
    expect(sanitizePtrNames([`${'a'.repeat(64)}.example`])).toEqual([]);
    const long = Array(5).fill('a'.repeat(50)).join('.');
    expect(long.length).toBeGreaterThan(253);
    expect(sanitizePtrNames([long])).toEqual([]);
    const ok = [...Array(3).fill('a'.repeat(63)), 'b'.repeat(61)].join('.');
    expect(ok.length).toBe(253);
    expect(sanitizePtrNames([ok])).toEqual([ok]);
  });
  it('drops control characters and markup', () => {
    expect(sanitizePtrNames(['a\u0000b.example', 'a\n.example', '<script>alert(1)</script>', 'x.example"><img', 'ok.example'])).toEqual(['ok.example']);
  });
  it('dedupes after normalising and caps at 5', () => {
    expect(sanitizePtrNames(['A.example', 'a.example.', 'a.example'])).toEqual(['a.example']);
    const many = Array.from({ length: 8 }, (_, i) => `h${i}.example`);
    expect(sanitizePtrNames(many)).toEqual(many.slice(0, 5));
  });
  it('returns [] for non-array and non-string members', () => {
    expect(sanitizePtrNames(undefined)).toEqual([]);
    expect(sanitizePtrNames(null)).toEqual([]);
    expect(sanitizePtrNames('a.example')).toEqual([]);
    expect(sanitizePtrNames({ length: 1, 0: 'a.example' })).toEqual([]);
    expect(sanitizePtrNames([1, null, {}, ['a.example'], 'ok.example'])).toEqual(['ok.example']);
  });
});

describe('lookupPtrs', () => {
  it('maps names, ENOTFOUND and ENODATA to [], other errors to null', async () => {
    const table: Record<string, () => Promise<string[]>> = {
      '192.0.2.1': async () => ['H.Example.'],
      '192.0.2.2': async () => { throw err('ENOTFOUND'); },
      '192.0.2.3': async () => { throw err('ENODATA'); },
      '192.0.2.4': async () => { throw err('ESERVFAIL'); },
      '192.0.2.5': async () => { throw err('ETIMEOUT'); },
      '192.0.2.6': async () => { throw err('ECONNREFUSED'); },
      '192.0.2.7': async () => { throw new Error('no code'); },
    };
    const m = await lookupPtrs(Object.keys(table), { budgetMs: 10_000, resolver: { reverse: (ip) => table[ip]!() } });
    expect([...m.entries()]).toEqual([
      ['192.0.2.1', ['h.example']], ['192.0.2.2', []], ['192.0.2.3', []],
      ['192.0.2.4', null], ['192.0.2.5', null], ['192.0.2.6', null], ['192.0.2.7', null],
    ]);
  });

  it('sanitises resolver output; all-invalid names give []', async () => {
    const m = await lookupPtrs(['192.0.2.1'], { budgetMs: 10_000, resolver: { reverse: async () => ['<b>x</b>'] } });
    expect(m.get('192.0.2.1')).toEqual([]);
  });

  it('times a hanging lookup out to null and clears its timer', async () => {
    let cancelled = 0;
    const t0 = Date.now();
    const m = await lookupPtrs(['192.0.2.1'], {
      timeoutMs: 50, budgetMs: 10_000,
      resolver: { reverse: () => new Promise<string[]>(() => {}), cancel: () => { cancelled++; } },
    });
    expect(m.get('192.0.2.1')).toBeNull();
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(cancelled).toBe(1);
  });

  it('never exceeds the concurrency cap', async () => {
    let inflight = 0, peak = 0;
    const ips = Array.from({ length: 12 }, (_, i) => `192.0.2.${i + 1}`);
    const m = await lookupPtrs(ips, {
      concurrency: 3, budgetMs: 10_000,
      resolver: { reverse: async () => { inflight++; peak = Math.max(peak, inflight); await new Promise((r) => setTimeout(r, 5)); inflight--; return ['a.example']; } },
    });
    expect(peak).toBe(3);
    expect(m.size).toBe(12);
    expect([...m.values()].every((v) => v?.[0] === 'a.example')).toBe(true);
  });

  it('starts nothing new once the budget is spent and maps the rest to null', async () => {
    let clock = 0;
    const started: string[] = [];
    const ips = ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4'];
    const stats = { skippedByBudget: -1 };
    const m = await lookupPtrs(ips, {
      concurrency: 1, budgetMs: 100, now: () => clock, stats,
      resolver: { reverse: async (ip) => { started.push(ip); clock += 60; return ['a.example']; } },
    });
    expect(started).toEqual(['192.0.2.1', '192.0.2.2']);
    expect(m.get('192.0.2.1')).toEqual(['a.example']);
    expect(m.get('192.0.2.2')).toEqual(['a.example']);
    expect(m.get('192.0.2.3')).toBeNull();
    expect(m.get('192.0.2.4')).toBeNull();
    expect(m.size).toBe(4);
    expect(stats.skippedByBudget).toBe(2);
  });

  it('looks duplicates up once', async () => {
    const seen: string[] = [];
    const m = await lookupPtrs(['192.0.2.1', '192.0.2.1', '192.0.2.2'], {
      budgetMs: 10_000, resolver: { reverse: async (ip) => { seen.push(ip); return []; } },
    });
    expect(seen.sort()).toEqual(['192.0.2.1', '192.0.2.2']);
    expect(m.size).toBe(2);
  });

  it('handles an empty list without building a resolver', async () => {
    expect((await lookupPtrs([], { budgetMs: 1 })).size).toBe(0);
  });
});
