import { describe, it, expect } from 'vitest';
import { pool } from '../src/lib/pool.js';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe('pool', () => {
  it('returns results index-aligned to input order', async () => {
    const items = [30, 5, 20, 1, 10];
    const out = await pool(items, 3, async (n, idx) => {
      await sleep(n);
      return `${idx}:${n}`;
    });
    expect(out).toEqual(['0:30', '1:5', '2:20', '3:1', '4:10']);
  });

  it('never runs more than size workers concurrently', async () => {
    let inFlight = 0;
    let max = 0;
    await pool(Array.from({ length: 20 }, (_, i) => i), 4, async () => {
      inFlight++;
      max = Math.max(max, inFlight);
      await sleep(3);
      inFlight--;
    });
    expect(max).toBe(4);
  });

  it('rejects when a worker throws', async () => {
    await expect(
      pool([1, 2, 3], 2, async (n) => {
        if (n === 2) throw new Error('boom');
        return n;
      }),
    ).rejects.toThrow('boom');
  });

  it('handles size larger than item count', async () => {
    let max = 0;
    let inFlight = 0;
    const out = await pool([1, 2, 3], 10, async (n) => {
      inFlight++;
      max = Math.max(max, inFlight);
      await sleep(2);
      inFlight--;
      return n * 2;
    });
    expect(out).toEqual([2, 4, 6]);
    expect(max).toBe(3);
  });

  it('returns [] for empty input', async () => {
    expect(await pool([], 5, async (x) => x)).toEqual([]);
  });
});
