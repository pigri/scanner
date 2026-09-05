import { describe, it, expect } from 'vitest';
import { runsToPrune, type RunRow } from '../src/lib/retention.js';

const now = '2026-09-01T00:00:00Z';
const rows: RunRow[] = [
  { id: 1, tool: 'nmap',   started_at: '2026-08-01T00:00:00Z' }, // 31 days old
  { id: 2, tool: 'nmap',   started_at: '2026-08-15T00:00:00Z' }, // 17 days old
  { id: 3, tool: 'nuclei', started_at: '2026-08-28T00:00:00Z' }, //  4 days old
  { id: 4, tool: 'nuclei', started_at: '2026-08-30T00:00:00Z' }, //  2 days old
  { id: 5, tool: 'httpx',  started_at: '2026-08-05T00:00:00Z' }, // 27 days old
];

describe('runsToPrune', () => {
  it('returns runs older than N days', () => {
    const result = runsToPrune(rows, { olderThanDays: 14, now });
    expect(result.map((r) => r.id).sort()).toEqual([1, 2, 5]);
  });

  it('empty when nothing old enough', () => {
    expect(runsToPrune(rows, { olderThanDays: 90, now })).toEqual([]);
  });

  it('keeps at least keepMin per tool even if all are old', () => {
    const result = runsToPrune(rows, { olderThanDays: 0, now, keepMinPerTool: 1 });
    // For each tool the newest is kept; older ones for that tool are prunable.
    const kept = new Set(rows.map((r) => r.id).filter((id) => !result.map((r) => r.id).includes(id)));
    expect(kept).toContain(2); // newest nmap
    expect(kept).toContain(4); // newest nuclei
    expect(kept).toContain(5); // only httpx
    expect(result.map((r) => r.id).sort()).toEqual([1, 3]);
  });

  it('respects keepMinPerTool=2', () => {
    const result = runsToPrune(rows, { olderThanDays: 0, now, keepMinPerTool: 2 });
    // 2 newest per tool kept: nmap {1,2}, nuclei {3,4}, httpx {5}
    expect(result).toEqual([]);
  });
});
