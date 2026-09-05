import { describe, it, expect } from 'vitest';
import {
  diffAgainstScan,
  classifyHost,
  keyOf,
  isMeaningful,
  type Observation,
  type ScanWindow,
} from '../src/lib/resolved.js';

function obs(overrides: Partial<Observation> & Pick<Observation, 'title' | 'seen_at'>): Observation {
  return {
    tool: 'nuclei',
    target: 'a.example',
    category: 'template-id',
    severity: 'medium',
    cve: null,
    matched_at: null,
    ...overrides,
  };
}

const window: ScanWindow = {
  target: 'a.example',
  startedAt: '2026-08-20T00:00:00.000Z',
  finishedAt: '2026-08-20T01:00:00.000Z',
};

describe('keyOf', () => {
  it('is stable across observations with the same (tool, category, title)', () => {
    const k1 = keyOf({ tool: 'nuclei', category: 'x', title: 'y' });
    const k2 = keyOf({ tool: 'nuclei', category: 'x', title: 'y' });
    expect(k1).toBe(k2);
  });
  it('distinguishes on any component', () => {
    const base = { tool: 'nuclei', category: 'x', title: 'y' };
    expect(keyOf(base)).not.toBe(keyOf({ ...base, tool: 'wpscan' }));
    expect(keyOf(base)).not.toBe(keyOf({ ...base, category: 'z' }));
    expect(keyOf(base)).not.toBe(keyOf({ ...base, title: 'z' }));
  });
  it('avoids delimiter collisions across component boundaries', () => {
    // A plain-space or plain-pipe delimiter would collide these two.
    const a = keyOf({ tool: 'a b', category: 'c', title: 'd' });
    const b = keyOf({ tool: 'a', category: 'b c', title: 'd' });
    expect(a).not.toBe(b);
  });
});

describe('isMeaningful', () => {
  it('accepts critical/high/medium/low case-insensitively', () => {
    for (const s of ['critical', 'HIGH', 'Medium', 'low']) {
      expect(isMeaningful({ severity: s })).toBe(true);
    }
  });
  it('rejects info + null + unknown severities', () => {
    for (const s of ['info', 'unknown', '', null]) {
      expect(isMeaningful({ severity: s })).toBe(false);
    }
  });
});

describe('diffAgainstScan', () => {
  it('buckets: resolved (pre only) / persistent (both) / novel (during only)', () => {
    const observations: Observation[] = [
      // Pre only — should be resolved.
      obs({ title: 'CVE-1999-0001', severity: 'high', seen_at: '2026-08-01T00:00:00.000Z' }),
      // Pre + during — persistent.
      obs({ title: 'weak-tls', severity: 'medium', seen_at: '2026-08-05T00:00:00.000Z' }),
      obs({ title: 'weak-tls', severity: 'medium', seen_at: '2026-08-20T00:30:00.000Z' }),
      // During only — novel.
      obs({ title: 'new-xss', severity: 'high', seen_at: '2026-08-20T00:45:00.000Z' }),
    ];
    const d = diffAgainstScan(observations, window);
    expect(d.resolved.map((o) => o.title)).toEqual(['CVE-1999-0001']);
    expect(d.persistent.map((p) => p.during.title)).toEqual(['weak-tls']);
    expect(d.novel.map((o) => o.title)).toEqual(['new-xss']);
  });

  it('collapses multiple pre/during observations to the latest per bucket', () => {
    const observations: Observation[] = [
      obs({ title: 'x', severity: 'low', seen_at: '2026-08-01T00:00:00.000Z' }),
      obs({ title: 'x', severity: 'medium', seen_at: '2026-08-10T00:00:00.000Z' }),
      obs({ title: 'x', severity: 'high', seen_at: '2026-08-20T00:10:00.000Z' }),
      obs({ title: 'x', severity: 'critical', seen_at: '2026-08-20T00:50:00.000Z' }),
    ];
    const d = diffAgainstScan(observations, window);
    expect(d.persistent).toHaveLength(1);
    const p = d.persistent[0]!;
    expect(p.pre.seen_at).toBe('2026-08-10T00:00:00.000Z');
    expect(p.pre.severity).toBe('medium');
    expect(p.during.seen_at).toBe('2026-08-20T00:50:00.000Z');
    expect(p.during.severity).toBe('critical');
  });

  it('ranks output critical > high > medium > low, then newer first', () => {
    const observations: Observation[] = [
      obs({ title: 'lo', severity: 'low', seen_at: '2026-08-01T00:00:00.000Z' }),
      obs({ title: 'hi-old', severity: 'high', seen_at: '2026-08-02T00:00:00.000Z' }),
      obs({ title: 'hi-new', severity: 'high', seen_at: '2026-08-05T00:00:00.000Z' }),
      obs({ title: 'crit', severity: 'critical', seen_at: '2026-08-03T00:00:00.000Z' }),
    ];
    const d = diffAgainstScan(observations, window);
    expect(d.resolved.map((o) => o.title)).toEqual(['crit', 'hi-new', 'hi-old', 'lo']);
  });

  it('ignores observations after the window (defensive, should not happen in practice)', () => {
    const observations: Observation[] = [
      obs({ title: 'stray', severity: 'high', seen_at: '2027-01-01T00:00:00.000Z' }),
    ];
    const d = diffAgainstScan(observations, window);
    expect(d.resolved).toEqual([]);
    expect(d.persistent).toEqual([]);
    expect(d.novel).toEqual([]);
  });

  it('treats findings AT startedAt as inside the window', () => {
    const d = diffAgainstScan(
      [obs({ title: 'edge', severity: 'high', seen_at: window.startedAt })],
      window,
    );
    expect(d.novel.map((o) => o.title)).toEqual(['edge']);
  });

  it('rejects observations for a different target', () => {
    expect(() =>
      diffAgainstScan(
        [obs({ target: 'other.example', title: 'x', seen_at: '2026-08-01T00:00:00.000Z' })],
        window,
      ),
    ).toThrow(/target other\.example != window.target a\.example/);
  });
});

describe('classifyHost', () => {
  const empty: ScanWindow = { target: 't', startedAt: '2026-08-20T00:00:00.000Z', finishedAt: '2026-08-20T01:00:00.000Z' };

  it('clean-always: no meaningful findings ever', () => {
    const d = diffAgainstScan(
      [{ tool: 'nuclei', target: 't', category: 'x', title: 'info-noise', severity: 'info', seen_at: '2026-08-01T00:00:00.000Z', cve: null, matched_at: null }],
      empty,
    );
    expect(classifyHost(d)).toBe('clean-always');
  });

  it('clean-now: meaningful pre findings but nothing meaningful in-window', () => {
    const d = diffAgainstScan(
      [
        { tool: 'nuclei', target: 't', category: 'x', title: 'old-bug', severity: 'high', seen_at: '2026-08-01T00:00:00.000Z', cve: null, matched_at: null },
        { tool: 'nuclei', target: 't', category: 'x', title: 'info-banner', severity: 'info', seen_at: '2026-08-20T00:30:00.000Z', cve: null, matched_at: null },
      ],
      empty,
    );
    expect(classifyHost(d)).toBe('clean-now');
  });

  it('still-dirty: meaningful finding in-window (persistent or novel)', () => {
    const d1 = diffAgainstScan(
      [{ tool: 'nuclei', target: 't', category: 'x', title: 'new', severity: 'high', seen_at: '2026-08-20T00:30:00.000Z', cve: null, matched_at: null }],
      empty,
    );
    expect(classifyHost(d1)).toBe('still-dirty');
    const d2 = diffAgainstScan(
      [
        { tool: 'nuclei', target: 't', category: 'x', title: 'ongoing', severity: 'medium', seen_at: '2026-08-01T00:00:00.000Z', cve: null, matched_at: null },
        { tool: 'nuclei', target: 't', category: 'x', title: 'ongoing', severity: 'medium', seen_at: '2026-08-20T00:30:00.000Z', cve: null, matched_at: null },
      ],
      empty,
    );
    expect(classifyHost(d2)).toBe('still-dirty');
  });

  it('info-only findings in-window do NOT flip clean-now to still-dirty', () => {
    const d = diffAgainstScan(
      [
        { tool: 'nuclei', target: 't', category: 'x', title: 'old-bug', severity: 'high', seen_at: '2026-08-01T00:00:00.000Z', cve: null, matched_at: null },
        { tool: 'nuclei', target: 't', category: 'x', title: 'banner', severity: 'info', seen_at: '2026-08-20T00:30:00.000Z', cve: null, matched_at: null },
      ],
      empty,
    );
    expect(classifyHost(d)).toBe('clean-now');
  });
});
