import { describe, it, expect } from 'vitest';
import {
  computeAttendance,
  type Observation,
  type ScanWindow,
} from '../src/lib/history.js';

function obs(overrides: Partial<Observation> & Pick<Observation, 'seen_at'>): Observation {
  return {
    tool: 'nuclei',
    target: 'a.example',
    category: 'template-id',
    title: 'default',
    severity: 'medium',
    cve: null,
    matched_at: null,
    run_id: null,
    ...overrides,
  };
}

const w = (tool: string, startedAt: string, finishedAt: string): ScanWindow => ({
  target: 'a.example', tool, startedAt, finishedAt,
});

// Three windows, all applicable to nuclei keys.
const W = [
  w('nuclei', '2026-08-01T00:00:00.000Z', '2026-08-01T01:00:00.000Z'),
  w('nuclei', '2026-08-10T00:00:00.000Z', '2026-08-10T01:00:00.000Z'),
  w('nuclei', '2026-08-20T00:00:00.000Z', '2026-08-20T01:00:00.000Z'),
];

describe('computeAttendance — presence bucketing', () => {
  it('marks present in every window when observed each time', () => {
    const rows = computeAttendance(
      [
        obs({ title: 'x', seen_at: '2026-08-01T00:30:00.000Z' }),
        obs({ title: 'x', seen_at: '2026-08-10T00:30:00.000Z' }),
        obs({ title: 'x', seen_at: '2026-08-20T00:30:00.000Z' }),
      ],
      W,
    );
    expect(rows[0]!.presence).toEqual(['present', 'present', 'present']);
    expect(rows[0]!.status).toBe('persistent');
    expect(rows[0]!.flapping).toBe(false);
  });

  it('resolved when the latest applicable window is absent', () => {
    const rows = computeAttendance(
      [
        obs({ title: 'x', seen_at: '2026-08-01T00:30:00.000Z' }),
        obs({ title: 'x', seen_at: '2026-08-10T00:30:00.000Z' }),
      ],
      W,
    );
    expect(rows[0]!.presence).toEqual(['present', 'present', 'absent']);
    expect(rows[0]!.status).toBe('resolved');
    expect(rows[0]!.flapping).toBe(false); // 1 transition
  });

  it('flapping = true on ≥ 2 present↔absent transitions', () => {
    const rows = computeAttendance(
      [
        obs({ title: 'x', seen_at: '2026-08-01T00:30:00.000Z' }),
        obs({ title: 'x', seen_at: '2026-08-20T00:30:00.000Z' }),
      ],
      W,
    );
    expect(rows[0]!.presence).toEqual(['present', 'absent', 'present']);
    expect(rows[0]!.flapping).toBe(true);
    expect(rows[0]!.status).toBe('persistent');
  });
});

describe('computeAttendance — tool-aware n/a', () => {
  it('a nuclei key in a testssl-only window is n/a, not absent', () => {
    const windows: ScanWindow[] = [
      w('nuclei', '2026-08-01T00:00:00.000Z', '2026-08-01T01:00:00.000Z'),
      w('testssl', '2026-08-10T00:00:00.000Z', '2026-08-10T01:00:00.000Z'),
      w('nuclei', '2026-08-20T00:00:00.000Z', '2026-08-20T01:00:00.000Z'),
    ];
    const rows = computeAttendance(
      [
        obs({ tool: 'nuclei', title: 'x', seen_at: '2026-08-01T00:30:00.000Z' }),
        obs({ tool: 'nuclei', title: 'x', seen_at: '2026-08-20T00:30:00.000Z' }),
      ],
      windows,
    );
    expect(rows[0]!.presence).toEqual(['present', 'n/a', 'present']);
    expect(rows[0]!.status).toBe('persistent');
    expect(rows[0]!.flapping).toBe(false); // n/a is skipped, so no transitions
  });

  it("scan-all windows act as wildcard applicable to every key's tool", () => {
    const windows: ScanWindow[] = [
      w('scan-all', '2026-08-01T00:00:00.000Z', '2026-08-01T01:00:00.000Z'),
      w('scan-all', '2026-08-20T00:00:00.000Z', '2026-08-20T01:00:00.000Z'),
    ];
    const rows = computeAttendance(
      [obs({ tool: 'nuclei', title: 'x', seen_at: '2026-08-01T00:30:00.000Z' })],
      windows,
    );
    expect(rows[0]!.presence).toEqual(['present', 'absent']);
    expect(rows[0]!.status).toBe('resolved');
  });

  it('status = unknown when every window is n/a', () => {
    const windows: ScanWindow[] = [
      w('testssl', '2026-08-01T00:00:00.000Z', '2026-08-01T01:00:00.000Z'),
      w('testssl', '2026-08-20T00:00:00.000Z', '2026-08-20T01:00:00.000Z'),
    ];
    // A nuclei observation from OUTSIDE both windows — key exists but no
    // applicable window covers it.
    const rows = computeAttendance(
      [obs({ tool: 'nuclei', title: 'x', seen_at: '2025-01-01T00:00:00.000Z' })],
      windows,
    );
    expect(rows[0]!.presence).toEqual(['n/a', 'n/a']);
    expect(rows[0]!.status).toBe('unknown');
    expect(rows[0]!.flapping).toBe(false);
  });

  it('resolved bases status on the last APPLICABLE window (skipping trailing n/a)', () => {
    const windows: ScanWindow[] = [
      w('nuclei', '2026-08-01T00:00:00.000Z', '2026-08-01T01:00:00.000Z'),
      w('nuclei', '2026-08-10T00:00:00.000Z', '2026-08-10T01:00:00.000Z'),
      w('testssl', '2026-08-20T00:00:00.000Z', '2026-08-20T01:00:00.000Z'),
    ];
    const rows = computeAttendance(
      [obs({ tool: 'nuclei', title: 'x', seen_at: '2026-08-01T00:30:00.000Z' })],
      windows,
    );
    expect(rows[0]!.presence).toEqual(['present', 'absent', 'n/a']);
    expect(rows[0]!.status).toBe('resolved'); // last applicable window said absent
  });
});

describe('computeAttendance — severity tracking', () => {
  it('records worst severity per window and worstSeverity overall', () => {
    const rows = computeAttendance(
      [
        obs({ title: 'x', severity: 'low', seen_at: '2026-08-01T00:30:00.000Z' }),
        obs({ title: 'x', severity: 'high', seen_at: '2026-08-01T00:40:00.000Z' }),
        obs({ title: 'x', severity: 'medium', seen_at: '2026-08-10T00:30:00.000Z' }),
        obs({ title: 'x', severity: 'critical', seen_at: '2026-08-20T00:30:00.000Z' }),
      ],
      W,
    );
    expect(rows[0]!.severityPerWindow).toEqual(['high', 'medium', 'critical']);
    expect(rows[0]!.worstSeverity).toBe('critical');
  });

  it('leaves severityPerWindow[i] = null when the key is absent that window', () => {
    const rows = computeAttendance(
      [obs({ title: 'x', severity: 'high', seen_at: '2026-08-10T00:30:00.000Z' })],
      W,
    );
    expect(rows[0]!.severityPerWindow).toEqual([null, 'high', null]);
  });
});

describe('computeAttendance — ordering + edge cases', () => {
  it('sorts output by worst severity desc, then last_seen desc', () => {
    const rows = computeAttendance(
      [
        obs({ title: 'lo', severity: 'low', seen_at: '2026-08-20T00:30:00.000Z' }),
        obs({ title: 'hi-old', severity: 'high', seen_at: '2026-08-20T00:10:00.000Z' }),
        obs({ title: 'hi-new', severity: 'high', seen_at: '2026-08-20T00:50:00.000Z' }),
        obs({ title: 'crit', severity: 'critical', seen_at: '2026-08-20T00:30:00.000Z' }),
      ],
      W,
    );
    expect(rows.map((r) => r.title)).toEqual(['crit', 'hi-new', 'hi-old', 'lo']);
  });

  it('rejects unsorted windows', () => {
    expect(() =>
      computeAttendance([], [
        w('nuclei', '2026-08-10T00:00:00.000Z', '2026-08-10T01:00:00.000Z'),
        w('nuclei', '2026-08-01T00:00:00.000Z', '2026-08-01T01:00:00.000Z'),
      ]),
    ).toThrow(/sorted by startedAt/);
  });

  it('rejects mixed-target windows', () => {
    expect(() =>
      computeAttendance([], [
        { target: 'a.example', tool: 'nuclei', startedAt: '2026-08-01T00:00:00.000Z', finishedAt: '2026-08-01T01:00:00.000Z' },
        { target: 'b.example', tool: 'nuclei', startedAt: '2026-08-02T00:00:00.000Z', finishedAt: '2026-08-02T01:00:00.000Z' },
      ]),
    ).toThrow(/same target/);
  });

  it('rejects empty windows', () => {
    expect(() => computeAttendance([], [])).toThrow(/at least one scan window/);
  });

  it('rejects observations for a different target', () => {
    expect(() =>
      computeAttendance(
        [obs({ target: 'b.example', title: 'x', seen_at: '2026-08-01T00:30:00.000Z' })],
        W,
      ),
    ).toThrow(/observation target b\.example/);
  });

  it('observations outside all windows still count in observations/firstSeen/lastSeen but not presence', () => {
    const rows = computeAttendance(
      [
        obs({ title: 'stray', severity: 'high', seen_at: '2025-01-01T00:00:00.000Z' }),
        obs({ title: 'stray', severity: 'high', seen_at: '2026-08-01T00:30:00.000Z' }),
      ],
      W,
    );
    expect(rows[0]!.observations).toBe(2);
    expect(rows[0]!.firstSeen).toBe('2025-01-01T00:00:00.000Z');
    expect(rows[0]!.presence).toEqual(['present', 'absent', 'absent']);
  });
});
