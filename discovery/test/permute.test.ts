import { describe, it, expect } from 'vitest';
import { permute } from '../src/lib/permute.js';
import type { MinedGrammar, TokenStat } from '../src/lib/patterns.js';

function grammar(
  zone: string,
  sequences: { template: string; values: number[]; width?: number }[],
  tokens: TokenStat[] = [],
): MinedGrammar {
  return {
    zones: {
      [zone]: {
        zone,
        names: 5,
        tokens,
        sequences: sequences.map((s) => ({ width: 0, ...s })),
      },
    },
  };
}

const ZONE = 'okfo.gov.hu';

describe('permute', () => {
  it('extends a numeric run past its max and skips known names', () => {
    const g = grammar(ZONE, [{ template: 'web#', values: [1, 2] }]);
    const out = permute(g, new Set([`web1.${ZONE}`, `web2.${ZONE}`]), { perZone: 50 });
    expect(out).toContain(`web3.${ZONE}`);
    expect(out).not.toContain(`web1.${ZONE}`);
    expect(out).not.toContain(`web2.${ZONE}`);
  });

  it('fills gaps inside the observed range', () => {
    const g = grammar(ZONE, [{ template: 'web#', values: [1, 4] }]);
    const out = permute(g, new Set(), { perZone: 50 });
    expect(out).toContain(`web2.${ZONE}`);
    expect(out).toContain(`web3.${ZONE}`);
  });

  it('respects zero-pad width', () => {
    const g = grammar(ZONE, [{ template: 'ns#', values: [1, 2], width: 2 }]);
    const out = permute(g, new Set(), { perZone: 50 });
    expect(out).toContain(`ns03.${ZONE}`);
    expect(out).not.toContain(`ns3.${ZONE}`);
  });

  it('honours sequenceLookahead', () => {
    const g = grammar(ZONE, [{ template: 'web#', values: [1, 2] }]);
    const out = permute(g, new Set(), { perZone: 50, sequenceLookahead: 1 });
    expect(out).toContain(`web3.${ZONE}`);
    expect(out).not.toContain(`web4.${ZONE}`);
  });

  it('gives a single-value run a small neighbourhood', () => {
    const g = grammar(ZONE, [{ template: 'efet-test#', values: [2] }]);
    const out = permute(g, new Set(), { perZone: 50 });
    expect(out).toContain(`efet-test1.${ZONE}`);
    expect(out).toContain(`efet-test3.${ZONE}`);
    expect(out).not.toContain(`efet-test2.${ZONE}`);
  });

  it('bounds the count per zone', () => {
    const g = grammar(ZONE, [{ template: 'web#', values: [1, 20] }]);
    const out = permute(g, new Set(), { perZone: 4 });
    expect(out).toHaveLength(4);
  });

  it('stays bounded for far-apart and unsafe-magnitude runs', () => {
    for (const values of [[1, 10_000_000], [1, 9_007_199_254_740_993]]) {
      const g = grammar(ZONE, [{ template: 'backup#', values }]);
      const t0 = Date.now();
      const out = permute(g, new Set(), { perZone: 10 });
      expect(Date.now() - t0).toBeLessThan(1000);
      expect(out.length).toBeLessThanOrEqual(10);
    }
  });

  it('excludes known FQDNs case-insensitively', () => {
    const g = grammar(ZONE, [{ template: 'web#', values: [1, 2] }]);
    const out = permute(g, new Set([`WEB3.${ZONE.toUpperCase()}`]), { perZone: 50 });
    expect(out).not.toContain(`web3.${ZONE}`);
    const out2 = permute(g, new Set([`Web3.${ZONE}`]), { perZone: 50 });
    expect(out2).not.toContain(`web3.${ZONE}`);
  });

  it('recombines a frequent stem with a suffix token', () => {
    const g = grammar(ZONE, [], [
      { text: 'web', count: 4, class: 'role' },
      { text: 'efet', count: 2, class: 'word' },
      { text: 'test', count: 3, class: 'suffix' },
    ]);
    const out = permute(g, new Set(), { perZone: 50 });
    expect(out).toContain(`web-test.${ZONE}`);
    expect(out).toContain(`efet-test.${ZONE}`);
    expect(out).not.toContain(`test-test.${ZONE}`);
  });

  it('recombines a stem with a region token', () => {
    const g = grammar(ZONE, [], [
      { text: 'mail', count: 4, class: 'role' },
      { text: 'bp', count: 1, class: 'region' },
    ]);
    expect(permute(g, new Set(), { perZone: 50 })).toContain(`mail-bp.${ZONE}`);
  });

  it('is deterministic and de-duplicated', () => {
    const g = grammar(
      ZONE,
      [{ template: 'web#', values: [1, 2] }],
      [
        { text: 'web', count: 4, class: 'role' },
        { text: 'dev', count: 2, class: 'suffix' },
      ],
    );
    const a = permute(g, new Set(), { perZone: 50 });
    const b = permute(g, new Set(), { perZone: 50 });
    expect(a).toEqual(b);
    expect(new Set(a).size).toBe(a.length);
  });
});
