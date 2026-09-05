import { describe, it, expect } from 'vitest';
import { buildGraph, type EnrichedRow } from '../src/lib/graph.js';

const asnRow = (o: Partial<EnrichedRow['addresses'][number]> = {}) => ({
  ip: '1.2.3.4',
  version: 4 as 4 | 6,
  ptr: [],
  asn: 'AS100',
  as_name: 'Example ISP',
  as_domain: 'example.net',
  country_code: 'HU',
  country: 'Hungary',
  continent_code: 'EU',
  ...o,
});

describe('buildGraph', () => {
  it('dedupes IPs across multiple domains', () => {
    const rows: EnrichedRow[] = [
      { domain: 'a.example.com', addresses: [asnRow({ ip: '10.0.0.1' })], errors: [] },
      { domain: 'b.example.com', addresses: [asnRow({ ip: '10.0.0.1' })], errors: [] },
    ];
    const g = buildGraph(rows);
    expect(g.ips).toHaveLength(1);
    expect(g.ips[0]!.ip).toBe('10.0.0.1');
    expect(g.ips[0]!.domains.sort()).toEqual(['a.example.com', 'b.example.com']);
  });

  it('preserves distinct IPs per domain', () => {
    const rows: EnrichedRow[] = [
      {
        domain: 'a.example.com',
        addresses: [asnRow({ ip: '10.0.0.1' }), asnRow({ ip: '10.0.0.2' })],
        errors: [],
      },
    ];
    const g = buildGraph(rows);
    expect(g.ips).toHaveLength(2);
    expect(g.domains).toHaveLength(1);
  });

  it('aggregates ASNs across IPs', () => {
    const rows: EnrichedRow[] = [
      {
        domain: 'a.example.com',
        addresses: [
          asnRow({ ip: '10.0.0.1', asn: 'AS100' }),
          asnRow({ ip: '10.0.0.2', asn: 'AS100' }),
          asnRow({ ip: '10.0.0.3', asn: 'AS200', as_name: 'Other ISP' }),
        ],
        errors: [],
      },
    ];
    const g = buildGraph(rows);
    expect(g.asns).toHaveLength(2);
    const as100 = g.asns.find((a) => a.asn === 'AS100');
    expect(as100?.ips.sort()).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(as100?.domains).toEqual(['a.example.com']);
  });

  it('counts countries by IP occurrence', () => {
    const rows: EnrichedRow[] = [
      {
        domain: 'a',
        addresses: [
          asnRow({ ip: '1.1.1.1', country_code: 'HU' }),
          asnRow({ ip: '2.2.2.2', country_code: 'HU' }),
          asnRow({ ip: '3.3.3.3', country_code: 'DE' }),
        ],
        errors: [],
      },
    ];
    const g = buildGraph(rows);
    expect(g.countries).toEqual([
      { cc: 'HU', n: 2 },
      { cc: 'DE', n: 1 },
    ]);
  });

  it('handles domains with no resolved addresses', () => {
    const rows: EnrichedRow[] = [
      { domain: 'nx.example.com', addresses: [], errors: ['A:ENOTFOUND'] },
    ];
    const g = buildGraph(rows);
    expect(g.domains).toHaveLength(1);
    expect(g.ips).toHaveLength(0);
    expect(g.asns).toHaveLength(0);
  });

  it('skips ASN aggregation when asn is null', () => {
    const rows: EnrichedRow[] = [
      { domain: 'a', addresses: [asnRow({ asn: null })], errors: [] },
    ];
    const g = buildGraph(rows);
    expect(g.asns).toHaveLength(0);
    expect(g.ips).toHaveLength(1);
  });

  it('countries sorted by count descending', () => {
    const rows: EnrichedRow[] = [
      {
        domain: 'a',
        addresses: [
          asnRow({ ip: '1.1.1.1', country_code: 'DE' }),
          asnRow({ ip: '2.2.2.2', country_code: 'HU' }),
          asnRow({ ip: '3.3.3.3', country_code: 'HU' }),
          asnRow({ ip: '4.4.4.4', country_code: 'HU' }),
        ],
        errors: [],
      },
    ];
    const g = buildGraph(rows);
    expect(g.countries[0]!.cc).toBe('HU');
    expect(g.countries[0]!.n).toBe(3);
  });
});
