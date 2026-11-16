import { describe, it, expect } from 'vitest';
import { openDb } from '../src/lib/db.js';
import { TARGET_NETWORK_SQL, markCurrent, shapeNetworkRows, type NetworkDbRow } from '../src/lib/target-network.js';

const T0 = '2026-11-10T12:00:00.000Z';
const hoursBefore = (h: number) => new Date(Date.parse(T0) - h * 3600_000).toISOString();

function row(over: Partial<NetworkDbRow> = {}): NetworkDbRow {
  return {
    ip: '192.0.2.1', ip_version: 4, ip_class: 'public',
    asn: null, as_name: null, as_domain: null, country_code: null, country: null,
    geo_checked_at: null, ptr_json: null, from_ports: 1, from_dns: 0,
    first_seen: T0, last_seen: T0, ...over,
  };
}

describe('TARGET_NETWORK_SQL', () => {
  it('returns only the asked target, in ip order', () => {
    const { raw } = openDb(':memory:');
    const ins = raw.prepare(
      `INSERT INTO target_network (target, ip, ip_version, ip_class, first_seen, last_seen)
       VALUES (?, ?, 4, 'public', ?, ?)`,
    );
    ins.run('a.example', '198.51.100.9', T0, T0);
    ins.run('a.example', '192.0.2.5', T0, T0);
    ins.run('b.example', '192.0.2.1', T0, T0);
    const rows = raw.prepare(TARGET_NETWORK_SQL).all('a.example') as NetworkDbRow[];
    expect(rows.map((r) => r.ip)).toEqual(['192.0.2.5', '198.51.100.9']);
  });
});

describe('markCurrent', () => {
  it('marks the newest row and rows within 24h current, older rows not', () => {
    const rows = [
      row({ ip: '192.0.2.1', last_seen: T0 }),
      row({ ip: '192.0.2.2', last_seen: hoursBefore(25) }),
      row({ ip: '192.0.2.3', last_seen: hoursBefore(23) }),
    ];
    expect(markCurrent(rows)).toEqual([true, false, true]);
  });
  it('counts an unparsable timestamp as current', () => {
    const rows = [row({ last_seen: T0 }), row({ ip: '192.0.2.2', last_seen: 'garbage' })];
    expect(markCurrent(rows)).toEqual([true, true]);
  });
  it('marks a single row current', () => {
    expect(markCurrent([row()])).toEqual([true]);
  });
  it('handles no rows', () => {
    expect(markCurrent([])).toEqual([]);
  });
});

describe('shapeNetworkRows', () => {
  it('maps the three geo states', () => {
    const [none, miss, hit] = shapeNetworkRows([
      row({ ip: '192.0.2.1', geo_checked_at: null }),
      row({ ip: '192.0.2.2', geo_checked_at: T0 }),
      row({ ip: '192.0.2.3', geo_checked_at: T0, asn: 'AS64496', country_code: 'HU', country: 'Hungary' }),
    ]);
    expect(none!.geo).toBe('none');
    expect(miss!.geo).toBe('miss');
    expect(hit!.geo).toBe('hit');
    expect(hit).toMatchObject({ asn: 'AS64496', country_code: 'HU', country: 'Hungary' });
  });

  it('treats a row with only a country or only an asn as a hit', () => {
    const [a, b] = shapeNetworkRows([
      row({ geo_checked_at: T0, country_code: 'HU' }),
      row({ ip: '192.0.2.2', geo_checked_at: T0, asn: 'AS64496' }),
    ]);
    expect(a!.geo).toBe('hit');
    expect(b!.geo).toBe('hit');
  });

  it('parses ptr_json defensively', () => {
    const ptr = (p: string | null) => shapeNetworkRows([row({ ptr_json: p })])[0]!.ptr;
    expect(ptr(null)).toBeNull();
    expect(ptr('[]')).toEqual([]);
    expect(ptr('["a.example","b.example"]')).toEqual(['a.example', 'b.example']);
    expect(ptr('{')).toBeNull();
    expect(ptr('"x"')).toBeNull();
    expect(ptr('{"a":1}')).toBeNull();
    expect(ptr('[1,"a.example"]')).toEqual(['a.example']);
  });

  it('derives seenVia, version, class and current', () => {
    const out = shapeNetworkRows([
      row({ ip: '192.0.2.1', from_ports: 1, from_dns: 1 }),
      row({ ip: '2001:db8::1', ip_version: 6, from_ports: 0, from_dns: 1, ip_class: 'public', last_seen: hoursBefore(30) }),
      row({ ip: '198.51.100.1', from_ports: 1, from_dns: 0, ip_class: 'private' }),
    ]);
    expect(out[0]).toMatchObject({ ip: '192.0.2.1', seenVia: ['ports', 'dns'], current: true, ipVersion: 4 });
    expect(out[1]).toMatchObject({ ip: '2001:db8::1', seenVia: ['dns'], current: false, ipVersion: 6 });
    expect(out[2]).toMatchObject({ seenVia: ['ports'], ipClass: 'private' });
  });
});
