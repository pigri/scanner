import { describe, it, expect } from 'vitest';
import { openDb } from '../src/lib/db.js';
import { TARGET_NETWORK_SQL, TARGET_NETWORK_LIST_SQL, TARGET_SCAN_SQL, TARGET_ANSWERED_SQL, TARGET_ANSWERED_DNS_SQL, DNS_TRACKING_SQL, DNS_UNTRACKED_TARGETS_SQL, DNS_TRACKING_START_SQL, markCurrent, historyText, scanStatus, unreachableSince, shapeNetworkRows, summarizeNetworks, type NetworkDbRow } from '../src/lib/target-network.js';

const T0 = '2026-11-10T12:00:00.000Z';
const hoursBefore = (h: number) => new Date(Date.parse(T0) - h * 3600_000).toISOString();

function row(over: Partial<NetworkDbRow> = {}): NetworkDbRow {
  return {
    ip: '192.0.2.1', ip_version: 4, ip_class: 'public',
    asn: null, as_name: null, as_domain: null, country_code: null, country: null,
    geo_checked_at: null, ptr_json: null, from_ports: 1, from_dns: 0, from_http: 0,
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
      row({ ip: '203.0.113.1', from_ports: 0, from_http: 1 }),
    ]);
    expect(out[0]).toMatchObject({ ip: '192.0.2.1', seenVia: ['ports', 'dns'], current: true, ipVersion: 4 });
    expect(out[1]).toMatchObject({ ip: '2001:db8::1', seenVia: ['dns'], current: false, ipVersion: 6 });
    expect(out[2]).toMatchObject({ seenVia: ['ports'], ipClass: 'private' });
    expect(out[3]).toMatchObject({ seenVia: ['http'] });
  });
});

type ListRow = NetworkDbRow & { target: string; started_at: string | null };
const lrow = (target: string, over: Partial<ListRow> = {}): ListRow => ({ target, started_at: null, ...row(over) });

describe('TARGET_NETWORK_LIST_SQL', () => {
  it('reads every target in primary-key order', () => {
    const { raw } = openDb(':memory:');
    const ins = raw.prepare(
      `INSERT INTO target_network (target, ip, ip_version, ip_class, first_seen, last_seen)
       VALUES (?, ?, 4, 'public', ?, ?)`,
    );
    ins.run('b.example', '192.0.2.1', T0, T0);
    ins.run('a.example', '198.51.100.9', T0, T0);
    ins.run('a.example', '192.0.2.5', T0, T0);
    const rows = raw.prepare(TARGET_NETWORK_LIST_SQL).all() as ListRow[];
    expect(rows.map((r) => `${r.target} ${r.ip}`)).toEqual([
      'a.example 192.0.2.5',
      'a.example 198.51.100.9',
      'b.example 192.0.2.1',
    ]);
  });
});

describe('TARGET_NETWORK_LIST_SQL scan join', () => {
  it('carries started_at of the done scan only, and null otherwise', () => {
    const { raw } = openDb(':memory:');
    const ins = raw.prepare(
      `INSERT INTO target_network (target, ip, ip_version, ip_class, first_seen, last_seen)
       VALUES (?, ?, 4, 'public', ?, ?)`,
    );
    for (const t of ['done.example', 'pending.example', 'none.example']) ins.run(t, '192.0.2.1', T0, T0);
    const q = raw.prepare(`INSERT INTO scan_queue (target, status, queued_at, started_at) VALUES (?, ?, ?, ?)`);
    q.run('done.example', 'done', T0, '2026-11-04T09:00:00.000Z');
    q.run('pending.example', 'pending', T0, '2026-11-04T09:00:00.000Z');
    const rows = raw.prepare(TARGET_NETWORK_LIST_SQL).all() as ListRow[];
    expect(Object.fromEntries(rows.map((r) => [r.target, r.started_at]))).toEqual({
      'done.example': '2026-11-04T09:00:00.000Z',
      'pending.example': null,
      'none.example': null,
    });
  });
});

describe('DNS list context SQL', () => {
  it('lists targets with an untracked row, and the tracking start', () => {
    const { raw } = openDb(':memory:');
    const ins = raw.prepare(
      `INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES (?, ?, 'A', ?, ?, ?)`,
    );
    ins.run('old.example', 'old.example', '192.0.2.1', T0, null);
    ins.run('new.example', 'new.example', '192.0.2.2', T0, '2026-11-16T00:00:00.000Z');
    ins.run('new.example', 'new.example', '192.0.2.3', T0, '2026-11-17T00:00:00.000Z');
    expect((raw.prepare(DNS_UNTRACKED_TARGETS_SQL).all() as { target: string }[]).map((r) => r.target)).toEqual(['old.example']);
    expect((raw.prepare(DNS_TRACKING_START_SQL).get() as { tracking_start: string | null }).tracking_start).toBe('2026-11-16T00:00:00.000Z');
  });
});

describe('summarizeNetworks with a scan context', () => {
  const started = '2026-11-04T09:00:00.000Z';
  const before = '2026-08-31T09:00:00.000Z';
  const after = '2026-11-05T09:00:00.000Z';
  const ctx = (untracked: string[], trackingStart: string | null) => ({ untracked: new Set(untracked), trackingStart });
  const hu = { country_code: 'HU', asn: 'AS64496' };

  it('keeps an ip seen in the latest scan (yes) and drops one it did not see (no)', () => {
    const m = summarizeNetworks(
      [
        lrow('a.example', { ip: '192.0.2.1', ...hu, started_at: started, last_seen: after }),
        lrow('a.example', { ip: '192.0.2.2', country_code: 'DE', asn: 'AS64511', started_at: started, last_seen: before }),
      ],
      ctx([], '2026-11-01T00:00:00.000Z'),
    );
    expect(m.get('a.example')).toEqual({ countries: ['HU'], asns: ['AS64496'], unreachableSince: null });
  });

  it('keeps an old ip as unknown when DNS rows predate tracking and the scan predates it too', () => {
    const m = summarizeNetworks(
      [lrow('a.example', { ip: '192.0.2.1', ...hu, started_at: started, last_seen: before })],
      ctx(['a.example'], '2026-11-16T00:00:00.000Z'),
    );
    expect(m.get('a.example')).toEqual({ countries: ['HU'], asns: ['AS64496'], unreachableSince: null });
  });

  it('drops an old ip when the target has untracked rows but the scan is after tracking began', () => {
    const m = summarizeNetworks(
      [lrow('a.example', { ip: '192.0.2.1', ...hu, started_at: started, last_seen: before })],
      ctx(['a.example'], '2026-11-01T00:00:00.000Z'),
    );
    expect(m.get('a.example')).toEqual({ countries: [], asns: [], unreachableSince: started });
  });

  it('applies the 24 h rule to a target with no done scan', () => {
    const m = summarizeNetworks(
      [
        lrow('a.example', { ip: '192.0.2.1', ...hu, started_at: null }),
        lrow('a.example', { ip: '192.0.2.2', country_code: 'DE', asn: 'AS64511', started_at: null, last_seen: hoursBefore(25) }),
      ],
      ctx([], null),
    );
    expect(m.get('a.example')).toEqual({ countries: ['HU'], asns: ['AS64496'], unreachableSince: null });
  });
});

describe('summarizeNetworks', () => {
  it('uses current rows only', () => {
    const m = summarizeNetworks([
      lrow('a.example', { ip: '192.0.2.1', country_code: 'HU', asn: 'AS64496' }),
      lrow('a.example', { ip: '192.0.2.2', country_code: 'DE', asn: 'AS64511', last_seen: hoursBefore(25) }),
    ]);
    expect(m.get('a.example')).toEqual({ countries: ['HU'], asns: ['AS64496'], unreachableSince: null });
  });

  it('computes currency per target, with distinct sorted values', () => {
    const m = summarizeNetworks([
      lrow('a.example', { ip: '192.0.2.1', country_code: 'HU', asn: 'AS64511' }),
      lrow('a.example', { ip: '192.0.2.2', country_code: 'DE', asn: 'AS64496' }),
      lrow('a.example', { ip: '192.0.2.3', country_code: 'HU', asn: 'AS64496' }),
      lrow('b.example', { ip: '198.51.100.1', country_code: 'US', asn: 'AS64500', last_seen: hoursBefore(100) }),
    ]);
    expect(m.get('a.example')).toEqual({ countries: ['DE', 'HU'], asns: ['AS64496', 'AS64511'], unreachableSince: null });
    expect(m.get('b.example')).toEqual({ countries: ['US'], asns: ['AS64500'], unreachableSince: null });
  });

  it('skips null and empty values', () => {
    const m = summarizeNetworks([
      lrow('a.example', { ip: '192.0.2.1', country_code: null, asn: '' }),
      lrow('a.example', { ip: '192.0.2.2', country_code: 'HU', asn: null }),
    ]);
    expect(m.get('a.example')).toEqual({ countries: ['HU'], asns: [], unreachableSince: null });
  });

  it('takes the country from country_code only, never the name', () => {
    const m = summarizeNetworks([
      lrow('a.example', { ip: '192.0.2.1', country_code: null, country: 'Exampleland' }),
      lrow('b.example', { ip: '192.0.2.2', country_code: 'HU', country: 'Hungary' }),
    ]);
    expect(m.get('a.example')).toEqual({ countries: [], asns: [], unreachableSince: null });
    expect(m.get('b.example')).toEqual({ countries: ['HU'], asns: [], unreachableSince: null });
  });

  it('ignores non-public rows', () => {
    const m = summarizeNetworks([
      lrow('a.example', { ip: '198.51.100.1', ip_class: 'private', country_code: 'HU', asn: 'AS64496' }),
    ]);
    expect(m.get('a.example') ?? { countries: [], asns: [] }).toEqual({ countries: [], asns: [], unreachableSince: null });
  });
});

const S = '2026-11-04T09:00:00.000Z';
const TRACK = '2026-11-16T00:00:00.000Z';

describe('scanStatus', () => {
  it('is yes when the ip was seen at or after the scan start, boundary included', () => {
    expect(scanStatus(S, S, false, null)).toBe('yes');
    expect(scanStatus('2026-11-04T09:00:01.000Z', S, false, null)).toBe('yes');
  });
  it('is no when the ip was last seen before the scan and DNS has no untracked rows', () => {
    expect(scanStatus('2026-11-04T08:59:59.999Z', S, false, TRACK)).toBe('no');
  });
  it('is unknown when untracked DNS rows exist and the scan predates tracking', () => {
    expect(scanStatus('2026-08-31T00:00:00.000Z', S, true, TRACK)).toBe('unknown');
    expect(scanStatus('2026-08-31T00:00:00.000Z', S, true, null)).toBe('unknown');
  });
  it('is no when the scan started at or after the tracking start, even with untracked rows', () => {
    expect(scanStatus('2026-08-31T00:00:00.000Z', TRACK, true, TRACK)).toBe('no');
  });
  it('is none when the target has no done scan', () => {
    expect(scanStatus(S, null, true, TRACK)).toBe('none');
  });
  it('compares parsed dates, not strings', () => {
    expect(scanStatus('2026-11-04T10:00:00+02:00', S, false, null)).toBe('no');
    expect(scanStatus('2026-11-04T11:00:00+02:00', S, false, null)).toBe('yes');
  });
  it('treats an unparsable time as current (yes)', () => {
    expect(scanStatus('garbage', S, false, null)).toBe('yes');
    expect(scanStatus(S, 'garbage', false, null)).toBe('yes');
  });
  it('treats an unparsable tracking start as no tracking at all', () => {
    expect(scanStatus('2026-08-31T00:00:00.000Z', S, true, 'garbage')).toBe('unknown');
  });
});

describe('shapeNetworkRows with a scan context', () => {
  const ctx = (over = {}) => ({ startedAt: S, dnsUntracked: false, trackingStart: TRACK, ...over });
  it('sets scanStatus and derives current from it, not from the 24h rule', () => {
    const out = shapeNetworkRows(
      [row({ ip: '192.0.2.1', last_seen: S }), row({ ip: '192.0.2.2', last_seen: '2026-10-01T00:00:00.000Z' })],
      ctx(),
    );
    expect(out.map((r) => [r.scanStatus, r.current])).toEqual([['yes', true], ['no', false]]);
  });
  it('keeps unknown rows current', () => {
    const [r] = shapeNetworkRows([row({ last_seen: '2026-08-31T00:00:00.000Z' })], ctx({ dnsUntracked: true }));
    expect(r).toMatchObject({ scanStatus: 'unknown', current: true });
  });
  it('falls back to the 24h rule with status none when the target has no done scan', () => {
    const rows = [row({ last_seen: T0 }), row({ ip: '192.0.2.2', last_seen: hoursBefore(48) })];
    const out = shapeNetworkRows(rows, ctx({ startedAt: null }));
    expect(out.map((r) => [r.scanStatus, r.current])).toEqual([['none', true], ['none', false]]);
  });
  it('reports none without a context', () => {
    expect(shapeNetworkRows([row()])[0]!.scanStatus).toBe('none');
  });
});

describe('scan SQL', () => {
  function db() {
    const { raw } = openDb(':memory:');
    return raw;
  }
  it('TARGET_SCAN_SQL returns the queue row of the target', () => {
    const raw = db();
    raw.prepare(`INSERT INTO scan_queue (target, status, queued_at, started_at, finished_at) VALUES (?, ?, ?, ?, ?)`).run('a.example', 'done', S, S, S);
    raw.prepare(`INSERT INTO scan_queue (target, status, queued_at) VALUES (?, 'pending', ?)`).run('b.example', S);
    expect(raw.prepare(TARGET_SCAN_SQL).get('a.example')).toMatchObject({ status: 'done', started_at: S });
    expect(raw.prepare(TARGET_SCAN_SQL).get('b.example')).toMatchObject({ status: 'pending', started_at: null });
    expect(raw.prepare(TARGET_SCAN_SQL).get('c.example')).toBeUndefined();
  });
  it('TARGET_ANSWERED_SQL reports newest time and counts since the scan start per source', () => {
    const raw = db();
    const port = raw.prepare(`INSERT INTO ports (target, port, protocol, seen_at) VALUES (?, ?, 'tcp', ?)`);
    port.run('a.example', 80, '2026-08-31T00:00:00.000Z');
    port.run('a.example', 80, S);
    port.run('a.example', 443, '2026-11-05T00:00:00.000Z');
    port.run('b.example', 22, S);
    raw.prepare(`INSERT INTO http_probes (target, url, seen_at) VALUES (?, ?, ?)`).run('a.example', 'http://a.example/', '2026-09-04T22:01:00.000Z');
    const rows = raw.prepare(TARGET_ANSWERED_SQL).all({ t: 'a.example', s: S }) as { source: string; at: string | null; n: number }[];
    const by = Object.fromEntries(rows.map((r) => [r.source, r]));
    expect(by.port).toMatchObject({ at: '2026-11-05T00:00:00.000Z', n: 2 });
    expect(by.http).toMatchObject({ at: '2026-09-04T22:01:00.000Z', n: 0 });
  });
  it('TARGET_ANSWERED_DNS_SQL uses last_seen, falling back to seen_at', () => {
    const raw = db();
    const ins = raw.prepare(`INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES (?, ?, 'A', ?, ?, ?)`);
    ins.run('a.example', 'a.example', '192.0.2.1', '2026-08-31T00:00:00.000Z', null);
    ins.run('a.example', 'a.example', '192.0.2.2', '2026-08-01T00:00:00.000Z', '2026-11-05T00:00:00.000Z');
    expect(raw.prepare(TARGET_ANSWERED_DNS_SQL).get({ t: 'a.example', s: S })).toMatchObject({ source: 'dns', at: '2026-11-05T00:00:00.000Z', n: 1 });
  });
  it('DNS_TRACKING_SQL gives the tracking start and whether the target has untracked rows', () => {
    const raw = db();
    const ins = raw.prepare(`INSERT INTO dns_records (target, name, type, value, seen_at, last_seen) VALUES (?, ?, 'A', ?, ?, ?)`);
    ins.run('a.example', 'a.example', '192.0.2.1', '2026-08-31T00:00:00.000Z', null);
    ins.run('b.example', 'b.example', '192.0.2.2', '2026-08-01T00:00:00.000Z', TRACK);
    expect(raw.prepare(DNS_TRACKING_SQL).get({ t: 'a.example' })).toEqual({ tracking_start: TRACK, untracked: 1 });
    expect(raw.prepare(DNS_TRACKING_SQL).get({ t: 'b.example' })).toEqual({ tracking_start: TRACK, untracked: 0 });
  });
});

describe('historyText', () => {
  const base = { old_country_code: null, new_country_code: null, old_asn: null, new_asn: null };
  it('names each event kind and marks reconstructed ones', () => {
    expect(historyText({ ...base, kind: 'ip_added', source: 'scan' })).toBe('added');
    expect(historyText({ ...base, kind: 'ip_gone', source: 'reconstructed' })).toBe('gone (inferred)');
    expect(historyText({ ...base, kind: 'ip_back', source: 'scan' })).toBe('back');
  });
  it('shows old to new for geo_changed and none for a missing side', () => {
    expect(historyText({ kind: 'geo_changed', source: 'scan', old_country_code: 'HU', new_country_code: 'DE', old_asn: 'AS64496', new_asn: 'AS64497' }))
      .toBe('geo changed: country HU → DE, ASN AS64496 → AS64497');
    expect(historyText({ kind: 'geo_changed', source: 'scan', old_country_code: 'HU', new_country_code: null, old_asn: 'AS64496', new_asn: 'AS64496' }))
      .toBe('geo changed: country HU → none');
  });
});

describe('unreachableSince', () => {
  const S = '2026-11-04T09:00:00.000Z';
  it('is the scan start when no ip was seen in it', () => {
    expect(unreachableSince(['no'], S)).toBe(S);
    expect(unreachableSince(['no', 'no'], S)).toBe(S);
  });
  it('is null when any ip is yes or unknown', () => {
    expect(unreachableSince(['no', 'yes'], S)).toBeNull();
    expect(unreachableSince(['no', 'unknown'], S)).toBeNull();
  });
  it('is null without a done scan, whatever the statuses', () => {
    expect(unreachableSince(['none'], null)).toBeNull();
    expect(unreachableSince(['no'], null)).toBeNull();
  });
  it('is null for a target with no ips at all', () => {
    expect(unreachableSince([], S)).toBeNull();
  });
});

describe('summarizeNetworks unreachableSince', () => {
  const S = '2026-11-04T09:00:00.000Z';
  const lr = (target: string, ip: string, last: string, started: string | null) => ({
    target, ip, asn: null, country_code: null, country: null, last_seen: last, ip_class: 'public', started_at: started,
  });
  const ctx = { untracked: new Set<string>(['d.example']), trackingStart: '2026-11-16T00:00:00.000Z' };
  it('flags a target whose ips all missed the latest scan, not one with yes, unknown or no scan', () => {
    const m = summarizeNetworks(
      [
        lr('a.example', '192.0.2.1', '2026-08-31T00:00:00.000Z', S),
        lr('b.example', '192.0.2.2', '2026-08-31T00:00:00.000Z', S),
        lr('b.example', '192.0.2.3', '2026-11-04T09:00:00.000Z', S),
        lr('c.example', '192.0.2.4', '2026-08-31T00:00:00.000Z', null),
        lr('d.example', '192.0.2.5', '2026-08-31T00:00:00.000Z', S),
      ],
      ctx,
    );
    expect(m.get('a.example')!.unreachableSince).toBe(S);
    expect(m.get('b.example')!.unreachableSince).toBeNull();
    expect(m.get('c.example')!.unreachableSince).toBeNull();
    expect(m.get('d.example')!.unreachableSince).toBeNull();
  });
  it('is null everywhere without a context', () => {
    const m = summarizeNetworks([lr('a.example', '192.0.2.1', '2026-08-31T00:00:00.000Z', S)]);
    expect(m.get('a.example')!.unreachableSince).toBeNull();
  });
});
