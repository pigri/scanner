import { describe, it, expect } from 'vitest';
import { decideHostStates, parseDnsxResolved, dnsxRecords, shouldApplyResolution, DNS_ARCHIVE_THRESHOLD, type HostStateRow } from '../src/lib/host-state.js';

const T1 = '2026-11-01T00:00:00Z';
const T2 = '2026-11-02T00:00:00Z';

function row(over: Partial<HostStateRow> & Pick<HostStateRow, 'target'>): HostStateRow {
  return {
    active: 1, reason: null, dns_fail_count: 0,
    last_checked: T1, last_resolved: T1, first_archived_at: null, updated_at: T1,
    ...over,
  };
}
const byTarget = (rows: HostStateRow[]) => new Map(rows.map((r) => [r.target, r]));

describe('decideHostStates', () => {
  it('uses a threshold of 1 by default', () => {
    expect(DNS_ARCHIVE_THRESHOLD).toBe(1);
  });

  it('marks a resolving new host active', () => {
    const out = byTarget(decideHostStates(['a.example'], new Set(['a.example']), new Map(), T2, 1));
    expect(out.get('a.example')).toEqual({
      target: 'a.example', active: 1, reason: null, dns_fail_count: 0,
      last_checked: T2, last_resolved: T2, first_archived_at: null, updated_at: T2,
    });
  });

  it('archives a non-resolving host at the threshold', () => {
    const out = byTarget(decideHostStates(['a.example'], new Set(), new Map(), T2, 1));
    expect(out.get('a.example')).toEqual({
      target: 'a.example', active: 0, reason: 'dns', dns_fail_count: 1,
      last_checked: T2, last_resolved: null, first_archived_at: T2, updated_at: T2,
    });
  });

  it('accrues dns_fail_count below the threshold without archiving', () => {
    const cur = new Map([['a.example', row({ target: 'a.example' })]]);
    const first = byTarget(decideHostStates(['a.example'], new Set(), cur, T2, 2)).get('a.example')!;
    expect(first.active).toBe(1);
    expect(first.dns_fail_count).toBe(1);
    expect(first.reason).toBeNull();
    expect(first.last_resolved).toBe(T1);
    const second = byTarget(decideHostStates(['a.example'], new Set(), new Map([['a.example', first]]), T2, 2)).get('a.example')!;
    expect(second.active).toBe(0);
    expect(second.dns_fail_count).toBe(2);
    expect(second.reason).toBe('dns');
    expect(second.first_archived_at).toBe(T2);
  });

  it('keeps an archived host archived and its first_archived_at', () => {
    const cur = new Map([['a.example', row({
      target: 'a.example', active: 0, reason: 'dns', dns_fail_count: 1, first_archived_at: T1,
    })]]);
    const r = byTarget(decideHostStates(['a.example'], new Set(), cur, T2, 1)).get('a.example')!;
    expect(r.active).toBe(0);
    expect(r.dns_fail_count).toBe(2);
    expect(r.first_archived_at).toBe(T1);
  });

  it('un-archives a host that resolves again and resets the counter', () => {
    const cur = new Map([['a.example', row({
      target: 'a.example', active: 0, reason: 'dns', dns_fail_count: 3, first_archived_at: T1,
    })]]);
    const r = byTarget(decideHostStates(['a.example'], new Set(['a.example']), cur, T2, 1)).get('a.example')!;
    expect(r.active).toBe(1);
    expect(r.reason).toBeNull();
    expect(r.dns_fail_count).toBe(0);
    expect(r.first_archived_at).toBeNull();
    expect(r.last_resolved).toBe(T2);
  });

  it('only returns rows for batch targets, deduped', () => {
    const cur = new Map([['other.example', row({ target: 'other.example' })]]);
    const out = decideHostStates(['a.example', 'a.example', 'b.example'], new Set(['a.example']), cur, T2, 1);
    expect(out.map((r) => r.target).sort()).toEqual(['a.example', 'b.example']);
  });

  it('is a no-op for an empty batch', () => {
    expect(decideHostStates([], new Set(['a.example']), new Map(), T2, 1)).toEqual([]);
  });

  it('ignores resolved entries that are not in the batch', () => {
    const out = decideHostStates(['a.example'], new Set(['zzz.example']), new Map(), T2, 1);
    expect(out).toHaveLength(1);
    expect(out[0]!.active).toBe(0);
  });
});

describe('parseDnsxResolved', () => {
  it('collects hosts with at least one A or AAAA', () => {
    const text = [
      JSON.stringify({ host: 'a.example', a: ['192.0.2.1'] }),
      JSON.stringify({ host: 'b.example', aaaa: ['2001:db8::1'] }),
      JSON.stringify({ host: 'c.example', cname: ['x.example'], mx: ['mx.example'] }),
      JSON.stringify({ host: 'd.example', a: [], aaaa: [] }),
    ].join('\n');
    const r = parseDnsxResolved(text);
    expect([...r.resolved].sort()).toEqual(['a.example', 'b.example']);
    expect(r.rows).toBe(4);
  });

  it('skips blank, malformed and host-less lines', () => {
    const text = ['', 'not json', JSON.stringify({ a: ['192.0.2.1'] }), JSON.stringify({ host: 'a.example', a: ['192.0.2.1'] })].join('\n');
    const r = parseDnsxResolved(text);
    expect([...r.resolved]).toEqual(['a.example']);
    expect(r.rows).toBe(1);
  });

  it('does not count a row whose host is not a non-empty string', () => {
    const text = [JSON.stringify({ host: 5, a: ['192.0.2.1'] }), JSON.stringify({ host: '', a: ['192.0.2.1'] }), JSON.stringify({ host: ['a.example'], a: ['192.0.2.1'] })].join('\n');
    const r = parseDnsxResolved(text);
    expect(r.rows).toBe(0);
    expect(r.resolved.size).toBe(0);
  });

  it('does not resolve a host whose a is a string rather than a list', () => {
    const r = parseDnsxResolved(JSON.stringify({ host: 'x.example', a: 'nonempty' }));
    expect(r.rows).toBe(1);
    expect(r.resolved.size).toBe(0);
  });

  it('does not resolve a host whose list holds no non-empty string', () => {
    const text = [
      JSON.stringify({ host: 'a.example', a: [42] }),
      JSON.stringify({ host: 'b.example', a: [''], aaaa: [null] }),
    ].join('\n');
    const r = parseDnsxResolved(text);
    expect(r.rows).toBe(2);
    expect(r.resolved.size).toBe(0);
  });

  it('resolves on aaaa when a is an empty list', () => {
    const r = parseDnsxResolved(JSON.stringify({ host: 'x.example', a: [], aaaa: ['2001:db8::1'] }));
    expect([...r.resolved]).toEqual(['x.example']);
  });

  it('skips null, array and scalar lines', () => {
    const text = ['null', '[]', '5', '"x"', JSON.stringify({ host: 'a.example', a: ['192.0.2.1'] })].join('\n');
    const r = parseDnsxResolved(text);
    expect([...r.resolved]).toEqual(['a.example']);
    expect(r.rows).toBe(1);
  });

  it('reports zero rows for empty output', () => {
    expect(parseDnsxResolved('')).toEqual({ rows: 0, resolved: new Set() });
  });
});

describe('shouldApplyResolution', () => {
  it('rejects a non-zero exit code', () => {
    expect(shouldApplyResolution(1, 10)).toBe(false);
    expect(shouldApplyResolution(-1, 10)).toBe(false);
  });
  it('rejects a clean exit with no output rows', () => {
    expect(shouldApplyResolution(0, 0)).toBe(false);
  });
  it('accepts a clean exit with output rows', () => {
    expect(shouldApplyResolution(0, 1)).toBe(true);
  });
});

describe('dnsxRecords', () => {
  const vals = (line: unknown) => dnsxRecords(JSON.stringify(line)).map((r) => `${r.type}:${r.value}`);

  it('stores no A records for a string a', () => {
    expect(vals({ host: 'x.example', a: 'abc' })).toEqual([]);
  });
  it('stores only the string entries of a list', () => {
    expect(vals({ host: 'x.example', a: [42, '192.0.2.1', ''] })).toEqual(['A:192.0.2.1']);
  });
  it('stores nothing for a non-string or empty host', () => {
    expect(vals({ host: 5, a: ['192.0.2.1'] })).toEqual([]);
    expect(vals({ host: '', a: ['192.0.2.1'] })).toEqual([]);
    expect(dnsxRecords('null')).toEqual([]);
    expect(dnsxRecords('not json')).toEqual([]);
  });
  it('stores a well-formed row as before', () => {
    const rows = dnsxRecords(JSON.stringify({
      host: 'x.example', ttl: 300, a: ['192.0.2.1'], aaaa: ['2001:db8::1'], cname: ['y.example'],
      mx: ['mx.example'], soa: [{ ns: 'ns.example', mailbox: 'h.example' }, 'ns2.example'],
    }));
    expect(rows).toEqual([
      { target: 'x.example', name: 'x.example', type: 'A', value: '192.0.2.1', ttl: 300 },
      { target: 'x.example', name: 'x.example', type: 'AAAA', value: '2001:db8::1', ttl: 300 },
      { target: 'x.example', name: 'x.example', type: 'CNAME', value: 'y.example', ttl: 300 },
      { target: 'x.example', name: 'x.example', type: 'MX', value: 'mx.example', ttl: 300 },
      { target: 'x.example', name: 'x.example', type: 'SOA', value: 'ns.example', ttl: 300 },
      { target: 'x.example', name: 'x.example', type: 'SOA', value: 'ns2.example', ttl: 300 },
    ]);
  });
});
