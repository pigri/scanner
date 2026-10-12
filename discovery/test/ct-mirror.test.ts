import { describe, it, expect, vi, afterEach } from 'vitest';
import { X509Certificate, createHash, generateKeyPairSync, createSign } from 'node:crypto';
import {
  extractCn,
  extractO,
  extractDnsNames,
  normaliseSuffix,
  matchScope,
  scopedMatches,
  parseEntry,
  type ParsedEntry,
} from '../src/lib/ct-mirror.js';
import { ingest, ingestFromEnv } from '../src/lib/axiom.js';
import { shardStatus, buildStatusEvents } from '../src/ct-mirror.js';

// Minimal helper: generate a self-signed cert with the given CN + SAN dnsNames.
// Uses node's built-in KeyObject.export('spki'/'pkcs8') + a hand-rolled X.509
// isn't tractable in stdlib alone, so we import a couple of real prod certs as
// base64 DER fixtures instead. See DER_FIXTURES below.

// Real prod cert fixtures pulled from Google Argon 2026h1 entries around
// #2807501278. Base64 DER. These are public CT log entries, no secrets.
const DER_MAKEIT = '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';
const DER_YUNSMAI = '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';

describe('extractCn / extractO', () => {
  it('parses CN out of a multi-line subject', () => {
    expect(extractCn('CN=example.com\nO=Example Corp')).toBe('example.com');
    expect(extractCn('O=Corp\nCN=Foo.Example.COM')).toBe('foo.example.com'); // lowercased
    expect(extractCn('O=Corp')).toBeNull();
    expect(extractCn('CN=')).toBeNull(); // empty → null
  });
  it('returns null on undefined / empty subject (defends against malformed CT entries)', () => {
    expect(extractCn(undefined)).toBeNull();
    expect(extractCn(null)).toBeNull();
    expect(extractCn('')).toBeNull();
  });
  it('parses O out of an issuer', () => {
    expect(extractO("CN=WE2\nO=Google Trust Services\nC=US")).toBe('Google Trust Services');
    expect(extractO('C=US\nCN=root')).toBeNull();
  });
  it('returns null on undefined / empty issuer', () => {
    expect(extractO(undefined)).toBeNull();
    expect(extractO(null)).toBeNull();
    expect(extractO('')).toBeNull();
  });
});

describe('extractDnsNames from a real cert', () => {
  it('pulls both SAN entries', () => {
    const cert = new X509Certificate(Buffer.from(DER_MAKEIT, 'base64'));
    const names = extractDnsNames(cert);
    expect(names).toContain('makeitwhatyouwant.com');
    expect(names).toContain('www.makeitwhatyouwant.com');
    expect(names).toHaveLength(2);
  });
  it('deduplicates when CN matches a SAN entry', () => {
    const cert = new X509Certificate(Buffer.from(DER_YUNSMAI, 'base64'));
    const names = extractDnsNames(cert);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toContain('yunsmai.com');
    expect(names).toContain('www.yunsmai.com');
  });
});

describe('parseEntry', () => {
  it('produces normalised shape with ISO timestamp + sha256 + names', () => {
    const parsed = parseEntry({
      entry_number: 42,
      timestamp: 1786099638408, // real Argon2026h1 SCT timestamp for this cert
      certificate: DER_MAKEIT,
    });
    expect(parsed.entryId).toBe(42);
    expect(parsed.sctAt).toBe('2026-08-07T10:47:18.408Z');
    expect(parsed.cn).toBe('makeitwhatyouwant.com');
    expect(parsed.issuerO).toBe('Sectigo Limited');
    expect(parsed.certDerSha256).toMatch(/^[0-9a-f]{64}$/);
    const expectSha = createHash('sha256').update(Buffer.from(DER_MAKEIT, 'base64')).digest('hex');
    expect(parsed.certDerSha256).toBe(expectSha);
    expect(parsed.dnsNames.sort()).toEqual(['makeitwhatyouwant.com', 'www.makeitwhatyouwant.com']);
  });
});

describe('normaliseSuffix', () => {
  it('strips leading dot, lowercases, ignores comments and blanks', () => {
    expect(normaliseSuffix('.gov.hu')).toBe('gov.hu');
    expect(normaliseSuffix('GOV.HU')).toBe('gov.hu');
    expect(normaliseSuffix('  .nisz.hu   ')).toBe('nisz.hu');
    expect(normaliseSuffix('# comment')).toBeNull();
    expect(normaliseSuffix('')).toBeNull();
    expect(normaliseSuffix('  ')).toBeNull();
    expect(normaliseSuffix('foo # inline comment')).toBeNull(); // inline comment leaves 'foo' which is single-label
    expect(normaliseSuffix('84.206.0.0/16')).toBeNull(); // CIDR — not applicable
    expect(normaliseSuffix('localhost')).toBeNull();     // no dot
  });
});

describe('matchScope', () => {
  const suffixes = ['gov.hu', 'nisz.hu', 'bar.gov.hu'];
  it('exact suffix match on apex', () => {
    expect(matchScope('gov.hu', suffixes)).toEqual({
      dnsName: 'gov.hu', isWildcard: false, matchedSuffix: 'gov.hu',
    });
  });
  it('subdomain match', () => {
    expect(matchScope('www.foo.gov.hu', suffixes)).toEqual({
      dnsName: 'www.foo.gov.hu', isWildcard: false, matchedSuffix: 'gov.hu',
    });
  });
  it('longest-suffix wins', () => {
    expect(matchScope('x.bar.gov.hu', suffixes)?.matchedSuffix).toBe('bar.gov.hu');
  });
  it('is case-insensitive on the DNS name', () => {
    expect(matchScope('Foo.GOV.HU', suffixes)?.dnsName).toBe('foo.gov.hu');
  });
  it('wildcard SAN matches when the parent zone matches', () => {
    expect(matchScope('*.foo.gov.hu', suffixes)).toEqual({
      dnsName: 'foo.gov.hu', isWildcard: true, matchedSuffix: 'gov.hu',
    });
  });
  it('unrelated domain returns null', () => {
    expect(matchScope('example.com', suffixes)).toBeNull();
    expect(matchScope('notgov.hu', suffixes)).toBeNull(); // no dot boundary — must not match gov.hu
  });
  it('rejects near-miss (would-be-substring) matches', () => {
    // 'agov.hu' has 'gov.hu' as a substring but not as a suffix at label boundary.
    expect(matchScope('agov.hu', suffixes)).toBeNull();
  });
});

describe('scopedMatches (integration on ParsedEntry)', () => {
  const suffixes = ['makeitwhatyouwant.com']; // pretend this domain is in scope
  it('returns dedup entries via (dnsName, isWildcard) tuple', () => {
    const parsed: ParsedEntry = {
      entryId: 1, sctAt: '2026-01-01T00:00:00.000Z',
      cn: 'makeitwhatyouwant.com', issuerO: 'X', certDerSha256: 'x',
      dnsNames: ['makeitwhatyouwant.com', 'www.makeitwhatyouwant.com', '*.makeitwhatyouwant.com', 'makeitwhatyouwant.com'],
    };
    const matches = scopedMatches(parsed, suffixes);
    expect(matches).toHaveLength(3);
    const map = new Map(matches.map((m) => [`${m.isWildcard ? '*' : '-'}|${m.dnsName}`, m]));
    expect(map.has('-|makeitwhatyouwant.com')).toBe(true);
    expect(map.has('-|www.makeitwhatyouwant.com')).toBe(true);
    expect(map.has('*|makeitwhatyouwant.com')).toBe(true);
  });
  it('returns [] when no names match scope', () => {
    const parsed: ParsedEntry = {
      entryId: 1, sctAt: '2026-01-01T00:00:00.000Z',
      cn: null, issuerO: null, certDerSha256: 'x',
      dnsNames: ['example.com', 'unrelated.net'],
    };
    expect(scopedMatches(parsed, suffixes)).toEqual([]);
  });
});

describe('shardStatus', () => {
  const row = {
    label: 'argon2026h1', log_url: 'https://ct.example/log/',
    baseline_tree_size: 100, last_entry_id: 900, updated_at: '2026-01-01T00:00:00.000Z',
  };
  it('computes lag as tree_size - last_entry_id', () => {
    expect(shardStatus(row, 1000)).toEqual({
      label: 'argon2026h1', last_entry_id: 900, tree_size: 1000, lag: 100,
      updated_at: '2026-01-01T00:00:00.000Z',
    });
  });
  it('clamps negative lag to 0 when the cursor exceeds a stale tree head', () => {
    expect(shardStatus(row, 850).lag).toBe(0);
  });
});

describe('buildStatusEvents (heartbeat)', () => {
  it('builds one ct_status event per shard with run_type heartbeat', () => {
    const evs = buildStatusEvents('heartbeat', [
      { label: 'a', last_entry_id: 5, tree_size: 15, lag: 10, updated_at: 'u' },
      { label: 'b', last_entry_id: 20, tree_size: 10, lag: 0, updated_at: 'u' },
    ], '2026-01-01T00:00:00.000Z');
    expect(evs).toHaveLength(2);
    expect(evs[0]).toMatchObject({
      _time: '2026-01-01T00:00:00.000Z', event: 'ct_status', run_type: 'heartbeat',
      shard: 'a', last_entry_id: 5, tree_size: 15, lag: 10, result: 'ok',
    });
    expect(evs[1]).toMatchObject({ shard: 'b', lag: 0 });
  });
});

describe('axiom ingest', () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

  it('POSTs a JSON array with bearer auth and defaults _time', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);
    await ingest([{ event: 'ct_status', shard: 'a' }, { event: 'x', _time: 'T' }],
      { dataset: 'ds', token: 'tok', url: 'https://axiom.test/' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://axiom.test/v1/datasets/ds/ingest');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer tok');
    expect(init.headers['Content-Type']).toBe('application/json');
    const body = JSON.parse(init.body);
    expect(Array.isArray(body)).toBe(true);
    expect(body[0].shard).toBe('a');
    expect(typeof body[0]._time).toBe('string');
    expect(body[1]._time).toBe('T');
  });

  it('uses https://api.axiom.co when url is omitted', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);
    await ingest([{ a: 1 }], { dataset: 'ds', token: 't' });
    expect(fetchMock.mock.calls[0]![0]).toBe('https://api.axiom.co/v1/datasets/ds/ingest');
  });

  it('does not throw on a non-2xx response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await expect(ingest([{ a: 1 }], { dataset: 'ds', token: 't' })).resolves.toBeUndefined();
  });

  it('does not throw when fetch rejects', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('boom')));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await expect(ingest([{ a: 1 }], { dataset: 'ds', token: 't' })).resolves.toBeUndefined();
  });

  it('is a no-op (with a warning) when env is unset', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    vi.stubEnv('AXIOM_INGEST_TOKEN', '');
    vi.stubEnv('AXIOM_DATASET', '');
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    await expect(ingestFromEnv([{ a: 1 }])).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled();
  });

  it('ingestFromEnv honours AXIOM_URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);
    vi.stubEnv('AXIOM_INGEST_TOKEN', 'tok');
    vi.stubEnv('AXIOM_DATASET', 'ds');
    vi.stubEnv('AXIOM_URL', 'https://axiom.test');
    await ingestFromEnv([{ a: 1 }]);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://axiom.test/v1/datasets/ds/ingest');
  });
});
