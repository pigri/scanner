import { describe, it, expect, vi, afterEach } from 'vitest';
import { openDb } from '../src/lib/db.js';
import { ingestSslyzeOutput } from '../src/lib/sslyze-ingest.js';

const NOW = '2026-01-01T00:00:00.000Z';

const good = (hostname: unknown = 'host.example.com') => ({
  server_location: { hostname, ip_address: '192.0.2.1', port: 443 },
  scan_status: 'COMPLETED',
  scan_result: {
    heartbleed: { result: { is_vulnerable_to_heartbleed: true } },
    tls_1_0_cipher_suites: { result: { is_tls_version_supported: true } },
    certificate_info: { result: { certificate_deployments: [{
      leaf_certificate_signed_certificate_timestamps_count: 0,
      received_certificate_chain: [{
        fingerprint_sha256: 'uTDvCVyiwPnM5M+7A6dM3WS6KZQGb8e8OFfrWcnlLHk=',
        serial_number: 'BIGSERIAL',
      }],
    }] } },
  },
});

// sslyze emits serials as bare integers beyond 2^53, which JSON.stringify cannot produce.
const toText = (v: unknown): string =>
  JSON.stringify(v).replace(/"BIGSERIAL"/g, '12345678901234567890123456789');

function setup() {
  const db = openDb(':memory:');
  const runId = db.startRun('sslyze', {}, NOW);
  return { db, runId };
}
const findings = (db: ReturnType<typeof openDb>) =>
  db.raw.prepare('SELECT target, category FROM findings ORDER BY id').all() as { target: string; category: string }[];
const certCount = (db: ReturnType<typeof openDb>) =>
  (db.raw.prepare('SELECT COUNT(*) AS n FROM certificates').get() as { n: number }).n;

afterEach(() => vi.restoreAllMocks());

describe('ingestSslyzeOutput', () => {
  it('stores findings and certificates of well-formed output', () => {
    const { db, runId } = setup();
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: [good()] }), NOW, runId);
    expect(r).toEqual({ rows: 1, findings: 3, certs: 1 });
    expect(findings(db).map((f) => f.category)).toEqual(['heartbleed', 'tls-1.0', 'sct-count']);
    expect(certCount(db)).toBe(1);
  });

  it.each([
    ['truncated JSON', '{"server_scan_results": [{"server_loc'],
    ['empty file', ''],
    ['invalid JSON', 'not json'],
    ['top-level null', 'null'],
    ['top-level array', '[]'],
    ['top-level number', '7'],
    ['top-level string', '"x"'],
  ])('returns null and records nothing for %s', (_n, text) => {
    const { db, runId } = setup();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(ingestSslyzeOutput(db, text, NOW, runId)).toBeNull();
    expect(findings(db)).toEqual([]);
    expect(certCount(db)).toBe(0);
    expect(log).toHaveBeenCalledTimes(1);
  });

  it('does not log the file content', () => {
    const { db, runId } = setup();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    ingestSslyzeOutput(db, 'SECRET-TOKEN-xyz {', NOW, runId);
    expect(String(log.mock.calls[0]?.[0])).not.toContain('SECRET-TOKEN-xyz');
  });

  it.each([
    ['object', { a: 1 }],
    ['null', null],
    ['string', 'x'],
  ])('counts a %s server_scan_results as empty', (_n, v) => {
    const { db, runId } = setup();
    const r = ingestSslyzeOutput(db, JSON.stringify({ server_scan_results: v }), NOW, runId);
    expect(r).toEqual({ rows: 0, findings: 0, certs: 0 });
  });

  it('counts a missing server_scan_results as empty', () => {
    const { db, runId } = setup();
    expect(ingestSslyzeOutput(db, '{}', NOW, runId)).toEqual({ rows: 0, findings: 0, certs: 0 });
  });

  it('skips non-object elements and bad hostnames, keeps the good row', () => {
    const { db, runId } = setup();
    const rows = [null, 'x', 5, [], good(42), good(''), good(null), good({ a: 1 }), good('ok.example.com')];
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: rows }), NOW, runId);
    expect(r?.findings).toBe(3);
    expect(r?.certs).toBe(1);
    expect(new Set(findings(db).map((f) => f.target))).toEqual(new Set(['ok.example.com']));
  });
});
