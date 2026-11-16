import { describe, it, expect, vi, afterEach } from 'vitest';
import { openDb } from '../src/lib/db.js';
import { ingestSslyzeOutput, ingestAndFinishRun } from '../src/lib/sslyze-ingest.js';

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

describe('ingestSslyzeOutput: wrong-typed nested fields', () => {
  const row = (scan_result: unknown) => ({
    server_location: { hostname: 'h.example.com', port: 443 }, scan_status: 'COMPLETED', scan_result,
  });
  const run = (scan_result: unknown) => {
    const { db, runId } = setup();
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: [row(scan_result)] }), NOW, runId);
    return { db, r };
  };
  const certInfo = (certificate_deployments: unknown) => ({ certificate_info: { result: { certificate_deployments } } });

  it.each([['string', 'abc'], ['object', { a: 1 }], ['number', 5], ['null', null]])(
    'stores nothing for %s certificate_deployments', (_n, v) => {
      const { db, r } = run(certInfo(v));
      expect(r).toMatchObject({ findings: 0, certs: 0 });
      expect(findings(db)).toEqual([]);
    });

  it.each([['null', null], ['string', 'abc'], ['number', 5], ['array', []]])(
    'skips a %s first deployment without a finding', (_n, v) => {
      const { db, r } = run(certInfo([v]));
      expect(r).toMatchObject({ findings: 0, certs: 0 });
      expect(findings(db)).toEqual([]);
    });

  it('does not throw and stores nothing when every nested field has the wrong type', () => {
    const wrong = 'yes';
    const { db, r } = run({
      heartbleed: { result: { is_vulnerable_to_heartbleed: wrong } },
      openssl_ccs_injection: { result: { is_vulnerable_to_ccs_injection: wrong } },
      robot: { result: { robot_result: 5 } },
      tls_compression: { result: { supports_compression: wrong } },
      session_renegotiation: { result: { supports_secure_renegotiation: wrong, is_vulnerable_to_client_renegotiation_dos: wrong } },
      tls_extended_master_secret: { result: { supports_ems_extension: wrong } },
      tls_fallback_scsv: { result: { supports_fallback_scsv: wrong } },
      ssl_2_0_cipher_suites: { result: { is_tls_version_supported: wrong } },
      ssl_3_0_cipher_suites: { result: { is_tls_version_supported: wrong } },
      tls_1_0_cipher_suites: { result: { is_tls_version_supported: wrong } },
      tls_1_1_cipher_suites: { result: { is_tls_version_supported: wrong } },
      tls_1_3_cipher_suites: { result: { is_tls_version_supported: wrong } },
      ...certInfo([{
        leaf_certificate_has_must_staple_extension: wrong,
        leaf_certificate_signed_certificate_timestamps_count: 5,
        verified_chain_has_sha1_signature: wrong,
        verified_chain_has_legacy_symantec_anchor: wrong,
        received_chain_has_valid_order: wrong,
        ocsp_response_is_trusted: wrong,
        received_certificate_chain: [{ fingerprint_sha256: 5, subject: 5, serial_number: {} }],
      }]),
    });
    expect(r).toMatchObject({ certs: 0 });
    expect(findings(db)).toEqual([]);
  });

  it.each([['string', 'abc'], ['number', 5], ['array', [1]], ['true', true]])(
    'does not throw for a %s scan_result', (_n, v) => {
      expect(run(v).r).toMatchObject({ findings: 0, certs: 0 });
    });

  it('treats a non-numeric SCT count as missing', () => {
    const { db } = run(certInfo([{ leaf_certificate_signed_certificate_timestamps_count: 'many' }]));
    expect(findings(db).map((f) => f.category)).toEqual(['sct-count']);
  });
});

describe('ingestAndFinishRun', () => {
  const text = (): string => toText({ server_scan_results: [good()] });

  it('finishes the run and closes the db after a normal ingest', () => {
    const { db, runId } = setup();
    const finish = vi.spyOn(db, 'finishRun');
    const close = vi.spyOn(db, 'close');
    const r = ingestAndFinishRun(db, () => text(), NOW, runId, 9);
    expect(r).toEqual({ rows: 1, findings: 3, certs: 1 });
    expect(finish).toHaveBeenCalledWith(runId, expect.objectContaining({ targetsCount: 1, findingsCount: 3 }));
    expect(close).toHaveBeenCalledTimes(1);
  });

  it('finishes the run with the scanned count when the output is unusable', () => {
    const { db, runId } = setup();
    const finish = vi.spyOn(db, 'finishRun');
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(ingestAndFinishRun(db, () => 'null', NOW, runId, 9)).toBeNull();
    expect(finish).toHaveBeenCalledWith(runId, expect.objectContaining({ targetsCount: 9, findingsCount: 0 }));
  });

  it('still finishes the run and closes the db when ingest throws, and rethrows', () => {
    const { db, runId } = setup();
    vi.spyOn(db, 'insertFinding').mockImplementation(() => { throw new Error('boom'); });
    const finish = vi.spyOn(db, 'finishRun');
    const close = vi.spyOn(db, 'close');
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => ingestAndFinishRun(db, () => text(), NOW, runId, 9)).toThrow('boom');
    expect(finish).toHaveBeenCalledWith(runId, expect.objectContaining({ targetsCount: 9, findingsCount: 0 }));
    expect(close).toHaveBeenCalledTimes(1);
    expect(log.mock.calls.map((c) => String(c[0])).join('\n')).toContain('boom');
  });

  it('finishes the run and closes the db when the file cannot be read, without rethrowing', () => {
    const { db, runId } = setup();
    const finish = vi.spyOn(db, 'finishRun');
    const close = vi.spyOn(db, 'close');
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const read = (): string => { throw Object.assign(new Error('EACCES: /secret/path'), { code: 'EACCES' }); };
    expect(ingestAndFinishRun(db, read, NOW, runId, 9)).toBeNull();
    expect(finish).toHaveBeenCalledWith(runId, expect.objectContaining({ targetsCount: 9, findingsCount: 0 }));
    expect(close).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledTimes(1);
    expect(String(log.mock.calls[0]?.[0])).not.toContain('/secret/path');
  });
});
