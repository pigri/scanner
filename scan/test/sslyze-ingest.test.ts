import { describe, it, expect, vi, afterEach } from 'vitest';
import { openDb } from '../src/lib/db.js';
import { ingestSslyzeOutput, ingestAndFinishRun, SSLYZE_READ_COMMANDS, SSLYZE_COVERAGE_COMMANDS, SSLYZE_SCAN_FLAGS } from '../src/lib/sslyze-ingest.js';

const NOW = '2026-01-01T00:00:00.000Z';

// Every command the ingester reads, finished; `over` replaces single commands.
const allCommands = (over: Record<string, unknown> = {}): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const c of SSLYZE_READ_COMMANDS) out[c] = { status: 'COMPLETED', result: {} };
  return { ...out, ...over };
};
// Shaped like real output: ssl_2_0 is never scheduled, tls_1_2 and session_resumption are scheduled but unread.
const realShape = (over: Record<string, unknown> = {}): Record<string, unknown> => allCommands({
  ssl_2_0_cipher_suites: { status: 'NOT_SCHEDULED', result: null },
  tls_1_2_cipher_suites: { status: 'COMPLETED', result: { is_tls_version_supported: true } },
  session_resumption: { status: 'COMPLETED', result: {} },
  ...over,
});
const done = (result: unknown) => ({ status: 'COMPLETED', result });

const good = (hostname: unknown = 'host.example.com') => ({
  server_location: { hostname, ip_address: '192.0.2.1', port: 443 },
  scan_status: 'COMPLETED',
  scan_result: allCommands({
    heartbleed: done({ is_vulnerable_to_heartbleed: true }),
    tls_1_0_cipher_suites: done({ is_tls_version_supported: true }),
    certificate_info: done({ certificate_deployments: [{
      leaf_certificate_signed_certificate_timestamps_count: 0,
      received_certificate_chain: [{
        fingerprint_sha256: 'uTDvCVyiwPnM5M+7A6dM3WS6KZQGb8e8OFfrWcnlLHk=',
        serial_number: 'BIGSERIAL',
      }],
    }] }),
  }),
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
    expect(r).toEqual({ rows: 1, findings: 3, certs: 1, covered: ['host.example.com'] });
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
    expect(r).toEqual({ rows: 0, findings: 0, certs: 0, covered: [] });
  });

  it('counts a missing server_scan_results as empty', () => {
    const { db, runId } = setup();
    expect(ingestSslyzeOutput(db, '{}', NOW, runId)).toEqual({ rows: 0, findings: 0, certs: 0, covered: [] });
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

const coverage = (db: ReturnType<typeof openDb>) =>
  db.raw.prepare('SELECT target, tool, seen_at, run_id FROM tool_coverage ORDER BY target').all();
const withStatus = (hostname: string, scan_status: string) => ({ ...good(hostname), scan_status });

describe('sslyze coverage', () => {
  it('gates coverage on exactly these commands', () => {
    expect([...SSLYZE_READ_COMMANDS]).toEqual([
      'heartbleed', 'openssl_ccs_injection', 'robot', 'tls_compression', 'session_renegotiation',
      'tls_extended_master_secret', 'tls_fallback_scsv', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
      'tls_1_1_cipher_suites', 'tls_1_3_cipher_suites', 'certificate_info',
    ]);
  });

  it('only gates on commands whose flag the wrapper passes', () => {
    for (const flag of Object.values(SSLYZE_COVERAGE_COMMANDS)) expect(SSLYZE_SCAN_FLAGS).toContain(flag);
  });

  it('covers a row shaped like real output, with ssl_2_0 NOT_SCHEDULED', () => {
    const { db, runId } = setup();
    const row = { ...good('real.example.com'), scan_result: realShape() };
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: [row] }), NOW, runId);
    expect(r?.covered).toEqual(['real.example.com']);
  });

  it.each(SSLYZE_READ_COMMANDS)('does not cover a row whose %s is NOT_SCHEDULED', (cmd) => {
    const { db, runId } = setup();
    const row = { ...good('ns.example.com'), scan_result: realShape({ [cmd]: { status: 'NOT_SCHEDULED', result: null } }) };
    expect(ingestSslyzeOutput(db, toText({ server_scan_results: [row] }), NOW, runId)?.covered).toEqual([]);
  });

  it('covers a COMPLETED row with the findings target, stamp and run', () => {
    const { db, runId } = setup();
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: [good('host.example.com')] }), NOW, runId);
    expect(r?.covered).toEqual(['host.example.com']);
    expect(coverage(db)).toEqual([{ target: 'host.example.com', tool: 'sslyze', seen_at: NOW, run_id: runId }]);
    expect(findings(db)[0]!.target).toBe('host.example.com');
  });

  it('covers a COMPLETED row that produced no findings', () => {
    const { db, runId } = setup();
    const quiet = { server_location: { hostname: 'quiet.example.com', ip_address: '192.0.2.2', port: 443 }, scan_status: 'COMPLETED', scan_result: allCommands() };
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: [quiet] }), NOW, runId);
    expect(r?.findings).toBe(0);
    expect(coverage(db)).toEqual([{ target: 'quiet.example.com', tool: 'sslyze', seen_at: NOW, run_id: runId }]);
  });

  it.each(SSLYZE_READ_COMMANDS)('does not cover a COMPLETED row whose %s command errored', (cmd) => {
    const { db, runId } = setup();
    const errored = { status: 'ERROR', error_reason: 'CONNECTIVITY_ISSUE', result: null };
    const row = { ...good('err.example.com'), scan_result: allCommands({ [cmd]: errored }) };
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: [row] }), NOW, runId);
    expect(r?.covered).toEqual([]);
    expect(coverage(db)).toEqual([]);
  });

  it('keeps an earlier tls-1.0 finding current when the tls_1_0 command errored', () => {
    const { db, runId } = setup();
    db.insertFinding({ tool: 'sslyze', target: 'err.example.com', category: 'tls-1.0', severity: 'medium', title: 'TLS 1.0 supported' }, '2025-12-01T00:00:00.000Z', runId);
    const errored = { status: 'ERROR', error_reason: 'CONNECTIVITY_ISSUE', result: null };
    const row = { ...good('err.example.com'), scan_result: allCommands({ tls_1_0_cipher_suites: errored }) };
    ingestSslyzeOutput(db, toText({ server_scan_results: [row] }), NOW, runId);
    expect(coverage(db)).toEqual([]);
  });

  it('does not cover a COMPLETED row that lacks a command the ingester reads', () => {
    const { db, runId } = setup();
    const bare = { server_location: { hostname: 'bare.example.com', port: 443 }, scan_status: 'COMPLETED', scan_result: {} };
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: [bare] }), NOW, runId);
    expect(r?.covered).toEqual([]);
  });

  it('covers nothing and throws when a findings insert fails', () => {
    const { db, runId } = setup();
    db.raw.exec("CREATE TRIGGER t BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'database is locked'); END");
    expect(() => ingestSslyzeOutput(db, toText({ server_scan_results: [good()] }), NOW, runId)).toThrow(/locked/);
    expect(coverage(db)).toEqual([]);
  });

  it.each(['ERROR_NO_CONNECTIVITY', 'ERROR_CONNECTIVITY_TIMEOUT', 'NOT_SCANNED'])('does not cover a %s row', (status) => {
    const { db, runId } = setup();
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: [withStatus('down.example.com', status)] }), NOW, runId);
    expect(r?.covered).toEqual([]);
    expect(coverage(db)).toEqual([]);
  });

  it('does not cover a host when any of its rows is not COMPLETED', () => {
    const { db, runId } = setup();
    const rows = [good('mixed.example.com'), withStatus('mixed.example.com', 'ERROR_NO_CONNECTIVITY'), good('ok.example.com')];
    const r = ingestSslyzeOutput(db, toText({ server_scan_results: rows }), NOW, runId);
    expect(r?.covered).toEqual(['ok.example.com']);
    expect(coverage(db).map((c) => (c as { target: string }).target)).toEqual(['ok.example.com']);
  });

  it('adds a run note and still returns the ingest when the coverage write fails', () => {
    const { db, runId } = setup();
    vi.spyOn(db, 'recordCoverage').mockReturnValue(false);
    const finish = vi.spyOn(db, 'finishRun');
    const r = ingestAndFinishRun(db, () => toText({ server_scan_results: [good()] }), NOW, runId, 1);
    expect(r?.findings).toBe(3);
    expect(finish).toHaveBeenCalledWith(runId, expect.objectContaining({ notes: 'tool_coverage write failed: scan.db busy' }));
  });
});

describe('ingestAndFinishRun', () => {
  const text = (): string => toText({ server_scan_results: [good()] });

  it('finishes the run and closes the db after a normal ingest', () => {
    const { db, runId } = setup();
    const finish = vi.spyOn(db, 'finishRun');
    const close = vi.spyOn(db, 'close');
    const r = ingestAndFinishRun(db, () => text(), NOW, runId, 9);
    expect(r).toEqual({ rows: 1, findings: 3, certs: 1, covered: ['host.example.com'] });
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
