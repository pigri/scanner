import type { Db } from './db.js';
import { toCertRecords, quoteBigSerials, type SslyzeCertResult } from './sslyze-cert.js';
import { classifyRobot } from './sslyze-robot.js';

export interface SslyzeResult {
  server_scan_results?: Array<{
    server_location?: { hostname?: string; ip_address?: string; port?: number };
    scan_status?: string;
    scan_result?: {
      heartbleed?: { result?: { is_vulnerable_to_heartbleed?: boolean } };
      openssl_ccs_injection?: { result?: { is_vulnerable_to_ccs_injection?: boolean } };
      robot?: { result?: { robot_result?: string } };
      tls_compression?: { result?: { supports_compression?: boolean } };
      session_renegotiation?: { result?: { supports_secure_renegotiation?: boolean; is_vulnerable_to_client_renegotiation_dos?: boolean } };
      tls_extended_master_secret?: { result?: { supports_ems_extension?: boolean } };
      tls_fallback_scsv?: { result?: { supports_fallback_scsv?: boolean } };
      ssl_2_0_cipher_suites?: { result?: { is_tls_version_supported?: boolean } };
      ssl_3_0_cipher_suites?: { result?: { is_tls_version_supported?: boolean } };
      tls_1_0_cipher_suites?: { result?: { is_tls_version_supported?: boolean } };
      tls_1_1_cipher_suites?: { result?: { is_tls_version_supported?: boolean } };
      tls_1_2_cipher_suites?: { result?: { is_tls_version_supported?: boolean } };
      tls_1_3_cipher_suites?: { result?: { is_tls_version_supported?: boolean } };
      certificate_info?: { result?: {
        certificate_deployments?: Array<{
          leaf_certificate_has_must_staple_extension?: boolean;
          leaf_certificate_is_ev?: boolean;
          leaf_certificate_signed_certificate_timestamps_count?: number;
          received_chain_contains_anchor_certificate?: boolean;
          received_chain_has_valid_order?: boolean;
          verified_chain_has_sha1_signature?: boolean;
          verified_chain_has_legacy_symantec_anchor?: boolean;
          ocsp_response?: unknown;
          ocsp_response_is_trusted?: boolean;
        }>;
      } };
    };
  }>;
}

export interface SslyzeIngest { rows: number; findings: number; certs: number }

type ServerRow = NonNullable<SslyzeResult['server_scan_results']>[number];
type ScanResult = NonNullable<ServerRow['scan_result']>;
type DeploymentRow = NonNullable<NonNullable<NonNullable<ScanResult['certificate_info']>['result']>['certificate_deployments']>[number];

// Parses sslyze's JSON output; null when it is unparsable or not an object.
// Logs one line and never the content, which comes from scanned servers.
function parseSslyzeOutput(text: string): SslyzeResult | null {
  let raw: unknown;
  try {
    raw = JSON.parse(quoteBigSerials(text));
  } catch (err) {
    console.error(`sslyze: output is not valid JSON (${text.length} bytes): ${err instanceof Error ? err.name : 'error'}`);
    return null;
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    console.error('sslyze: output is not a JSON object');
    return null;
  }
  return raw as SslyzeResult;
}

// Rows that are objects with a non-empty string hostname; the rest cannot be a finding target.
function usableRows(raw: SslyzeResult): ServerRow[] {
  const all: unknown = raw.server_scan_results;
  if (!Array.isArray(all)) return [];
  return all.filter((row): row is ServerRow => {
    if (typeof row !== 'object' || row === null) return false;
    const host = (row as ServerRow).server_location?.hostname;
    return typeof host === 'string' && host !== '';
  });
}

// Stores the findings and certificates of one sslyze JSON output.
// Returns null, storing nothing, when the output is unusable.
export function ingestSslyzeOutput(db: Db, text: string, now: string, runId: number): SslyzeIngest | null {
  const raw = parseSslyzeOutput(text);
  if (!raw) return null;
  const rows = usableRows(raw);
  let findings = 0;
  const emit = (target: string, category: string, severity: string, title: string, meta: unknown): void => {
    db.insertFinding({ tool: 'sslyze', target, category, severity, title, matched_at: target, meta }, now, runId);
    findings++;
  };

  for (const row of rows) {
    const target = row.server_location?.hostname;
    if (!target || row.scan_status !== 'COMPLETED') continue;
    const s = (typeof row.scan_result === 'object' && row.scan_result !== null ? row.scan_result : {}) as ScanResult;

    // ---- known-CVE vulnerability flags ----------------------------------
    if (s.heartbleed?.result?.is_vulnerable_to_heartbleed === true) {
      emit(target, 'heartbleed', 'critical', 'Heartbleed (CVE-2014-0160) — memory disclosure', {});
    }
    if (s.openssl_ccs_injection?.result?.is_vulnerable_to_ccs_injection === true) {
      emit(target, 'ccs-injection', 'critical', 'OpenSSL CCS Injection (CVE-2014-0224) — MITM', {});
    }
    const robotResult = typeof s.robot?.result?.robot_result === 'string' ? s.robot.result.robot_result : undefined;
    const robot = classifyRobot(robotResult);
    if (robot) emit(target, 'robot', robot.severity, robot.title, { detail: robotResult });
    if (s.tls_compression?.result?.supports_compression === true) {
      emit(target, 'crime', 'medium', 'TLS compression enabled (CRIME attack path)', {});
    }
    const reneg = s.session_renegotiation?.result;
    if (reneg?.supports_secure_renegotiation === false) {
      emit(target, 'secure-renegotiation', 'high', 'Server does not support secure TLS renegotiation', {});
    }
    if (reneg?.is_vulnerable_to_client_renegotiation_dos === true) {
      emit(target, 'client-renegotiation-dos', 'high', 'Vulnerable to client-initiated renegotiation DoS', {});
    }

    // ---- deprecated protocol support ------------------------------------
    if (s.ssl_2_0_cipher_suites?.result?.is_tls_version_supported === true) {
      emit(target, 'sslv2', 'critical', 'SSLv2 supported (DROWN / broken)', {});
    }
    if (s.ssl_3_0_cipher_suites?.result?.is_tls_version_supported === true) {
      emit(target, 'sslv3', 'high', 'SSLv3 supported (POODLE / deprecated)', {});
    }
    if (s.tls_1_0_cipher_suites?.result?.is_tls_version_supported === true) {
      emit(target, 'tls-1.0', 'medium', 'TLS 1.0 supported (deprecated; PCI-DSS non-compliant)', {});
    }
    if (s.tls_1_1_cipher_suites?.result?.is_tls_version_supported === true) {
      emit(target, 'tls-1.1', 'medium', 'TLS 1.1 supported (deprecated; PCI-DSS non-compliant)', {});
    }
    if (s.tls_1_3_cipher_suites?.result?.is_tls_version_supported === false) {
      emit(target, 'no-tls-1.3', 'low', 'TLS 1.3 NOT supported — modern clients fall back', {});
    }

    // ---- TLS session hardening ------------------------------------------
    if (s.tls_extended_master_secret?.result?.supports_ems_extension === false) {
      emit(target, 'no-ems', 'low', 'Extended Master Secret (RFC 7627) not supported — weakens session binding', {});
    }
    if (s.tls_fallback_scsv?.result?.supports_fallback_scsv === false) {
      emit(target, 'no-fallback-scsv', 'low', 'TLS_FALLBACK_SCSV not supported — downgrade attack risk', {});
    }

    // ---- Certificate deployment quality ---------------------------------
    const deps: unknown = s.certificate_info?.result?.certificate_deployments;
    const dep = Array.isArray(deps) && typeof deps[0] === 'object' && deps[0] !== null && !Array.isArray(deps[0]) ? (deps[0] as DeploymentRow) : undefined;
    if (dep) {
      if (dep.verified_chain_has_sha1_signature === true) {
        emit(target, 'chain-sha1', 'medium', 'Certificate chain contains SHA-1 signature (browsers block)', {});
      }
      if (dep.verified_chain_has_legacy_symantec_anchor === true) {
        emit(target, 'symantec-anchor', 'medium', 'Chain terminates in a distrusted Symantec-era CA', {});
      }
      if (dep.received_chain_has_valid_order === false) {
        emit(target, 'chain-order', 'low', 'Certificate chain sent in wrong order (some clients reject)', {});
      }
      const sctRaw = dep.leaf_certificate_signed_certificate_timestamps_count;
      const sctCount = typeof sctRaw === 'number' ? sctRaw : 0;
      if (sctCount < 2) {
        emit(target, 'sct-count', 'low', `Only ${sctCount} SCT(s) embedded — Chrome/Safari require ≥ 2`, { count: sctCount });
      }
      if (dep.leaf_certificate_has_must_staple_extension === true && dep.ocsp_response_is_trusted !== true) {
        emit(target, 'ocsp-must-staple', 'medium', 'must-staple set but no valid OCSP response returned', {});
      }
    }
  }

  // Certificate inventory: sslyze collects the full leaf cert reliably, so it
  // is the inventory source. Dedup is INSERT OR IGNORE on
  // UNIQUE(target, port, fingerprint_sha256).
  let certs = 0;
  for (const cert of toCertRecords({ server_scan_results: rows } as SslyzeCertResult)) {
    db.insertCertificate(cert, now, runId);
    certs++;
  }

  return { rows: rows.length, findings, certs };
}

// Ingests one sslyze output and always finishes the run and closes the db, even when
// ingest throws; the error is logged and rethrown, not swallowed.
export function ingestAndFinishRun(db: Db, text: string, now: string, runId: number, scanned: number): SslyzeIngest | null {
  let result: SslyzeIngest | null = null;
  try {
    result = ingestSslyzeOutput(db, text, now, runId);
    return result;
  } catch (err) {
    console.error(`sslyze: ingest failed: ${err instanceof Error ? err.message : String(err)}`);
    throw err;
  } finally {
    db.finishRun(runId, {
      targetsCount: result ? result.rows : scanned,
      findingsCount: result ? result.findings : 0,
      at: new Date().toISOString(),
    });
    db.close();
  }
}
