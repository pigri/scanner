#!/usr/bin/env -S node --loader tsx
// sslyze — modern TLS audit. Complements testssl: catches ROBOT/CCS/Heartbleed
// as typed findings, verifies certificate chain-order and SCT count, flags
// SSLv3/TLS 1.0/1.1 protocol support, and audits session-renegotiation +
// TLS-extended-master-secret which testssl only partially covers.
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, resolveOutputPath } from './lib/runner.js';
import { openDb, type Db } from './lib/db.js';

// Live-HTTPS targets from either http_probes (https://) or a 443/tcp port.
function loadHttpsTargets(db: Db, targets: readonly string[]): string[] {
  if (!targets.length) return [];
  const p = targets.map(() => '?').join(',');
  const httpsRows = db.raw.prepare(
    `SELECT DISTINCT target FROM http_probes
     WHERE target IN (${p}) AND url LIKE 'https://%'`
  ).all(...targets) as { target: string }[];
  const portRows = db.raw.prepare(
    `SELECT DISTINCT target FROM ports WHERE target IN (${p}) AND port = 443`
  ).all(...targets) as { target: string }[];
  const set = new Set<string>();
  for (const r of httpsRows) set.add(r.target);
  for (const r of portRows) set.add(r.target);
  return [...set];
}

interface SslyzeResult {
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

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  let liveOnly = true;
  let slow = false;
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    if (a === '--no-live-only') liveOnly = false;
    else if (a === '--slow') slow = true;
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('sslyze', `
sslyze — modern TLS audit per HTTPS target. Emits findings for known-vuln
positives (Heartbleed / ROBOT / CCS / CRIME), deprecated-protocol support
(SSLv2/3, TLS 1.0/1.1), and certificate-chain quality (SHA-1, Symantec
anchor, SCT count, chain order, OCSP must-staple).

Defaults: --certinfo --heartbleed --openssl_ccs --robot --fallback
          --compression --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 --sslv3
          --reneg --resum --ems. Runs one process across all targets in
          parallel via --targets_in.

Wrapper flags (before '--'):
  --slow                 pass --slow_connection (fewer parallel conns)
  --no-live-only         include hosts httpx never saw alive (or with 443 open)`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('sslyze');
  if (!opts.sqlite) { console.error('sslyze: --sqlite is required'); process.exit(1); }

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const now = new Date().toISOString();
  const db = openDb(opts.sqlite);
  const runId = db.startRun('sslyze', { targets: targets.length, liveOnly, slow }, now);

  let scanTargets: string[];
  if (liveOnly) {
    scanTargets = loadHttpsTargets(db, targets);
    console.error(`live-only filter: ${targets.length} → ${scanTargets.length}`);
  } else {
    scanTargets = [...targets];
  }
  if (!scanTargets.length) {
    console.error('no HTTPS targets to scan');
    db.finishRun(runId, { targetsCount: 0, findingsCount: 0, at: new Date().toISOString() });
    db.close();
    return;
  }

  const tmp = resolveOutputPath({ ...opts, outFile: null }, runId, 'sslyze-targets.txt');
  fs.writeFileSync(tmp, scanTargets.join('\n') + '\n');
  const outFile = resolveOutputPath(opts, runId, 'sslyze.json');

  const args = [
    '--targets_in', tmp,
    '--json_out', outFile,
    '--quiet',
    '--certinfo', '--heartbleed', '--openssl_ccs', '--robot', '--fallback',
    '--compression', '--reneg', '--resum', '--ems',
    '--sslv3', '--tlsv1', '--tlsv1_1', '--tlsv1_2', '--tlsv1_3',
    ...(slow ? ['--slow_connection'] : []),
    ...passthrough,
  ];
  console.error(`sslyze ${args.slice(0, 6).join(' ')} ... (${scanTargets.length} target(s))`);
  const r = await run('sslyze', args, { timeoutMs: Math.max(60 * scanTargets.length, 600) * 1000 });
  console.error(`sslyze exited ${r.code}`);
  if (r.code !== 0 && r.stderr) console.error(r.stderr.slice(0, 500));

  if (!fs.existsSync(outFile)) {
    db.finishRun(runId, { targetsCount: scanTargets.length, findingsCount: 0, at: new Date().toISOString() });
    db.close();
    return;
  }

  const raw = JSON.parse(fs.readFileSync(outFile, 'utf8')) as SslyzeResult;
  const rows = raw.server_scan_results ?? [];
  let findings = 0;
  const emit = (target: string, category: string, severity: string, title: string, meta: unknown): void => {
    db.insertFinding({ tool: 'sslyze', target, category, severity, title, matched_at: target, meta }, now, runId);
    findings++;
  };

  for (const row of rows) {
    const target = row.server_location?.hostname;
    if (!target || row.scan_status !== 'COMPLETED') continue;
    const s = row.scan_result ?? {};

    // ---- known-CVE vulnerability flags ----------------------------------
    if (s.heartbleed?.result?.is_vulnerable_to_heartbleed) {
      emit(target, 'heartbleed', 'critical', 'Heartbleed (CVE-2014-0160) — memory disclosure', {});
    }
    if (s.openssl_ccs_injection?.result?.is_vulnerable_to_ccs_injection) {
      emit(target, 'ccs-injection', 'critical', 'OpenSSL CCS Injection (CVE-2014-0224) — MITM', {});
    }
    const robotResult = s.robot?.result?.robot_result;
    if (robotResult && !robotResult.startsWith('NOT_VULNERABLE')) {
      emit(target, 'robot', 'critical', `ROBOT vulnerable (${robotResult})`, { detail: robotResult });
    }
    if (s.tls_compression?.result?.supports_compression) {
      emit(target, 'crime', 'medium', 'TLS compression enabled (CRIME attack path)', {});
    }
    const reneg = s.session_renegotiation?.result;
    if (reneg?.supports_secure_renegotiation === false) {
      emit(target, 'secure-renegotiation', 'high', 'Server does not support secure TLS renegotiation', {});
    }
    if (reneg?.is_vulnerable_to_client_renegotiation_dos) {
      emit(target, 'client-renegotiation-dos', 'high', 'Vulnerable to client-initiated renegotiation DoS', {});
    }

    // ---- deprecated protocol support ------------------------------------
    if (s.ssl_2_0_cipher_suites?.result?.is_tls_version_supported) {
      emit(target, 'sslv2', 'critical', 'SSLv2 supported (DROWN / broken)', {});
    }
    if (s.ssl_3_0_cipher_suites?.result?.is_tls_version_supported) {
      emit(target, 'sslv3', 'high', 'SSLv3 supported (POODLE / deprecated)', {});
    }
    if (s.tls_1_0_cipher_suites?.result?.is_tls_version_supported) {
      emit(target, 'tls-1.0', 'medium', 'TLS 1.0 supported (deprecated; PCI-DSS non-compliant)', {});
    }
    if (s.tls_1_1_cipher_suites?.result?.is_tls_version_supported) {
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
    const dep = s.certificate_info?.result?.certificate_deployments?.[0];
    if (dep) {
      if (dep.verified_chain_has_sha1_signature) {
        emit(target, 'chain-sha1', 'medium', 'Certificate chain contains SHA-1 signature (browsers block)', {});
      }
      if (dep.verified_chain_has_legacy_symantec_anchor) {
        emit(target, 'symantec-anchor', 'medium', 'Chain terminates in a distrusted Symantec-era CA', {});
      }
      if (dep.received_chain_has_valid_order === false) {
        emit(target, 'chain-order', 'low', 'Certificate chain sent in wrong order (some clients reject)', {});
      }
      const sctCount = dep.leaf_certificate_signed_certificate_timestamps_count ?? 0;
      if (sctCount < 2) {
        emit(target, 'sct-count', 'low', `Only ${sctCount} SCT(s) embedded — Chrome/Safari require ≥ 2`, { count: sctCount });
      }
      if (dep.leaf_certificate_has_must_staple_extension && !dep.ocsp_response_is_trusted) {
        emit(target, 'ocsp-must-staple', 'medium', 'must-staple set but no valid OCSP response returned', {});
      }
    }
  }

  db.finishRun(runId, { targetsCount: rows.length, findingsCount: findings, at: new Date().toISOString() });
  db.close();
  console.error(`sslyze done: +${findings} finding(s) across ${rows.length} scanned host(s), run #${runId}`);
  console.error(`  sqlite: ${path.resolve(opts.sqlite)}`);
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
