export interface ResponderHash {
  source: string;   // e.g. responder-ntlmv2 / responder-smb / responder-http
  user: string;
  domain: string | null;
  hash: string;     // the full raw line
  hashType: string; // NTLMv2 | NTLMv1 | ...
}

/**
 * Parse a single line from a Responder log file. Returns null if it doesn't
 * look like an NTLM-style hash line. `source` is derived from the filename
 * (Responder names files like `NTLMv2-SMB-<ip>.txt` or `SMB-<ip>.txt`).
 */
export function parseHashLine(line: string, filename: string): ResponderHash | null {
  const l = line.trim();
  if (!l) return null;
  // NTLMv2 format: user::domain:challenge:response:blob
  //   - challenge is hex (>= 16 chars, typically exactly 16 for NTLMv2)
  //   - response and blob are hex, response >= 16 chars
  const m = l.match(/^([^:]+)::([^:]*):([0-9a-f]{16,}):([0-9a-f]{16,}):([0-9a-f]+)$/i);
  if (!m) return null;
  const prefix = filename.split('-')[0] ?? 'responder';
  return {
    source: `responder-${prefix.toLowerCase()}`,
    user: m[1]!,
    domain: m[2]! || null,
    hash: l,
    hashType: /NTLMv1/i.test(filename) ? 'NTLMv1' : 'NTLMv2',
  };
}
