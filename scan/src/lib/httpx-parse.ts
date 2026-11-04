import type { HttpProbeRow } from './db.js';

interface HttpxRow {
  input?: string; url?: string; host?: string;
  status_code?: number; status?: number;
  title?: string; webserver?: string; 'web-server'?: string;
  tech?: string[]; technologies?: string[];
  content_length?: number; body_hash?: string; hash?: { body_sha256?: string };
}

// Parses one httpx JSONL line into a probe row; null for a blank or malformed line.
export function parseHttpxRow(line: string): HttpProbeRow | null {
  if (!line.trim()) return null;
  let row: HttpxRow;
  try { row = JSON.parse(line) as HttpxRow; } catch { return null; }
  // Normalize `target` to the bare hostname (matching scan_queue / ports).
  // We feed httpx expanded URLs (http://foo + https://foo), so row.input
  // is scheme-prefixed. Storing it verbatim broke every downstream join
  // (report-worker, risk.ts, sslyze/headers/ffuf live-only filters,
  // synthesize-eol, graph-export) because they all key on the bare host.
  const rawTarget = row.host ?? row.input ?? row.url ?? '';
  const target = rawTarget
    .replace(/^https?:\/\//i, '')
    .replace(/[/:?#].*$/, '')
    .replace(/\.$/, '')
    .toLowerCase();
  return {
    target,
    url: row.url ?? '',
    status_code: row.status_code ?? row.status ?? null,
    title: row.title ?? null,
    web_server: row.webserver ?? row['web-server'] ?? null,
    tech: row.tech ?? row.technologies ?? null,
    content_length: row.content_length ?? null,
    hash_body: row.body_hash ?? row.hash?.body_sha256 ?? null,
  };
}
