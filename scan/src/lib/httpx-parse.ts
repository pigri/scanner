import type { Db, HttpProbeRow } from './db.js';
import { normalizeIp } from './ip.js';

interface HttpxRow {
  input?: string; url?: string; host?: string; host_ip?: unknown; a?: unknown;
  status_code?: number; status?: number;
  title?: string; webserver?: string; 'web-server'?: string;
  tech?: string[]; technologies?: string[];
  header?: { server?: string; Server?: string };
  content_length?: number; body_hash?: string; hash?: { body_sha256?: string };
}

// The address that answered: host_ip is the one httpx connected to, host is an
// IP only for IP-literal inputs, and a[0] is the first resolved A record.
function answeringIp(row: HttpxRow): string | null {
  const candidates: unknown[] = [row.host_ip, row.host, Array.isArray(row.a) ? row.a[0] : undefined];
  for (const c of candidates) {
    const n = typeof c === 'string' ? normalizeIp(c) : null;
    if (n) return n.ip;
  }
  return null;
}

// Bare lowercase hostname of a host, URL or host:port string.
export function normalizeHost(raw: string): string {
  return raw
    .replace(/^https?:\/\//i, '')
    .replace(/[/:?#].*$/, '')
    .replace(/\.$/, '')
    .toLowerCase();
}

// Parses one httpx JSONL line into a probe row; null for a blank or malformed line.
export function parseHttpxRow(line: string): HttpProbeRow | null {
  if (!line.trim()) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(line); } catch { return null; }
  // httpx output carries what scanned servers sent: valid JSON need not be an object.
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const row = parsed as HttpxRow;
  const str = (v: unknown): string => (typeof v === 'string' ? v : '');
  // Normalize `target` to the bare hostname (matching scan_queue / ports).
  // We feed httpx expanded URLs (http://foo + https://foo), so row.input
  // is scheme-prefixed. Storing it verbatim broke every downstream join
  // (report-worker, risk.ts, sslyze/headers/ffuf live-only filters,
  // synthesize-eol, graph-export) because they all key on the bare host.
  const target = normalizeHost(str(row.host ?? row.input ?? row.url));
  if (!target) return null;
  return {
    target,
    ip: answeringIp(row),
    url: str(row.url),
    status_code: row.status_code ?? row.status ?? null,
    title: row.title ?? null,
    web_server: row.webserver ?? row['web-server'] ?? row.header?.server ?? row.header?.Server ?? null,
    tech: row.tech ?? row.technologies ?? null,
    content_length: row.content_length ?? null,
    hash_body: row.body_hash ?? row.hash?.body_sha256 ?? null,
  };
}

// Stores every probe line of an httpx JSONL output; returns how many rows were stored.
export function ingestHttpxOutput(db: Db, jsonl: string, at: string, runId: number): number {
  let count = 0;
  for (const line of jsonl.split('\n')) {
    const probe = parseHttpxRow(line);
    if (!probe) continue;
    try {
      db.insertHttpProbe(probe, at, runId);
      count++;
    } catch { /* ignore unwritable row */ }
  }
  return count;
}
