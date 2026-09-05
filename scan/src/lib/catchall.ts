// Shared catch-all-responder detection.
//
// Some hosts return HTTP 200 with a templated page for every path (Zorp/OWA
// login shims, decoys, single-page apps served through catch-all rewrites,
// stock 200-for-everything WAF stances). Path-brute tools (ffuf, kiterunner)
// and content-fingerprint templates (nuclei "backup files", "config files")
// fire dozens of false positives on those hosts.
//
// The primitives here let a caller (a) fetch a canary URL and record what "no
// such path" looks like on that host, (b) compare a candidate response's
// (status, size, body-hash-with-URL-stripped) against the canary, and (c)
// preserve the actual page body + status so a human reviewer can confirm.
//
// Not tied to any particular scanner — used from ffuf.ts, kiterunner.ts, and
// nuclei.ts today. Any future path-brute-shape tool should reuse this.

import crypto from 'node:crypto';
import { run } from './runner.js';

export interface CanaryProbe {
  url: string;
  status: number;
  size: number;
  body: string;
  hash: string;         // sha256 of body with URL echoes stripped
}

// Strip the requested URL from a body so path-echo doesn't perturb the hash.
// Both the raw URL and the URI-encoded form are replaced with a stable token.
export function normaliseBody(body: string, url: string): string {
  const enc = encodeURIComponent(url);
  return body.replaceAll(url, 'URL').replaceAll(enc, 'URL');
}

export function hashBody(body: string, url: string): string {
  return crypto.createHash('sha256').update(normaliseBody(body, url)).digest('hex');
}

// Fetch a URL via curl (bundled with the toolchain — no new deps). Returns
// null on transport failure. Body is truncated at maxBytes so a runaway
// response doesn't blow up memory.
export async function probeUrl(
  url: string,
  timeoutSec: number,
  maxBytes = 8192
): Promise<{ status: number; size: number; body: string } | null> {
  const r = await run(
    'curl',
    ['-sk', '--max-time', String(timeoutSec), '-o', '-', '-w', '\n---meta---\n%{http_code}\n%{size_download}\n', url],
    { timeoutMs: (timeoutSec + 3) * 1000 }
  );
  if (r.code !== 0 && !r.stdout) return null;
  const marker = r.stdout.lastIndexOf('\n---meta---\n');
  if (marker < 0) return null;
  const bodyRaw = r.stdout.slice(0, marker);
  const meta = r.stdout.slice(marker + '\n---meta---\n'.length).trim().split('\n');
  const status = parseInt(meta[0] ?? '0', 10);
  const size = parseInt(meta[1] ?? '0', 10);
  if (!status) return null;
  return { status, size, body: bodyRaw.length > maxBytes ? bodyRaw.slice(0, maxBytes) : bodyRaw };
}

// Fetch a canary URL (unlikely-to-exist path) and record what "no such path"
// looks like on this host. Caller compares real candidates against the return
// value's (status, size, hash) to decide needs_review.
export async function fetchCanary(seed: string, timeoutSec = 8): Promise<CanaryProbe | null> {
  const canaryPath = `gen0sec-canary-${crypto.randomBytes(6).toString('hex')}`;
  const url = `${seed.replace(/\/+$/, '')}/${canaryPath}`;
  const probe = await probeUrl(url, timeoutSec);
  if (!probe) return null;
  return { url, status: probe.status, size: probe.size, body: probe.body, hash: hashBody(probe.body, url) };
}

// Does (status, size) fall within the canary's near-cluster bucket? Both
// candidate and canary are treated as "near" if they share status and land in
// one of four adjacent 50-byte buckets (canary bucket ±2 in either direction).
// This tolerates path-echo of up to ~100 chars per response.
export function isNearCanary(
  canary: CanaryProbe,
  candidate: { status?: number | null; size?: number | null }
): boolean {
  if (candidate.status == null || canary.status !== candidate.status) return false;
  const b = Math.floor(canary.size / 50);
  const cb = Math.floor((candidate.size ?? 0) / 50);
  return Math.abs(cb - b) <= 2;
}
