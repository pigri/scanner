#!/usr/bin/env -S node --loader tsx
// gapi-key-check: probe a Google Cloud API key against a curated set of
// Google API endpoints and report which are enabled + accessible without any
// referrer restriction. The point isn't "is the key present" (it clearly is,
// scanned assets have it embedded) but "which billable / abusable APIs will
// this specific key redeem". Modelled on ozguralp/gmapsapiscanner but built
// for our pipeline: single script, JSON output, severity per surface.
//
// Only-referrer-restricted keys are NOT considered safe here — HTTP Referer
// is trivially spoofable by any non-browser attacker. Only IP-restricted or
// app-signature-restricted keys are considered safe from public abuse. Since
// we can't verify the console-side restriction config, we probe with no
// Referer and treat any 200 with real payload as "reachable from public".
//
// Usage:
//   gapi-key-check <AIza...> [<AIza...> ...]
//   echo "AIza..." | gapi-key-check --stdin
//   gapi-key-check --bundle-dir path/to/bundles     # auto-extract AIza keys
//   gapi-key-check --target host.example --sqlite scan.db   # write findings

import fs from 'node:fs';
import path from 'node:path';
import { openDb } from './lib/db.js';

interface ProbeResult {
  api: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  enabled: boolean;
  status: number;
  detail: string;
}

interface Probe {
  api: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  build(key: string): { url: string; method?: 'GET' | 'POST'; body?: string };
  enabledIf(status: number, body: string): { enabled: boolean; detail: string };
}

const OK = (detail: string) => ({ enabled: true, detail });
const NO = (detail: string) => ({ enabled: false, detail });

// Google's `status` field is the authoritative signal on Maps-family JSON
// endpoints: 'OK' = enabled + returned data, 'REQUEST_DENIED' = disabled or
// restricted, 'INVALID_REQUEST' = enabled (we sent malformed input on
// purpose, but the API accepted the key — that's the finding), 'ZERO_RESULTS'
// = enabled + no results (still a positive-enabled signal).
// Google Cloud (non-Maps) APIs return errors with a nested `details[].reason`
// field that's authoritative for whether the KEY was accepted at all. Common
// reasons: `API_KEY_INVALID` (key rejected by project), `API_KEY_SERVICE_BLOCKED`
// (this API not enabled on the project), `API_KEY_HTTP_REFERRER_BLOCKED` (key
// works but not from our origin), `SERVICE_DISABLED` (project hasn't enabled
// the API), `RATE_LIMIT_EXCEEDED` (enabled + throttled). We MUST look at these
// — the outer `status` alone is ambiguous (INVALID_ARGUMENT can mean bad key
// OR bad input, depending on reason).
function classifyGoogleCloudApi(status: number, body: string, _apiLabel: string): { enabled: boolean; detail: string } {
  if (status === 200) return OK('200 OK — request succeeded');
  try {
    const j = JSON.parse(body) as { error?: { status?: string; message?: string; details?: Array<{ reason?: string }> } };
    const e = j.error;
    if (!e) return NO(`HTTP ${status}, no error object`);
    const reasons = (e.details ?? []).map((d) => d.reason).filter(Boolean) as string[];
    for (const r of reasons) {
      if (r === 'API_KEY_INVALID') return NO('API_KEY_INVALID (key rejected)');
      if (r === 'API_KEY_SERVICE_BLOCKED') return NO('API_KEY_SERVICE_BLOCKED (this API not enabled for the key)');
      if (r === 'API_KEY_HTTP_REFERRER_BLOCKED') return OK('key valid but referrer-restricted (spoofable — still redeemable)');
      if (r === 'API_KEY_IP_ADDRESS_BLOCKED') return NO('API_KEY_IP_ADDRESS_BLOCKED (IP-restricted — safe)');
      if (r === 'API_KEY_ANDROID_APP_BLOCKED' || r === 'API_KEY_IOS_APP_BLOCKED') return NO(`${r} (app-signature-restricted — safe)`);
      if (r === 'SERVICE_DISABLED') return NO('SERVICE_DISABLED (API not enabled on the project)');
      if (r === 'CONSUMER_INVALID') return NO('CONSUMER_INVALID');
      if (r === 'RATE_LIMIT_EXCEEDED') return OK('RATE_LIMIT_EXCEEDED (enabled, throttled)');
      if (r === 'BILLING_DISABLED') return NO('BILLING_DISABLED (billing not linked)');
    }
    if (e.status === 'PERMISSION_DENIED') return NO(`PERMISSION_DENIED: ${e.message?.slice(0, 100) ?? ''}`);
    if (e.status === 'FAILED_PRECONDITION') return NO(`FAILED_PRECONDITION: ${e.message?.slice(0, 100) ?? ''}`);
    if (e.status === 'RESOURCE_EXHAUSTED') return OK('RESOURCE_EXHAUSTED (enabled, quota depleted)');
    // Only claim "enabled" from a bare INVALID_ARGUMENT if we've already
    // ruled out API_KEY_INVALID via reasons above — otherwise stay safe.
    if (e.status === 'INVALID_ARGUMENT' && reasons.length && !reasons.some((r) => r.startsWith('API_KEY'))) {
      return OK('INVALID_ARGUMENT with non-key reason (API enabled, bad input)');
    }
    return NO(`${e.status ?? `HTTP ${status}`}: ${e.message?.slice(0, 80) ?? ''} [reasons: ${reasons.join(',') || 'none'}]`);
  } catch { return NO(`HTTP ${status}, non-JSON`); }
}

function classifyMapsJson(status: number, body: string): { enabled: boolean; detail: string } {
  if (status >= 500) return NO(`HTTP ${status}`);
  try {
    const j = JSON.parse(body) as { status?: string; error_message?: string };
    const s = j.status ?? '';
    if (s === 'OK' || s === 'ZERO_RESULTS' || s === 'INVALID_REQUEST') return OK(`status=${s}`);
    if (s === 'REQUEST_DENIED') return NO(`REQUEST_DENIED: ${j.error_message ?? ''}`);
    if (s === 'OVER_QUERY_LIMIT') return OK(`OVER_QUERY_LIMIT — enabled but throttled`);
    return NO(`status=${s || 'unknown'}`);
  } catch {
    return NO(`non-JSON body (${body.slice(0, 60).replace(/\s+/g, ' ')})`);
  }
}

const PROBES: Probe[] = [
  {
    api: 'gemini (Generative Language)',
    severity: 'critical',
    build: (k) => ({
      url: `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(k)}`,
      method: 'POST',
      body: JSON.stringify({ contents: [{ parts: [{ text: 'hi' }] }], generationConfig: { maxOutputTokens: 1 } }),
    }),
    enabledIf: (status, body) => classifyGoogleCloudApi(status, body, 'Generative Language'),
  },
  {
    api: 'custom-search (Programmable Search)',
    severity: 'high',
    build: (k) => ({ url: `https://customsearch.googleapis.com/customsearch/v1?q=x&cx=0&key=${encodeURIComponent(k)}` }),
    enabledIf: (status, body) => classifyGoogleCloudApi(status, body, 'Custom Search'),
  },
  {
    api: 'places-nearbysearch',
    severity: 'high',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=0,0&radius=1&key=${encodeURIComponent(k)}` }),
    enabledIf: classifyMapsJson,
  },
  {
    api: 'places-textsearch',
    severity: 'high',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/place/textsearch/json?query=x&key=${encodeURIComponent(k)}` }),
    enabledIf: classifyMapsJson,
  },
  {
    api: 'places-autocomplete',
    severity: 'high',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=x&key=${encodeURIComponent(k)}` }),
    enabledIf: classifyMapsJson,
  },
  {
    api: 'directions',
    severity: 'medium',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/directions/json?origin=0,0&destination=1,1&key=${encodeURIComponent(k)}` }),
    enabledIf: classifyMapsJson,
  },
  {
    api: 'distance-matrix',
    severity: 'medium',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/distancematrix/json?origins=0,0&destinations=1,1&key=${encodeURIComponent(k)}` }),
    enabledIf: classifyMapsJson,
  },
  {
    api: 'geocoding',
    severity: 'medium',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/geocode/json?address=x&key=${encodeURIComponent(k)}` }),
    enabledIf: classifyMapsJson,
  },
  {
    api: 'timezone',
    severity: 'medium',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/timezone/json?location=0,0&timestamp=0&key=${encodeURIComponent(k)}` }),
    enabledIf: classifyMapsJson,
  },
  {
    api: 'roads-snap',
    severity: 'medium',
    build: (k) => ({ url: `https://roads.googleapis.com/v1/snapToRoads?path=0,0&key=${encodeURIComponent(k)}` }),
    enabledIf: (status, body) => {
      try {
        const j = JSON.parse(body) as { error?: { status?: string; message?: string }; snappedPoints?: unknown[] };
        if (j.snappedPoints !== undefined) return OK('snappedPoints returned');
        if (j.error?.status === 'PERMISSION_DENIED') return NO('PERMISSION_DENIED');
        if (status === 200) return OK('200 OK');
        return NO(`HTTP ${status}: ${j.error?.message ?? ''}`);
      } catch { return NO(`HTTP ${status}, non-JSON`); }
    },
  },
  {
    api: 'elevation',
    severity: 'low',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/elevation/json?locations=0,0&key=${encodeURIComponent(k)}` }),
    enabledIf: classifyMapsJson,
  },
  {
    api: 'static-maps',
    severity: 'low',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key=${encodeURIComponent(k)}` }),
    enabledIf: (status, body) => {
      if (status === 200 && body.length > 0 && !body.startsWith('{')) return OK('200 OK, image body');
      if (status === 403) return NO('403 Forbidden');
      return NO(`HTTP ${status}`);
    },
  },
  {
    api: 'street-view-static',
    severity: 'low',
    build: (k) => ({ url: `https://maps.googleapis.com/maps/api/streetview?size=1x1&location=0,0&key=${encodeURIComponent(k)}` }),
    enabledIf: (status, body) => {
      if (status === 200 && !body.startsWith('{')) return OK('200 OK, image body');
      if (status === 403) return NO('403 Forbidden');
      return NO(`HTTP ${status}`);
    },
  },
  {
    api: 'geolocation (Wi-Fi/cell)',
    severity: 'medium',
    build: (k) => ({
      url: `https://www.googleapis.com/geolocation/v1/geolocate?key=${encodeURIComponent(k)}`,
      method: 'POST', body: '{}',
    }),
    enabledIf: (status, body) => classifyGoogleCloudApi(status, body, 'Geolocation'),
  },
];

async function probeOne(key: string, probe: Probe, timeoutMs: number): Promise<ProbeResult> {
  const spec = probe.build(key);
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const init: RequestInit = { method: spec.method ?? 'GET', signal: ctl.signal };
    if (spec.body) { init.body = spec.body; init.headers = { 'content-type': 'application/json' }; }
    const res = await fetch(spec.url, init);
    const body = await res.text();
    const { enabled, detail } = probe.enabledIf(res.status, body);
    return { api: probe.api, severity: probe.severity, enabled, status: res.status, detail };
  } catch (e) {
    return { api: probe.api, severity: probe.severity, enabled: false, status: 0, detail: (e as Error).message };
  } finally {
    clearTimeout(timer);
  }
}

async function probeKey(key: string, timeoutMs: number): Promise<ProbeResult[]> {
  // Sequential — Google rate-limits per key and parallel probes just trigger
  // throttling that shows up as false negatives. 14 requests × ~500ms ≈ 7s.
  const out: ProbeResult[] = [];
  for (const p of PROBES) out.push(await probeOne(key, p, timeoutMs));
  return out;
}

function keySeverity(results: ProbeResult[]): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const order = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const enabled = results.filter((r) => r.enabled);
  if (!enabled.length) return 'info';
  for (const sev of order) if (enabled.some((r) => r.severity === sev)) return sev;
  return 'info';
}

function extractAizaKeysFromFile(file: string): Set<string> {
  const keys = new Set<string>();
  try {
    const buf = fs.readFileSync(file, 'utf8');
    const re = /AIza[0-9A-Za-z_-]{35}/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(buf)) !== null) keys.add(m[0]);
  } catch { /* ignore */ }
  return keys;
}

function walkBundles(root: string): Map<string, Set<string>> {
  // Return map: host → set of AIza keys found in that host's bundle tree.
  const out = new Map<string, Set<string>>();
  const stack: Array<{ path: string; host: string | null }> = [{ path: root, host: null }];
  while (stack.length) {
    const cur = stack.pop()!;
    const st = fs.statSync(cur.path);
    if (st.isDirectory()) {
      for (const name of fs.readdirSync(cur.path)) {
        const child = path.join(cur.path, name);
        const host = cur.host ?? (name.includes('.') ? name : null);
        stack.push({ path: child, host });
      }
    } else {
      const keys = extractAizaKeysFromFile(cur.path);
      if (keys.size && cur.host) {
        if (!out.has(cur.host)) out.set(cur.host, new Set());
        for (const k of keys) out.get(cur.host)!.add(k);
      }
    }
  }
  return out;
}

function formatKey(k: string): string {
  return `${k.slice(0, 8)}…${k.slice(-4)}`;
}

interface Opts {
  keys: string[];
  bundleDir: string | null;
  target: string | null;
  sqlite: string | null;
  timeoutMs: number;
  json: boolean;
  stdin: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { keys: [], bundleDir: null, target: null, sqlite: null, timeoutMs: 10000, json: false, stdin: false, help: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '--bundle-dir') opts.bundleDir = next();
    else if (a === '--target') opts.target = next();
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '--timeout-ms') opts.timeoutMs = parseInt(next(), 10);
    else if (a === '--json') opts.json = true;
    else if (a === '--stdin') opts.stdin = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else opts.keys.push(a);
  }
  return opts;
}

function usage(): void {
  console.error(`Usage: gapi-key-check <AIza...> [<AIza...> ...]
       gapi-key-check --bundle-dir <dir>     # auto-extract AIza keys, group by host
       echo AIza... | gapi-key-check --stdin

Options:
  --target <host>          Attribute findings to this target (only with a single key)
  --sqlite <path>          Write one finding per enabled API surface to scan.db
  --timeout-ms <N>         Per-probe timeout (default: 10000)
  --json                   Emit results as JSON (default: table)
  --stdin                  Read one AIza key per stdin line
`);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help) { usage(); process.exit(0); }
  const keys = new Map<string, string | null>(); // key → host (or null if unknown)
  if (opts.stdin) {
    const data = fs.readFileSync(0, 'utf8');
    for (const line of data.split('\n')) {
      const t = line.trim();
      if (/^AIza[0-9A-Za-z_-]{35}$/.test(t)) keys.set(t, opts.target);
    }
  }
  for (const k of opts.keys) if (/^AIza[0-9A-Za-z_-]{35}$/.test(k)) keys.set(k, opts.target);
  if (opts.bundleDir) {
    const perHost = walkBundles(opts.bundleDir);
    for (const [host, keySet] of perHost) for (const k of keySet) keys.set(k, host);
  }
  if (!keys.size) {
    // Not an error when invoked from the secrets pipeline: most scanned
    // bundles contain no Google API keys. Exit clean so a no-op run
    // doesn't spam the worker log with a bogus "exited 1".
    console.error('no valid AIza… keys — nothing to probe');
    process.exit(0);
  }

  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('gapi-key-check', { keys: keys.size }, now) : null;

  const allResults: Array<{ key: string; host: string | null; results: ProbeResult[] }> = [];
  for (const [key, host] of keys) {
    console.error(`\n=== ${formatKey(key)} ${host ? `(host: ${host})` : ''} ===`);
    const results = await probeKey(key, opts.timeoutMs);
    const enabled = results.filter((r) => r.enabled);
    for (const r of results) {
      const mark = r.enabled ? '✔' : '·';
      const line = `  ${mark} [${r.severity.padEnd(8)}] ${r.api.padEnd(30)} → ${r.detail}`;
      console.error(line);
    }
    console.error(`  → ${enabled.length}/${results.length} APIs enabled; worst = ${keySeverity(results)}`);
    allResults.push({ key, host, results });

    if (db && runId !== null && host && enabled.length) {
      for (const r of enabled) {
        db.insertFinding({
          tool: 'gapi-key-check',
          target: host,
          category: `gapi:${r.api.split(' ')[0]}`,
          severity: r.severity,
          title: `Exposed Google API key redeems ${r.api} (${formatKey(key)})`,
          cve: null,
          matched_at: `${host}`,
          meta: { key_prefix: key.slice(0, 12), api: r.api, status: r.status, detail: r.detail },
        }, now, runId);
      }
    }
  }

  if (db && runId !== null) {
    const total = allResults.reduce((a, r) => a + r.results.filter((x) => x.enabled).length, 0);
    db.finishRun(runId, { targetsCount: keys.size, findingsCount: total, at: new Date().toISOString() });
    db.close();
  }

  if (opts.json) console.log(JSON.stringify(allResults, null, 2));
}

main().catch((e) => { console.error('FATAL:', e instanceof Error ? e.message : String(e)); process.exit(1); });
