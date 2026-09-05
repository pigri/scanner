export interface Finding {
  tool: string;
  severity: string | null;
  title: string;
  cve: string | null;
  // 1 when the scanner suspected a false positive (catch-all responder,
  // decoy, etc.). Excluded from scoring so noisy hosts don't distort the risk
  // ranking. See src/lib/catchall.ts + src/ffuf.ts.
  needsReview?: boolean;
}

export interface Port {
  port: number;
  service?: string | null;
  protocol?: string | null;
}

export interface HttpProbe {
  url: string;
  status_code?: number | null;
  tech?: string[] | null;
}

export interface TargetSignals {
  target: string;
  findings: Finding[];
  ports: Port[];
  http: HttpProbe[];
  hostShared: number;              // #domains on the same IP
  hostCountryCode: string | null;  // country of the resolved IP
  hostSuffix?: string;             // expected suffix, e.g. 'gov.hu' — used with hostCountryCode
  firstSeen: string | null;        // ISO
  now: string;                     // ISO
}

export interface Breakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  reviewSkipped: number;                  // findings excluded because needs_review=1
  highPoints: number;
  mediumPoints: number;
  criticalPoints: number;
  lowPoints: number;
  infoPoints: number;
  cvePoints: number;
  takeover: number;
  tlsWeak: number;
  wordpress: number;
  portPoints: number;
  keywordPoints: number;
  keywords: string[];
  sharedIp: number;
  foreign: number;
  fresh: number;
  total: number;
}

export interface ScoreResult {
  score: number;   // 0..100 int (hard-capped; raw total kept in breakdown.total)
  breakdown: Breakdown;
}

const RISK_KEYWORDS = [
  'admin', 'dev', 'staging', 'test', 'backup', 'old', 'legacy',
  'jenkins', 'gitlab', 'sonar', 'phpmyadmin', '.git',
];

const SUFFIX_COUNTRY: Record<string, string> = {
  'gov.hu': 'HU', 'hu': 'HU', 'gov.de': 'DE', 'de': 'DE',
  'gov.at': 'AT', 'at': 'AT', 'gov.uk': 'GB', 'uk': 'GB',
};

export function matchesRiskKeyword(host: string): string[] {
  const h = host.toLowerCase();
  return RISK_KEYWORDS.filter((k) => h.includes(k));
}

function daysBetween(a: string, b: string): number {
  return Math.floor((Date.parse(b) - Date.parse(a)) / 86_400_000);
}

// Diminishing-returns severity scoring: first `linearN` findings count at
// `perUnit`, extras count at a reduced `tailRate` up to a per-severity cap.
// Lets a host with 100 criticals outscore one with 3 without letting one
// finding cluster peg the total.
function tieredPoints(n: number, perUnit: number, linearN: number, tailRate: number, cap: number): number {
  if (n <= 0) return 0;
  const linear = Math.min(n, linearN) * perUnit;
  const tail = Math.max(0, n - linearN) * tailRate;
  return Math.min(cap, linear + tail);
}

export function computeScore(s: TargetSignals): ScoreResult {
  let critical = 0, high = 0, medium = 0, low = 0, info = 0, cves = 0;
  let takeover = 0, tlsWeak = 0, wordpress = 0;
  let reviewSkipped = 0;

  // Findings are append-only INSERTs in scan.db: the same host rescanned N
  // times gets the same (tool, category, title) row N times, and the scorer
  // used to multiply the severity contribution by N. Dedupe first — one
  // observation per logical finding — so a hourly rescan can't drift a
  // score by 20+ points per pass.
  const dedupedFindings: typeof s.findings = [];
  const seen = new Set<string>();
  for (const f of s.findings) {
    const key = `${f.tool}|${f.severity ?? ''}|${(f.title || '').toLowerCase()}|${f.cve ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    dedupedFindings.push(f);
  }

  for (const f of dedupedFindings) {
    // Findings the scanner suspects are false positives (catch-all-200
    // responders, decoy pages, etc.) don't get to distort the score.
    if (f.needsReview) { reviewSkipped++; continue; }
    const sev = (f.severity ?? '').toLowerCase();
    if (sev === 'critical') critical++;
    else if (sev === 'high') high++;
    else if (sev === 'medium') medium++;
    else if (sev === 'low') low++;
    else if (sev === 'info' || sev === 'informational') info++;
    if (f.cve) cves++;
    if (f.tool === 'takeover') takeover = 30;
    // TLS bonus reduced from 12 → 8 to avoid double-counting: testssl
    // findings already contribute via highPoints/mediumPoints, and a flat
    // 12 on top pushed weak-TLS hosts into ASAP territory unfairly.
    if (f.tool === 'testssl' && (sev === 'medium' || sev === 'high' || sev === 'critical' || sev === 'low')) tlsWeak = 8;
    if (f.tool === 'wpscan') wordpress = 5;
    if ((f.title || '').toLowerCase().includes('wordpress')) wordpress = Math.max(wordpress, 5);
  }
  for (const p of s.http) {
    for (const t of p.tech ?? []) if (t.toLowerCase().includes('wordpress')) wordpress = Math.max(wordpress, 5);
  }

  // Severity contribution: first N count full weight, extras add smaller but
  // real amounts. Per-severity caps prevent any one bucket from monopolising.
  //
  // Design intent: score 100 == "fix RIGHT NOW". A single confirmed
  // critical (wp-config.php~ leak, live AWS root key, RCE) hits the cap by
  // itself. Highs / mediums / lows accumulate but are weighted low enough
  // that a host with only 3 mid-severity findings (missing DMARC, weak
  // TLS ciphers) lands ~65-75 — meaningful but not ASAP.
  const criticalPoints = tieredPoints(critical, /*perUnit*/ 100, /*linearN*/ 1, /*tailRate*/ 15, /*cap*/ 140);
  const highPoints     = tieredPoints(high,     12, 4, 3, 60);
  const mediumPoints   = tieredPoints(medium,   5, 5, 1, 30);
  const lowPoints      = tieredPoints(low,      1, 10, 0.3, 15);
  const infoPoints     = tieredPoints(info,     0.2, 20, 0.05, 5);
  const cvePoints      = tieredPoints(cves,     10, 3, 2, 60);

  // Count distinct (port, protocol) pairs — the ports table holds one row
  // per tool per port, so naabu + nmap + rustscan all inserting rows for
  // 80/tcp would triple-count. Attack surface is the port itself, not the
  // number of scanners that saw it.
  const uniquePortKeys = new Set<string>();
  for (const p of s.ports) uniquePortKeys.add(`${p.port}|${p.protocol ?? 'tcp'}`);
  const portPoints = Math.min(uniquePortKeys.size, 10) * 2;

  const keywords = matchesRiskKeyword(s.target);
  const keywordPoints = Math.min(keywords.length, 3) * 8;

  const sharedIp = s.hostShared > 5 ? 4 : 0;

  let foreign = 0;
  if (s.hostSuffix && s.hostCountryCode) {
    const expected = SUFFIX_COUNTRY[s.hostSuffix];
    // Foreign-hosted government infrastructure is a material sovereignty +
    // supply-chain concern (see the deep-dive on ist.mfa.gov.hu). Weight it
    // higher than the old 6-point flat bonus.
    if (expected && s.hostCountryCode !== expected) foreign = 15;
  }

  let fresh = 0;
  if (s.firstSeen) {
    const d = daysBetween(s.firstSeen, s.now);
    if (d >= 0 && d < 7) fresh = 3;
  }

  const total =
    criticalPoints + highPoints + mediumPoints + lowPoints + infoPoints + cvePoints +
    takeover + tlsWeak + wordpress +
    portPoints + keywordPoints + sharedIp + foreign + fresh;

  // Hard-capped 0-100. A bounded scale is easier to reason about at a
  // glance ("this host is at 87 of 100") than an unbounded severity total
  // ("this host is at 427"). When two hosts both hit the cap the raw
  // signal isn't lost — the uncapped `total` is preserved in the
  // breakdown JSON, so downstream sorts/reports can tie-break by
  // `breakdown_json->>'total'` when needed.
  const score = Math.max(0, Math.min(100, Math.round(total)));

  return {
    score,
    breakdown: {
      critical, high, medium, low, info, reviewSkipped,
      criticalPoints, highPoints, mediumPoints, lowPoints, infoPoints, cvePoints,
      takeover, tlsWeak, wordpress,
      portPoints, keywordPoints, keywords,
      sharedIp, foreign, fresh, total,
    },
  };
}
