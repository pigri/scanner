-- scan: SQLite schema for active-scan findings + history.
-- Timestamps: ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SS.sssZ`).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- One row per orchestrated tool invocation.
CREATE TABLE IF NOT EXISTS runs (
  id              INTEGER PRIMARY KEY,
  tool            TEXT NOT NULL,           -- nmap | httpx | nuclei | wpscan | masscan | testssl | gowitness | takeover | scan-all
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  args_json       TEXT,
  targets_count   INTEGER DEFAULT 0,
  findings_count  INTEGER DEFAULT 0,
  notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
CREATE INDEX IF NOT EXISTS idx_runs_tool    ON runs(tool);

-- Open-port observations (nmap + masscan).
CREATE TABLE IF NOT EXISTS ports (
  id         INTEGER PRIMARY KEY,
  target     TEXT NOT NULL,      -- hostname or IP
  ip         TEXT,               -- resolved IP if known
  port       INTEGER NOT NULL,
  protocol   TEXT NOT NULL,      -- tcp | udp
  service    TEXT,
  product    TEXT,
  version    TEXT,
  tunnel     TEXT,               -- ssl | ""
  extrainfo  TEXT,
  seen_at    TEXT NOT NULL,
  run_id     INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_ports_target  ON ports(target);
CREATE INDEX IF NOT EXISTS idx_ports_ip      ON ports(ip);
CREATE INDEX IF NOT EXISTS idx_ports_port    ON ports(port);
CREATE INDEX IF NOT EXISTS idx_ports_seen    ON ports(seen_at);

-- HTTP surface fingerprints (httpx).
CREATE TABLE IF NOT EXISTS http_probes (
  id             INTEGER PRIMARY KEY,
  target         TEXT NOT NULL,
  url            TEXT NOT NULL,
  status_code    INTEGER,
  title          TEXT,
  web_server     TEXT,
  tech_json      TEXT,           -- JSON array of detected tech
  content_length INTEGER,
  hash_body      TEXT,
  seen_at        TEXT NOT NULL,
  run_id         INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_http_target ON http_probes(target);
CREATE INDEX IF NOT EXISTS idx_http_url    ON http_probes(url);
CREATE INDEX IF NOT EXISTS idx_http_status ON http_probes(status_code);
CREATE INDEX IF NOT EXISTS idx_http_seen   ON http_probes(seen_at);

-- Cross-tool findings: nuclei, wpscan, testssl, takeover, ad-hoc.
-- needs_review flags likely-false-positive rows the scanner couldn't rule out
-- automatically (catch-all responders, SPAs, decoy pages). The reviewer looks
-- at meta_json.body_preview + meta_json.body_status and decides whether to
-- confirm or dismiss. See src/ffuf.ts for the current producer.
CREATE TABLE IF NOT EXISTS findings (
  id             INTEGER PRIMARY KEY,
  tool           TEXT NOT NULL,       -- nuclei | wpscan | testssl | takeover | manual
  target         TEXT NOT NULL,       -- URL or host
  category       TEXT,                -- template-id | cve | tls-issue | takeover-type
  severity       TEXT,                -- info | low | medium | high | critical
  title          TEXT NOT NULL,
  cve            TEXT,
  matched_at     TEXT,                -- URL/component that matched
  meta_json      TEXT,                -- everything else the tool emitted
  seen_at        TEXT NOT NULL,
  run_id         INTEGER REFERENCES runs(id) ON DELETE SET NULL,
  needs_review   INTEGER NOT NULL DEFAULT 0   -- 1 = likely FP, awaiting reviewer
);
CREATE INDEX IF NOT EXISTS idx_findings_tool     ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_cve      ON findings(cve);
CREATE INDEX IF NOT EXISTS idx_findings_seen     ON findings(seen_at);
-- idx_findings_review (partial index on needs_review = 1) is created inside
-- openDb() so it can follow the ALTER-TABLE migration on legacy DBs that
-- predate the column. Do NOT reference needs_review here — schema.sql runs
-- once on every open and would fail before the migration on those DBs.

-- Risk score computed per target. Multiple rows per target over time.
CREATE TABLE IF NOT EXISTS risk_scores (
  id             INTEGER PRIMARY KEY,
  target         TEXT NOT NULL,
  score          INTEGER NOT NULL,
  breakdown_json TEXT NOT NULL,
  computed_at    TEXT NOT NULL,
  run_id         INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_target   ON risk_scores(target);
CREATE INDEX IF NOT EXISTS idx_risk_score    ON risk_scores(score);
CREATE INDEX IF NOT EXISTS idx_risk_computed ON risk_scores(computed_at);

-- Local work queue: hosts to scan, prioritized. A worker claims batches
-- of `pending` rows, runs scan-all on them, then marks `done` or `failed`.
-- Nothing else in the pipeline depends on this — it's purely a batching aid.
CREATE TABLE IF NOT EXISTS scan_queue (
  id           INTEGER PRIMARY KEY,
  target       TEXT NOT NULL UNIQUE,
  priority     INTEGER NOT NULL DEFAULT 0,   -- higher = scanned first
  status       TEXT NOT NULL DEFAULT 'pending', -- pending | in_progress | done | failed
  queued_at    TEXT NOT NULL,
  started_at   TEXT,
  finished_at  TEXT,
  run_id       INTEGER REFERENCES runs(id) ON DELETE SET NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_queue_status_prio ON scan_queue(status, priority DESC);
CREATE INDEX IF NOT EXISTS idx_queue_target ON scan_queue(target);

-- Certificate inventory: one row per (host, port, cert). Populated from the
-- full testssl cert_* block. Deduped by fingerprint so re-scans don't pile up.
CREATE TABLE IF NOT EXISTS certificates (
  id                 INTEGER PRIMARY KEY,
  target             TEXT NOT NULL,
  port               INTEGER,
  cert_index         INTEGER NOT NULL DEFAULT 1,   -- host may present RSA + ECDSA
  common_name        TEXT,
  san_json           TEXT,                          -- JSON array of SAN hostnames
  issuer             TEXT,
  not_before         TEXT,
  not_after          TEXT,
  key_algo           TEXT,                          -- RSA | EC | ...
  key_size           INTEGER,                       -- bits
  sig_algo           TEXT,
  serial             TEXT,
  fingerprint_sha256 TEXT,
  self_signed        INTEGER NOT NULL DEFAULT 0,
  seen_at            TEXT NOT NULL,
  run_id             INTEGER REFERENCES runs(id) ON DELETE SET NULL,
  UNIQUE(target, port, fingerprint_sha256)
);
CREATE INDEX IF NOT EXISTS idx_cert_target   ON certificates(target);
CREATE INDEX IF NOT EXISTS idx_cert_fp       ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_notafter ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_cert_keysize  ON certificates(key_size);

-- Report queue: targets that finished scanning and await report generation.
-- Same shape as scan_queue; a scanner enqueues here after a successful batch,
-- and the report worker drains it. Decoupling scan from report lets multiple
-- scanners run flat-out while report generation proceeds independently.
CREATE TABLE IF NOT EXISTS report_queue (
  id           INTEGER PRIMARY KEY,
  target       TEXT NOT NULL UNIQUE,
  priority     INTEGER NOT NULL DEFAULT 0,   -- higher = reported first
  status       TEXT NOT NULL DEFAULT 'pending', -- pending | in_progress | done | failed
  queued_at    TEXT NOT NULL,
  started_at   TEXT,
  finished_at  TEXT,
  run_id       INTEGER REFERENCES runs(id) ON DELETE SET NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_report_queue_status_prio ON report_queue(status, priority DESC);
CREATE INDEX IF NOT EXISTS idx_report_queue_target ON report_queue(target);

-- URLs discovered by the crawler (katana). Feed for URL-level nuclei re-scan.
-- Dedup by (target, url) so re-crawls don't pile up.
CREATE TABLE IF NOT EXISTS discovered_urls (
  id       INTEGER PRIMARY KEY,
  target   TEXT NOT NULL,           -- the FQDN we crawled from
  url      TEXT NOT NULL,           -- absolute URL (may be off-target if crawler followed)
  method   TEXT,                    -- GET | POST | ...
  source   TEXT NOT NULL,           -- katana | gau | waybackurls | manual
  status   INTEGER,                 -- HTTP status if known
  content_type TEXT,
  seen_at  TEXT NOT NULL,
  run_id   INTEGER REFERENCES runs(id) ON DELETE SET NULL,
  UNIQUE(target, url)
);
CREATE INDEX IF NOT EXISTS idx_urls_target ON discovered_urls(target);
CREATE INDEX IF NOT EXISTS idx_urls_source ON discovered_urls(source);
CREATE INDEX IF NOT EXISTS idx_urls_seen   ON discovered_urls(seen_at);

-- CVE rollup: one row per (target, cve_id). Populated from findings.cve by
-- src/cve-rollup.ts (or npm run cve-rollup). Multi-tool detection tracked in
-- `tools` (comma-sep sorted set) so a CVE surfaced by both nmap-vulners AND
-- nuclei collapses into one row with both tools noted. severity = worst-seen
-- for that (target, cve) pair.
CREATE TABLE IF NOT EXISTS cves (
  id            INTEGER PRIMARY KEY,
  target        TEXT NOT NULL,
  cve_id        TEXT NOT NULL,
  severity      TEXT,               -- worst-seen severity across all matching finding rows
  cvss          REAL,               -- max CVSS score across sources (from findings.meta_json.cvss)
  tools         TEXT NOT NULL,      -- comma-separated sorted set: 'nmap-vulners,nuclei'
  hit_count     INTEGER NOT NULL DEFAULT 1,   -- how many findings rows contributed
  first_seen    TEXT NOT NULL,
  last_seen     TEXT NOT NULL,
  exploit       INTEGER NOT NULL DEFAULT 0,   -- 1 if any source flagged an exploit available
  -- NVD enrichment (nullable; populated by src/cve-enrich.ts)
  description   TEXT,                          -- English description from NVD
  published_at  TEXT,                          -- ISO date from NVD
  nvd_cvss      REAL,                          -- authoritative CVSS from NVD (v3 preferred)
  nvd_vector    TEXT,                          -- CVSS vector string (v3 or v2)
  refs_json     TEXT,                          -- JSON array of {url, source}
  enriched_at   TEXT,                          -- ISO date when NVD fetch happened
  UNIQUE(target, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_cves_target    ON cves(target);
CREATE INDEX IF NOT EXISTS idx_cves_cve       ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity  ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss      ON cves(cvss);
CREATE INDEX IF NOT EXISTS idx_cves_last_seen ON cves(last_seen);

-- DNS records per FQDN. One row per (name, type, value). Dedup so a rescan
-- doesn't pile up identical rows.
CREATE TABLE IF NOT EXISTS dns_records (
  id       INTEGER PRIMARY KEY,
  target   TEXT NOT NULL,           -- the FQDN we queried
  name     TEXT NOT NULL,           -- record name (usually the target itself)
  type     TEXT NOT NULL,           -- A | AAAA | CNAME | MX | TXT | NS | SOA | SRV
  value    TEXT NOT NULL,
  ttl      INTEGER,
  seen_at  TEXT NOT NULL,
  run_id   INTEGER REFERENCES runs(id) ON DELETE SET NULL,
  UNIQUE(target, name, type, value)
);
CREATE INDEX IF NOT EXISTS idx_dns_target ON dns_records(target);
CREATE INDEX IF NOT EXISTS idx_dns_type   ON dns_records(type);
CREATE INDEX IF NOT EXISTS idx_dns_seen   ON dns_records(seen_at);

-- Screenshots (gowitness).
CREATE TABLE IF NOT EXISTS screenshots (
  id       INTEGER PRIMARY KEY,
  target   TEXT NOT NULL,
  url      TEXT NOT NULL,
  path     TEXT NOT NULL,
  status   INTEGER,
  title    TEXT,
  seen_at  TEXT NOT NULL,
  run_id   INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_shots_target ON screenshots(target);
CREATE INDEX IF NOT EXISTS idx_shots_seen   ON screenshots(seen_at);
