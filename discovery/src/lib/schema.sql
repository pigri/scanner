-- discovery: recon SQLite schema
-- All timestamps are ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SS.sssZ`) so string
-- comparison is a valid date range test.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS hosts (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hosts_first_seen ON hosts(first_seen);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen  ON hosts(last_seen);

-- provenance: each (host, source) sighting
CREATE TABLE IF NOT EXISTS sources (
  id       INTEGER PRIMARY KEY,
  host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  source   TEXT NOT NULL,   -- ddg | ct-crtsh | ct-certspotter | ptr | brute | manual
  seen_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sources_host   ON sources(host_id);
CREATE INDEX IF NOT EXISTS idx_sources_source ON sources(source);
CREATE INDEX IF NOT EXISTS idx_sources_seen   ON sources(seen_at);

-- IPs enriched from the MMDB. Latest known values live here.
CREATE TABLE IF NOT EXISTS ips (
  ip             TEXT PRIMARY KEY,
  family         INTEGER NOT NULL,     -- 4 or 6
  asn            TEXT,
  as_name        TEXT,
  as_domain      TEXT,
  country_code   TEXT,
  country        TEXT,
  continent_code TEXT,
  first_seen     TEXT NOT NULL,
  last_seen      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ips_asn      ON ips(asn);
CREATE INDEX IF NOT EXISTS idx_ips_country  ON ips(country_code);
CREATE INDEX IF NOT EXISTS idx_ips_lastseen ON ips(last_seen);

-- host → ip mapping observed at seen_at. Multiple rows per (host,ip) form the history.
CREATE TABLE IF NOT EXISTS resolutions (
  id       INTEGER PRIMARY KEY,
  host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  ip       TEXT NOT NULL REFERENCES ips(ip) ON DELETE CASCADE,
  family   INTEGER NOT NULL,
  seen_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_res_host    ON resolutions(host_id);
CREATE INDEX IF NOT EXISTS idx_res_ip      ON resolutions(ip);
CREATE INDEX IF NOT EXISTS idx_res_seen    ON resolutions(seen_at);

-- reverse DNS observations. Same ip → name pair may appear multiple times over time.
CREATE TABLE IF NOT EXISTS ptr_records (
  id       INTEGER PRIMARY KEY,
  ip       TEXT NOT NULL,
  name     TEXT NOT NULL,
  seen_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ptr_ip   ON ptr_records(ip);
CREATE INDEX IF NOT EXISTS idx_ptr_name ON ptr_records(name);
CREATE INDEX IF NOT EXISTS idx_ptr_seen ON ptr_records(seen_at);

-- refresh runs — one row per orchestrated pipeline execution.
CREATE TABLE IF NOT EXISTS runs (
  id            INTEGER PRIMARY KEY,
  tool          TEXT NOT NULL,          -- refresh | ct-log | dns-brute | ptr-sweep | enrich | ddg-sweep
  started_at    TEXT NOT NULL,
  finished_at   TEXT,
  args_json     TEXT,
  added_hosts   INTEGER DEFAULT 0,
  added_ips     INTEGER DEFAULT 0,
  notes         TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
CREATE INDEX IF NOT EXISTS idx_runs_tool    ON runs(tool);
