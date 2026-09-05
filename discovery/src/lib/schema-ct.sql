-- ct-mirror: local Certificate Transparency mirror. Stores scope-matched
-- (dns_name, entry) pairs from public CT logs so new subdomains under an
-- authorised zone are detectable without hitting rate-limited aggregators.
--
-- Forward-only: each shard has a baseline_tree_size recorded at init; we only
-- ever pull entries with entry_id > last_entry_id. Full cert bodies are NOT
-- stored — only their SHA-256 fingerprint (for audit + dedup).
--
-- Timestamps: ISO 8601 UTC.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- One row per configured CT log shard.
CREATE TABLE IF NOT EXISTS ct_shards (
  label               TEXT PRIMARY KEY,          -- 'argon2026h1', 'nimbus2026', ...
  log_url             TEXT NOT NULL UNIQUE,      -- 'https://ct.googleapis.com/logs/us1/argon2026h1/'
  baseline_tree_size  INTEGER NOT NULL,          -- tree_size when the shard was init'd
  last_entry_id       INTEGER NOT NULL,          -- highest entry_number we've processed (-1 = none yet)
  updated_at          TEXT NOT NULL              -- last successful update
);

-- One row per CT entry we've parsed (scope-matched entries only — the
-- filter is applied at insert time to keep the DB bounded).
CREATE TABLE IF NOT EXISTS ct_entries (
  log_shard        TEXT NOT NULL REFERENCES ct_shards(label) ON DELETE CASCADE,
  entry_id         INTEGER NOT NULL,
  seen_at          TEXT NOT NULL,                -- when we ingested it
  sct_at           TEXT NOT NULL,                -- entry.timestamp (SCT issuance)
  issuer_o         TEXT,                         -- issuer O= (e.g. "Let's Encrypt")
  cn               TEXT,                         -- subject CN, if any
  cert_der_sha256  TEXT NOT NULL,                -- fingerprint for audit + dedup
  PRIMARY KEY (log_shard, entry_id)
);
CREATE INDEX IF NOT EXISTS idx_ct_entries_seen ON ct_entries(seen_at);
CREATE INDEX IF NOT EXISTS idx_ct_entries_sct  ON ct_entries(sct_at);

-- One row per (entry, dns_name) with the scope suffix that matched. Wildcard
-- SANs (*.foo.example) are recorded with is_wildcard=1 and dns_name stripped
-- of the '*.' prefix so downstream tooling can decide whether to enqueue the
-- apex or a wildcard-probe host.
CREATE TABLE IF NOT EXISTS ct_names (
  id               INTEGER PRIMARY KEY,
  log_shard        TEXT NOT NULL,
  entry_id         INTEGER NOT NULL,
  dns_name         TEXT NOT NULL,                -- lowercased; wildcard '*.' stripped
  is_wildcard      INTEGER NOT NULL DEFAULT 0,
  matched_suffix   TEXT NOT NULL,                -- which scope suffix matched
  first_seen_at    TEXT NOT NULL,                -- when THIS dns_name was first observed
  UNIQUE(log_shard, entry_id, dns_name),
  FOREIGN KEY (log_shard, entry_id) REFERENCES ct_entries(log_shard, entry_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ct_names_dns    ON ct_names(dns_name);
CREATE INDEX IF NOT EXISTS idx_ct_names_suffix ON ct_names(matched_suffix);
CREATE INDEX IF NOT EXISTS idx_ct_names_first  ON ct_names(first_seen_at);

-- One row per unique dns_name across all shards, tracking earliest sighting.
-- Populated as a side effect of ct_names inserts (via trigger below), so
-- "what's genuinely new since T?" is a fast lookup instead of a join.
CREATE TABLE IF NOT EXISTS ct_name_history (
  dns_name         TEXT PRIMARY KEY,
  first_seen_at    TEXT NOT NULL,                -- earliest sct_at across all sightings
  first_log_shard  TEXT NOT NULL,
  first_entry_id   INTEGER NOT NULL,
  sighting_count   INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_ct_history_first ON ct_name_history(first_seen_at);
