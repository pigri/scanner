-- attack: SQLite schema for authenticated / exploitation attempts.
-- Timestamps: ISO 8601 UTC.
-- SEPARATE DB from the recon side (scan.db / recon.db) because the retention
-- and legal handling of "attack attempts" is different from "we probed a port".

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
  id            INTEGER PRIMARY KEY,
  tool          TEXT NOT NULL,      -- netexec | responder | manual
  started_at    TEXT NOT NULL,
  finished_at   TEXT,
  args_json     TEXT,
  scope_authorized INTEGER NOT NULL DEFAULT 0,  -- 1 iff --yes-i-am-authorized was passed
  notes         TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
CREATE INDEX IF NOT EXISTS idx_runs_tool ON runs(tool);

-- Each authentication attempt against a target.
CREATE TABLE IF NOT EXISTS attempts (
  id         INTEGER PRIMARY KEY,
  target     TEXT NOT NULL,
  protocol   TEXT NOT NULL,          -- smb | winrm | ldap | mssql | rdp | ssh | ftp | ...
  username   TEXT,
  password   TEXT,                    -- store the attempted value; scrub before export
  nthash     TEXT,
  domain     TEXT,
  outcome    TEXT NOT NULL,           -- success | fail | locked | error
  privilege  TEXT,                    -- pwn3d | admin | user | guest | ...
  raw_line   TEXT,                    -- one raw line of the tool's output for provenance
  seen_at    TEXT NOT NULL,
  run_id     INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_target   ON attempts(target);
CREATE INDEX IF NOT EXISTS idx_attempts_outcome  ON attempts(outcome);
CREATE INDEX IF NOT EXISTS idx_attempts_seen     ON attempts(seen_at);

-- Any credentials we captured (Responder hashes, NetExec dumped creds).
CREATE TABLE IF NOT EXISTS credentials (
  id         INTEGER PRIMARY KEY,
  source     TEXT NOT NULL,           -- responder-nbt | responder-llmnr | netexec-lsassy | ...
  target     TEXT,                    -- the target where it was captured (if applicable)
  username   TEXT,
  domain     TEXT,
  hash_type  TEXT,                    -- NTLMv2 | LM | PLAIN | NT
  hash_value TEXT,
  password   TEXT,                    -- plaintext if cracked
  seen_at    TEXT NOT NULL,
  run_id     INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_creds_source  ON credentials(source);
CREATE INDEX IF NOT EXISTS idx_creds_user    ON credentials(username);
CREATE INDEX IF NOT EXISTS idx_creds_seen    ON credentials(seen_at);

-- Sessions / shell established (NetExec `--exec-method`, etc.)
CREATE TABLE IF NOT EXISTS sessions (
  id         INTEGER PRIMARY KEY,
  target     TEXT NOT NULL,
  protocol   TEXT NOT NULL,
  username   TEXT,
  privilege  TEXT,
  opened_at  TEXT NOT NULL,
  closed_at  TEXT,
  notes      TEXT,
  run_id     INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target);
CREATE INDEX IF NOT EXISTS idx_sessions_open   ON sessions(opened_at);
