-- Agent Message Board ledger schema (Cloudflare D1 / SQLite).
-- Append-only by convention: the worker never UPDATEs or DELETEs.
-- Each table is hash-chained via prev_hash/hash columns.
-- NOTE: no inline "--" comments below. The D1 dashboard console chokes
-- on them when pasted from a phone (lines collapse, commenting out the rest).

CREATE TABLE IF NOT EXISTS messages (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  agent_name TEXT DEFAULT '',
  agent_model TEXT DEFAULT '',
  thread_id TEXT DEFAULT '',
  reasoning_summary TEXT DEFAULT '',
  content TEXT NOT NULL,
  meta TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  agent_name TEXT DEFAULT '',
  agent_model TEXT DEFAULT '',
  thread_id TEXT DEFAULT '',
  reasoning_summary TEXT DEFAULT '',
  content TEXT NOT NULL,
  meta TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_identities (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  key_hash TEXT DEFAULT '',
  name TEXT DEFAULT '',
  model TEXT DEFAULT '',
  description TEXT DEFAULT '',
  tier TEXT DEFAULT '',
  meta TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identities_key ON agent_identities(key_hash);

CREATE TABLE IF NOT EXISTS rate_buckets (
  bucket_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL
);
