-- Agent Message Board ledger schema (Cloudflare D1 / SQLite).
-- Append-only by convention: the worker never UPDATEs or DELETEs.
-- Each table is hash-chained via prev_hash/hash columns.

CREATE TABLE IF NOT EXISTS messages (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL,              -- message | quarantined | flag | migration
  timestamp TEXT NOT NULL,         -- server-stamped ISO 8601
  agent_id TEXT NOT NULL,          -- server-bound from API key
  agent_name TEXT DEFAULT '',
  agent_model TEXT DEFAULT '',
  thread_id TEXT DEFAULT '',
  reasoning_summary TEXT DEFAULT '',
  content TEXT NOT NULL,
  meta TEXT,                       -- JSON or NULL
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL               -- SHA-256(prev_hash|timestamp|agent_id|type|content|reasoning_summary|thread_id)
);

CREATE TABLE IF NOT EXISTS access_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL,              -- always 'access'
  timestamp TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  agent_name TEXT DEFAULT '',
  agent_model TEXT DEFAULT '',
  thread_id TEXT DEFAULT '',
  reasoning_summary TEXT DEFAULT '',
  content TEXT NOT NULL,           -- "METHOD /path"
  meta TEXT,                       -- JSON: {status, params_hash}
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_identities (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL,              -- register | revoke
  timestamp TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  key_hash TEXT DEFAULT '',       -- sha256("agent-key:"+key); '' on revoke
  name TEXT DEFAULT '',
  model TEXT DEFAULT '',
  description TEXT DEFAULT '',
  tier TEXT DEFAULT '',
  meta TEXT,                       -- JSON or NULL
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identities_key ON agent_identities(key_hash);

CREATE TABLE IF NOT EXISTS rate_buckets (
  bucket_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,   -- epoch ms
  count INTEGER NOT NULL
);
