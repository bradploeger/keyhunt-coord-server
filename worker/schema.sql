-- D1 schema for the keyhunt coordination Worker.
-- Apply with:  wrangler d1 execute keyhunt-coord --file worker/schema.sql --remote
-- (D1 is SQLite, so this is the same shape as the stdlib server's SCHEMA, plus
--  `targets` and `meta` tables since a Worker has no local files.)

CREATE TABLE IF NOT EXISTS nodes (
  id            TEXT PRIMARY KEY,
  x25519        TEXT NOT NULL,
  gpu           TEXT,
  sw            TEXT,
  status        TEXT NOT NULL DEFAULT 'active',
  first_seen    REAL,
  last_seen     REAL,
  last_seq      INTEGER NOT NULL DEFAULT 0,
  out_seq       INTEGER NOT NULL DEFAULT 0,
  blocks_requested INTEGER NOT NULL DEFAULT 0,
  blocks_done   INTEGER NOT NULL DEFAULT 0,
  total_seconds REAL    NOT NULL DEFAULT 0,
  keys_checked  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS blocks (
  idx           INTEGER PRIMARY KEY AUTOINCREMENT,
  prefix        TEXT NOT NULL,                     -- 54-hex (216-bit) prefix
  state         TEXT NOT NULL DEFAULT 'leased',    -- pending | leased | expired | done
  node_id       TEXT,
  leased_at     REAL,
  lease_expires REAL,
  completed_at  REAL,
  seconds       REAL,
  attempts      INTEGER NOT NULL DEFAULT 0
);
-- Expired blocks are re-handed oldest-first; pending blocks are handed out in
-- id order. Index supports both the (state, lease_expires) and (state, idx) scans.
CREATE INDEX IF NOT EXISTS blocks_state_exp ON blocks(state, lease_expires);
CREATE INDEX IF NOT EXISTS blocks_state_idx ON blocks(state, idx);
CREATE INDEX IF NOT EXISTS blocks_node ON blocks(node_id, state);

-- Append-only block-lifecycle log for the rolling stats; pruned to ~25 hours.
CREATE TABLE IF NOT EXISTS events (
  ts            REAL NOT NULL,
  kind          TEXT NOT NULL,          -- request | expire | complete
  node_id       TEXT,
  block_idx     INTEGER,
  keys          INTEGER NOT NULL DEFAULT 0,
  seconds       REAL
);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts);

CREATE TABLE IF NOT EXISTS matches (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id      TEXT,
  block_idx    INTEGER,
  privkey      TEXT UNIQUE,
  pubkey       TEXT,
  reported_at  REAL,
  verified     INTEGER,
  in_targets   INTEGER,
  note         TEXT
);

-- The search target list (one compressed pubkey per row, in file order). A
-- Worker has no local targets.txt, so the list lives here; seed it out of band.
CREATE TABLE IF NOT EXISTS targets (
  ord          INTEGER PRIMARY KEY,
  pub          TEXT NOT NULL UNIQUE
);

-- Small key/value store; caches targets_digest and targets_count so register
-- and stats need not rescan the whole target list on every request.
CREATE TABLE IF NOT EXISTS meta (
  k            TEXT PRIMARY KEY,
  v            TEXT
);
