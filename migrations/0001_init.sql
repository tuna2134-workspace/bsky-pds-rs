-- bsky-pds-rs D1 schema
-- Spec refs: atproto.com/specs/account, /specs/repository, /specs/sync, /specs/oauth
-- Workers/D1 is SQLite. Keep tables narrow; repo blocks live in CAR/R2, not here.

CREATE TABLE IF NOT EXISTS account (
  did TEXT PRIMARY KEY,
  handle TEXT NOT NULL,
  email TEXT,
  email_confirmed INTEGER NOT NULL DEFAULT 0,
  password_hash TEXT, -- legacy/app-password fallback (OAuth is primary; see goal)
  signing_key_k256_priv_hex TEXT, -- atproto signing key (secp256k1). TODO: move to secret store
  signing_key_k256_pub_hex TEXT,
  rotation_key_k256_priv_hex TEXT,
  status TEXT NOT NULL DEFAULT 'active', -- active|deactivated|deleted|takendown|suspended
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_handle ON account(handle);
CREATE INDEX IF NOT EXISTS idx_account_email ON account(email);

CREATE TABLE IF NOT EXISTS repo_root (
  did TEXT PRIMARY KEY REFERENCES account(did) ON DELETE CASCADE,
  rev TEXT NOT NULL, -- TID logical clock
  data_cid TEXT NOT NULL, -- MST root CID (blessed CID format)
  commit_cid TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS record (
  did TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
  collection TEXT NOT NULL, -- NSID
  rkey TEXT NOT NULL, -- record key (TID or literal:*)
  cid TEXT NOT NULL,
  value_json TEXT NOT NULL, -- canonical JSON of record
  rev TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (did, collection, rkey)
);
CREATE INDEX IF NOT EXISTS idx_record_collection ON record(collection, updated_at);

CREATE TABLE IF NOT EXISTS blob (
  did TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
  cid TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (did, cid)
);

-- Firehose sequencer (com.atproto.sync.subscribeRepos seq). Single-row counter pattern
-- compatible with the official PDS `sequencer.sqlite` repair workflow.
CREATE TABLE IF NOT EXISTS seq_state (
  name TEXT PRIMARY KEY,
  seq INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO seq_state(name, seq) VALUES ('repo_seq', 0);

CREATE TABLE IF NOT EXISTS firehose_event (
  seq INTEGER PRIMARY KEY,
  did TEXT NOT NULL,
  kind TEXT NOT NULL, -- commit|sync|identity|account
  rev TEXT,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_firehose_did ON firehose_event(did, seq);

CREATE TABLE IF NOT EXISTS invite_code (
  code TEXT PRIMARY KEY,
  used_by TEXT,
  created_at TEXT NOT NULL,
  used_at TEXT
);

-- OAuth (atproto profile): PAR requests, auth codes, tokens, DPoP nonces live partly in KV.
CREATE TABLE IF NOT EXISTS oauth_par (
  request_uri TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  state TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  login_hint TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_code (
  code TEXT PRIMARY KEY,
  request_uri TEXT NOT NULL REFERENCES oauth_par(request_uri) ON DELETE CASCADE,
  did TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS oauth_token (
  jti TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL, -- DPoP public key thumbprint the token is bound to
  access_token_hash TEXT NOT NULL,
  refresh_token_hash TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_token_did ON oauth_token(did);
