-- Drop the FK (ON DELETE CASCADE) on oauth_code.request_uri: PARs are
-- single-use and deleted at approval, which must NOT cascade to codes.
CREATE TABLE oauth_code_new (
  code TEXT PRIMARY KEY,
  request_uri TEXT NOT NULL,
  did TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  client_id TEXT,
  redirect_uri TEXT,
  scope TEXT,
  code_challenge TEXT
);
INSERT INTO oauth_code_new (code, request_uri, did, created_at, expires_at, used_at, client_id, redirect_uri, scope, code_challenge)
  SELECT code, request_uri, did, created_at, expires_at, used_at, client_id, redirect_uri, scope, code_challenge FROM oauth_code;
DROP TABLE oauth_code;
ALTER TABLE oauth_code_new RENAME TO oauth_code;
CREATE INDEX IF NOT EXISTS idx_oauth_code_request_uri ON oauth_code (request_uri);
