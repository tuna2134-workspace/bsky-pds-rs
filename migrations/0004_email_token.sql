-- Email tokens for confirmation + password reset (hashed at rest).
CREATE TABLE IF NOT EXISTS email_token (
  did TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
  purpose TEXT NOT NULL, -- 'confirm' | 'reset' | 'update'
  token_hash TEXT NOT NULL,
  email TEXT, -- for 'update': the pending new address
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (did, purpose, token_hash)
);
CREATE INDEX IF NOT EXISTS idx_email_token_hash ON email_token(token_hash);
