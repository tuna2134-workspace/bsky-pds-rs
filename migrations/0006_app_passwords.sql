-- App Passwords (argon2 hashes, never plaintext) + reserved signing keys (migration handshake).
CREATE TABLE IF NOT EXISTS app_password (
  did TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  privileged INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  PRIMARY KEY (did, name)
);

CREATE TABLE IF NOT EXISTS reserved_key (
  did TEXT PRIMARY KEY,
  priv_hex TEXT NOT NULL,
  pub_hex TEXT NOT NULL,
  created_at TEXT NOT NULL
);
