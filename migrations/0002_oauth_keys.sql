-- OAuth server keys (ES256) for access/refresh JWT issuance.
-- One row per key kind; generated lazily on first use and reused after.
CREATE TABLE IF NOT EXISTS oauth_keys (
  kind TEXT PRIMARY KEY, -- e.g. 'oauth-es256'
  alg TEXT NOT NULL,
  priv_hex TEXT NOT NULL,
  pub_hex TEXT NOT NULL, -- compressed 33-byte hex
  created_at TEXT NOT NULL
);
