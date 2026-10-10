-- Per-user opaque AppView preferences (served locally so official
-- clients work without relay indexing; synced per device).
CREATE TABLE IF NOT EXISTS user_prefs (
  did TEXT PRIMARY KEY,
  prefs_json TEXT NOT NULL DEFAULT '{"preferences":[]}',
  updated_at TEXT NOT NULL
);
