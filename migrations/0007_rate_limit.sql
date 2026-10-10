-- Fixed-window rate limit counters (keyed by scope + window start).
CREATE TABLE IF NOT EXISTS rate_limit (
  bucket TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, window_start)
);
