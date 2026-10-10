-- Compat session epoch: bumped by deleteSession, invalidating all prior HS256 tokens.
ALTER TABLE account ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
