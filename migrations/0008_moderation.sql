-- Per-account invite switch, invite code kill-switch, record/blob takedown flags.
ALTER TABLE account ADD COLUMN invites_disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invite_code ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE record ADD COLUMN takendown INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blob ADD COLUMN takendown INTEGER NOT NULL DEFAULT 0;
