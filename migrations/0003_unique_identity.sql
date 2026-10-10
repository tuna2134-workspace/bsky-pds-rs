-- Uniqueness the reference PDS enforces: one handle and one email per account.
-- (NULL emails are exempt from the unique index in SQLite semantics.)
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_handle_unique ON account(handle);
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_email_unique ON account(email);
