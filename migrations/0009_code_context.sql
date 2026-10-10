-- Carry PAR context into the authorization code row so PARs stay single-use.
ALTER TABLE oauth_code ADD COLUMN client_id TEXT;
ALTER TABLE oauth_code ADD COLUMN redirect_uri TEXT;
ALTER TABLE oauth_code ADD COLUMN scope TEXT;
ALTER TABLE oauth_code ADD COLUMN code_challenge TEXT;
