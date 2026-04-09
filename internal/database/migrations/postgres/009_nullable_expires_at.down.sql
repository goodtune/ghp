-- Restore NOT NULL constraint on expires_at. Existing NULL values are set to
-- a far-future timestamp so the migration succeeds without data loss.
UPDATE proxy_tokens SET expires_at = '9999-12-31T23:59:59Z' WHERE expires_at IS NULL;
ALTER TABLE proxy_tokens ALTER COLUMN expires_at SET NOT NULL;
