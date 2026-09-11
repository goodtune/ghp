-- Allow proxy tokens to have no expiry (NULL expires_at).
ALTER TABLE proxy_tokens ALTER COLUMN expires_at DROP NOT NULL;
