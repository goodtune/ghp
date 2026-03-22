ALTER TABLE proxy_tokens ADD COLUMN last_used_at TEXT;
ALTER TABLE proxy_tokens ADD COLUMN request_count INTEGER NOT NULL DEFAULT 0;
