-- The bundled modernc SQLite (3.35+) supports DROP COLUMN directly. A table
-- rebuild must not be used here: DROP TABLE apps would fire ON DELETE SET NULL
-- on proxy_tokens.app_id and github_tokens.app_id while foreign keys are on.
ALTER TABLE apps DROP COLUMN webhook_secret;
