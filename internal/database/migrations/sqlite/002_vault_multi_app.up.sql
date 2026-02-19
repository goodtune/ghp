-- Add app_slug column to github_tokens for multi-app (Vault) support.
-- In single-app mode (no vault), app_slug will be empty string.
-- The unique constraint changes from (user_id) to (user_id, app_slug)
-- so a user can hold tokens for multiple GitHub Apps.

-- SQLite does not support ALTER TABLE ... DROP CONSTRAINT or ADD CONSTRAINT,
-- so we recreate the table.

CREATE TABLE github_tokens_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_slug TEXT NOT NULL DEFAULT '',
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    access_token_expires_at TEXT NOT NULL,
    refresh_token_expires_at TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(user_id, app_slug)
);

INSERT INTO github_tokens_new (id, user_id, app_slug, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at)
SELECT id, user_id, '', access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at
FROM github_tokens;

DROP TABLE github_tokens;
ALTER TABLE github_tokens_new RENAME TO github_tokens;
