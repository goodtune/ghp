-- Revert to single-app schema: remove app_slug column and restore UNIQUE(user_id).

CREATE TABLE github_tokens_old (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    access_token_expires_at TEXT NOT NULL,
    refresh_token_expires_at TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Keep only the most recently updated token per user.
INSERT INTO github_tokens_old (id, user_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at)
SELECT id, user_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at
FROM github_tokens
WHERE id IN (SELECT id FROM github_tokens GROUP BY user_id HAVING MAX(updated_at));

DROP TABLE github_tokens;
ALTER TABLE github_tokens_old RENAME TO github_tokens;
