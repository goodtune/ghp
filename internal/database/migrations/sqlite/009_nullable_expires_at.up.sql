-- SQLite does not support ALTER COLUMN to drop NOT NULL, so we recreate
-- the table without the NOT NULL constraint on expires_at.

CREATE TABLE proxy_tokens_new (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    token_type TEXT NOT NULL DEFAULT 'proxy' CHECK (token_type IN ('proxy', 'agent')),
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    github_token_id TEXT REFERENCES github_tokens(id) ON DELETE CASCADE,
    installation_id INTEGER,
    repositories TEXT NOT NULL DEFAULT '[]',
    scopes TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    expires_at TEXT,
    revoked_at TEXT,
    app_id TEXT REFERENCES apps(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO proxy_tokens_new (id, token_hash, token_prefix, token_type, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, app_id, created_at)
    SELECT id, token_hash, token_prefix, token_type, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, app_id, created_at FROM proxy_tokens;

DROP TABLE proxy_tokens;
ALTER TABLE proxy_tokens_new RENAME TO proxy_tokens;

CREATE INDEX idx_proxy_tokens_user_id ON proxy_tokens(user_id);
CREATE INDEX idx_proxy_tokens_token_hash ON proxy_tokens(token_hash);
