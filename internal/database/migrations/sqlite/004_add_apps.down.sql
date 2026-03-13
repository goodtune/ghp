-- SQLite does not support DROP COLUMN before 3.35.0; recreate tables without app_id.
-- For simplicity, drop the app_id columns by recreating the tables.

CREATE TABLE proxy_tokens_backup AS SELECT
    id, token_hash, token_prefix, token_type, user_id, github_token_id,
    installation_id, repositories, scopes, session_id, expires_at,
    revoked_at, last_used_at, request_count, created_at
FROM proxy_tokens;
DROP TABLE proxy_tokens;
CREATE TABLE proxy_tokens (
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
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO proxy_tokens SELECT * FROM proxy_tokens_backup;
DROP TABLE proxy_tokens_backup;
CREATE INDEX idx_proxy_tokens_user_id ON proxy_tokens(user_id);
CREATE INDEX idx_proxy_tokens_token_hash ON proxy_tokens(token_hash);

CREATE TABLE github_tokens_backup AS SELECT
    id, user_id, access_token, refresh_token, access_token_expires_at,
    refresh_token_expires_at, scopes, created_at, updated_at
FROM github_tokens;
DROP TABLE github_tokens;
CREATE TABLE github_tokens (
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
INSERT INTO github_tokens SELECT * FROM github_tokens_backup;
DROP TABLE github_tokens_backup;

DROP TABLE apps;
