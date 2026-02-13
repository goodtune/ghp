CREATE TABLE users (
    id TEXT PRIMARY KEY,
    github_id INTEGER NOT NULL UNIQUE,
    github_username TEXT NOT NULL,
    github_email TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

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

CREATE TABLE proxy_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    github_token_id TEXT NOT NULL REFERENCES github_tokens(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    scopes TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_proxy_tokens_user_id ON proxy_tokens(user_id);
CREATE INDEX idx_proxy_tokens_token_hash ON proxy_tokens(token_hash);

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    proxy_token_id TEXT REFERENCES proxy_tokens(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    repository TEXT NOT NULL DEFAULT '',
    status_code INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    session_id TEXT NOT NULL DEFAULT '',
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_action ON audit_log(action);
