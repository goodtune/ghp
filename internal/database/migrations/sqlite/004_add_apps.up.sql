CREATE TABLE apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    app_id INTEGER NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    client_secret TEXT NOT NULL DEFAULT '',
    private_key TEXT NOT NULL DEFAULT '',
    base_url TEXT NOT NULL DEFAULT '',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Enforce at most one default app at the DB level.
CREATE UNIQUE INDEX apps_single_default ON apps (is_default) WHERE is_default = 1;

ALTER TABLE proxy_tokens ADD COLUMN app_id TEXT REFERENCES apps(id) ON DELETE SET NULL;
ALTER TABLE github_tokens ADD COLUMN app_id TEXT REFERENCES apps(id) ON DELETE SET NULL;
