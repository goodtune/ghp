-- SQLite does not support DROP COLUMN before 3.35.0; rebuild the table.
CREATE TABLE apps_backup (
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
INSERT INTO apps_backup SELECT id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at FROM apps;
DROP TABLE apps;
ALTER TABLE apps_backup RENAME TO apps;
CREATE UNIQUE INDEX apps_single_default ON apps (is_default) WHERE is_default = 1;
