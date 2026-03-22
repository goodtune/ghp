-- SQLite does not support DROP COLUMN before 3.35.0; rebuild the table.
CREATE TABLE cached_repositories_backup (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO cached_repositories_backup SELECT id, owner, name, enabled, created_at, updated_at FROM cached_repositories;
DROP TABLE cached_repositories;
ALTER TABLE cached_repositories_backup RENAME TO cached_repositories;
CREATE UNIQUE INDEX idx_cached_repos_owner_name ON cached_repositories (owner, name);
