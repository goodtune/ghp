CREATE TABLE forward_proxy_rulesets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    algorithm TEXT NOT NULL CHECK (algorithm IN ('round_robin', 'weighted', 'sticky')),
    proxies TEXT NOT NULL DEFAULT '[]',
    rules TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX idx_forward_proxy_rulesets_name ON forward_proxy_rulesets (name);
