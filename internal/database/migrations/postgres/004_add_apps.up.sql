CREATE TABLE apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    app_id BIGINT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    client_secret TEXT NOT NULL DEFAULT '',
    private_key TEXT NOT NULL DEFAULT '',
    base_url TEXT NOT NULL DEFAULT '',
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enforce at most one default app at the DB level.
CREATE UNIQUE INDEX apps_single_default ON apps (is_default) WHERE is_default = TRUE;

ALTER TABLE proxy_tokens ADD COLUMN app_id UUID REFERENCES apps(id) ON DELETE SET NULL;
ALTER TABLE github_tokens ADD COLUMN app_id UUID REFERENCES apps(id) ON DELETE SET NULL;
