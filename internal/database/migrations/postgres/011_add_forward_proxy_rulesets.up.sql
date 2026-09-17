CREATE TABLE forward_proxy_rulesets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    algorithm TEXT NOT NULL CHECK (algorithm IN ('round_robin', 'weighted', 'sticky')),
    proxies TEXT NOT NULL DEFAULT '[]',
    rules TEXT NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_forward_proxy_rulesets_name ON forward_proxy_rulesets (name);
