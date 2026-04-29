-- See postgres/010_add_auth_state.up.sql for design rationale.

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE oauth_states (
    state TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('login', 'broker')),
    return_to TEXT NOT NULL DEFAULT '',
    broker_redirect_uri TEXT NOT NULL DEFAULT '',
    broker_downstream_state TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX oauth_states_expires_at_idx ON oauth_states (expires_at);

CREATE TABLE cli_device_authorizations (
    device_code TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    session_token TEXT,
    username TEXT,
    last_polled_at TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX cli_device_authorizations_user_code_idx ON cli_device_authorizations (user_code);
CREATE INDEX cli_device_authorizations_expires_at_idx ON cli_device_authorizations (expires_at);
