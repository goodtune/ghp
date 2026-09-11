-- Persistent storage for ghp's auth state. Previously these were held in
-- in-memory LRUs in the auth handler, which broke any flow whose round-trips
-- crossed instances in an HA deployment (browser sessions, OAuth state for
-- the GitHub login redirect, OAuth broker state, and the CLI device-
-- authorization records). All four are now backed by the database.

-- Browser/CLI session tokens. The raw bearer (a `ghpr_` prefix + 32 bytes
-- of randomness) is hashed with SHA-256 before storage so a database
-- compromise does not yield active session tokens — handlers hash the
-- presented token on every lookup.
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- In-flight OAuth state tokens. `kind` distinguishes the main GitHub login
-- flow ('login') from the OAuth broker flow ('broker'). Each kind has its
-- own optional payload columns; the unused ones are empty strings. One-time
-- use: rows are deleted by the consume operation as soon as the matching
-- callback validates them.
CREATE TABLE oauth_states (
    state TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('login', 'broker')),
    -- 'login' kind: optional return-to path appended to the post-callback
    -- redirect target. Empty means the default ("/").
    return_to TEXT NOT NULL DEFAULT '',
    -- 'broker' kind: the validated downstream redirect_uri to bounce back to.
    broker_redirect_uri TEXT NOT NULL DEFAULT '',
    -- 'broker' kind: the downstream service's own state value, echoed back
    -- to it so it can match its own request.
    broker_downstream_state TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX oauth_states_expires_at_idx ON oauth_states (expires_at);

-- CLI device-authorization (RFC 8628 shape, against ghp itself).
CREATE TABLE cli_device_authorizations (
    -- The long, high-entropy secret the CLI polls with.
    device_code TEXT PRIMARY KEY,
    -- The short, human-readable code displayed to the user. Globally unique
    -- within the active TTL window so the verification page can resolve a
    -- request from the URL parameter alone.
    user_code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    -- Populated once status transitions to 'approved'. The CLI receives
    -- this on its next successful poll, after which the row is deleted.
    session_token TEXT,
    username TEXT,
    -- Updated on every poll to enforce the minimum poll interval.
    last_polled_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- user_code already has an implicit unique index via the UNIQUE column
-- constraint above; no separate index is needed for verification-page lookups.
CREATE INDEX cli_device_authorizations_expires_at_idx ON cli_device_authorizations (expires_at);
