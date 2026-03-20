# Development

## Requirements

- Go 1.24+
- Node.js (for E2E tests)
- Docker (for Vault dev environment)
- [goreleaser](https://goreleaser.com/) (for building Docker images)

## Build

    make build

## Run Tests

Run unit tests and vet:

    make check

Run E2E tests (requires Node.js):

    cd e2e
    npm ci
    npx playwright install --with-deps chromium
    npx playwright test

## Dev Mode

Dev mode (`GHP_DEV_MODE=true`) enables:

- `/auth/test-login` endpoint — creates a test session without GitHub OAuth
- Built-in admin login form at `/admin` for quick access

### Quick Dev Setup (SQLite)

Generate an encryption key:

    export GHP_ENCRYPTION_KEY=$(openssl rand -hex 32)

Start the server:

    export GHP_DEV_MODE=true
    export GHP_DATABASE_DRIVER=sqlite
    export GHP_DATABASE_DSN=ghp.db
    export GHP_SERVER_LISTEN=:8080
    export GHP_GITHUB_CLIENT_ID=unused
    export GHP_GITHUB_CLIENT_SECRET=unused

    ./ghp migrate
    ./ghp serve

!!! note "Agent tokens require a GitHub App"
    The SQLite quick setup does not configure a GitHub App, so `ghx_` proxy
    tokens work but `gha_` agent tokens cannot be created. To work with agent
    tokens, either add `GHP_GITHUB_APP_ID` and `GHP_GITHUB_PRIVATE_KEY` to
    seed an app from config, or register one via the admin UI at `/admin`.
    The [Docker Compose with Vault](#docker-compose-with-vault) setup below
    is recommended for multi-app development.

### Docker Compose with Vault

A Docker Compose file is provided that runs GHP with a HashiCorp Vault backend
— the same storage backend used in production deployments. This is the
recommended way to develop and test multi-app workflows.

**1. Build the GHP Docker image locally with goreleaser:**

```
goreleaser release --snapshot --clean --skip=publish
```

This produces architecture-specific images tagged as
`ghcr.io/goodtune/ghp:latest-arm64` and `ghcr.io/goodtune/ghp:latest-amd64`.

**2. Start the stack:**

```
docker compose up -d
```

This brings up three containers:

| Container | Purpose | Port |
|---|---|---|
| `ghp-vault` | Vault dev server (in-memory, unsealed) | `localhost:8200` |
| `ghp-vault-init` | One-shot init that configures AppRole auth and policies | — |
| `ghp` | GHP server with Vault backend in dev mode | `localhost:8080` |

All credentials are pre-configured with fixed values — no manual copying
required. The init container enables AppRole auth, writes a `ghp` policy
granting access to `secret/data/ghp/*`, and sets deterministic role and secret
IDs.

!!! note
    The `ghp` service image tag in `docker-compose.yml` is
    `ghcr.io/goodtune/ghp:latest-arm64`. On Intel Macs or Linux amd64, change
    this to `ghcr.io/goodtune/ghp:latest-amd64`.

**3. Open the admin UI:**

Navigate to [http://127.0.0.1:8080/admin](http://127.0.0.1:8080/admin) and
sign in with any username (e.g. `admin`).

!!! tip
    Use `127.0.0.1` rather than `localhost` — Safari does not reliably persist
    cookies on `localhost` over plain HTTP.

From here you can add GitHub Apps, configure installations, and mint tokens
against multiple apps — all backed by Vault.

**4. Useful endpoints:**

| URL | Description |
|---|---|
| `http://127.0.0.1:8080/admin` | GHP admin UI |
| `http://127.0.0.1:8080/metrics` | Prometheus metrics (or `:9136/metrics`) |
| `http://127.0.0.1:8200` | Vault UI (token: `dev-root-token`) |

**5. Tear down:**

```
docker compose down -v
```

The `-v` flag removes Vault's in-memory data. Omit it to preserve state across
restarts.

#### How it works

The Vault dev server starts unsealed with KV v2 mounted at `secret/`. The init
container configures:

- **Policy** `ghp` — grants CRUD + list on `secret/data/ghp/*` and
  read/list/delete on `secret/metadata/ghp/*`
- **AppRole** `ghp` — bound to the `ghp` policy with a 1-hour token TTL
- **Fixed credentials** — `role_id=ghp-dev-role-id`,
  `secret_id=ghp-dev-secret-id` (set via Vault's custom-secret-id API)

GHP connects to Vault using these AppRole credentials. Because Vault encrypts
data at rest, no `GHP_ENCRYPTION_KEY` is required when using the Vault backend.

#### Rebuilding after code changes

After modifying Go code, rebuild the image and restart:

```
goreleaser release --snapshot --clean --skip=publish
docker compose up -d ghp
```

Vault state is preserved — only the GHP container is recreated.

### Working with the dev environment

Create a test session:

    curl -s -X POST http://127.0.0.1:8080/auth/test-login \
      -H 'Content-Type: application/json' \
      -d '{"username": "dev", "role": "admin"}'

Save the `session_token` from the response, then create a scoped proxy token:

    curl -s -X POST http://127.0.0.1:8080/api/tokens \
      -H "Authorization: Bearer <session_token>" \
      -H 'Content-Type: application/json' \
      -d '{"repository": "owner/repo", "scopes": "contents:read,pulls:write", "duration": "1h"}'

## Project Layout

```
cmd/ghp/          CLI entrypoint and subcommands
internal/
  auth/           GitHub OAuth and session management
  config/         Configuration loading (YAML + env vars)
  crypto/         AES-256-GCM encryption for stored tokens
  database/       Database abstraction and migrations
  github/         GitHub App JWT/installation handling
  metrics/        Prometheus metrics
  proxy/          GitHub API proxy, passthrough handlers, token resolver
  server/         HTTP server, TLS, host dispatch, access logging
  token/          Token service (create, validate, revoke)
  web/            Web UI handlers and templates
e2e/              Playwright end-to-end tests
docs/             MkDocs documentation source
packaging/        Systemd units, default config, install scripts
```
