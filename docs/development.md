# Development

## Requirements

- Go 1.24+
- Node.js (for E2E tests)

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

### Quick Dev Setup

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

Create a test session:

    curl -s -X POST http://localhost:8080/auth/test-login \
      -H 'Content-Type: application/json' \
      -d '{"username": "dev", "role": "admin"}'

Save the `session_token` from the response, then create a scoped proxy token:

    curl -s -X POST http://localhost:8080/api/tokens \
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
  metrics/        Prometheus metrics
  proxy/          GitHub API proxy, passthrough handlers, token resolver
  server/         HTTP server, TLS, host dispatch, access logging
  token/          Token service (create, validate, revoke)
  web/            Web UI handlers and templates
```
