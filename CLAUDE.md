# CLAUDE.md

## Project Overview

GHP is a GitHub API reverse proxy that issues scoped, auditable tokens (`ghx_`-prefixed) to autonomous coding agents. Single static Go binary, self-hosted.

## Tech Stack

- **Language:** Go 1.24
- **CLI:** cobra
- **Database:** PostgreSQL (production) via pgx, SQLite (development) via modernc.org/sqlite
- **Config:** koanf (YAML + `GHP_` env vars)
- **Metrics:** Prometheus
- **E2E tests:** Playwright (TypeScript, Chromium)
- **Docs:** MkDocs with shadcn theme, built via `uv`

## Build & Development Commands

```bash
# Build
make build

# Run unit tests
make test

# Run tests + go vet
make check

# Lint (requires golangci-lint)
make lint

# Run go vet only
make vet

# Build and start server
make run

# Run database migrations
make migrate
```

### E2E Tests

```bash
cd e2e
npm ci
npx playwright install --with-deps chromium
npx playwright test
```

E2E tests require a running ghp server on `http://localhost:8080` with `GHP_DEV_MODE=true`.

## Project Structure

```
cmd/ghp/          CLI entrypoint (cobra commands: serve, migrate, auth, token)
internal/
  auth/           GitHub OAuth + session management + rate limiting
  proxy/          Core proxy logic, scope enforcement, token resolution
  server/         HTTP server, routing, API endpoints, access logging, TLS
  token/          Token creation, validation, revocation
  database/       PostgreSQL + SQLite drivers, models, migrations
  crypto/         AES-256-GCM encryption, RSA key operations
  config/         Configuration loading via koanf
  web/            Web UI handlers, templates, static assets, middleware
  metrics/        Prometheus metric registration
  github/         GitHub App JWT/installation handling
  backend/        Database abstraction interface
  docs/           Embedded MkDocs output
e2e/              Playwright end-to-end tests
docs/             MkDocs documentation source
packaging/        Systemd units, default config, install scripts
```

## Coding Conventions

- Standard Go formatting (`gofmt`)
- Table-driven tests using `t.Run()`
- Explicit error handling (`if err != nil`)
- Unit tests colocated with source (`*_test.go`)
- `CGO_ENABLED=0` for all builds (pure Go, no C dependencies)
- Configuration via YAML files or environment variables with `GHP_` prefix

## Database Migrations

SQL migrations live in `internal/database/migrations/` with separate `postgres/` and `sqlite/` subdirectories. Each migration has `*.up.sql` and `*.down.sql` files. Run with `./ghp migrate`.

## CI

PRs trigger the Test workflow (`.github/workflows/test.yml`):
1. Go unit tests + binary build
2. Playwright E2E tests against a live server with SQLite backend
