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

## Metrics & Observability

Detailed metrics collection is a first-class concern. Every significant operation in the request pipeline must be individually instrumented so operators can pinpoint latency sources. All metrics are registered in `internal/metrics/metrics.go` using `promauto` and exposed at the `/metrics` endpoint.

### Decision Pipeline Metrics (`ghp_proxy_decision_duration_seconds`)

The proxy decision pipeline is broken into individually timed stages so that the overhead GHP adds to each request is fully transparent. When adding or modifying request processing logic, **always** instrument the new code path with the appropriate stage timing. The stages are:

| Stage | What it measures |
|---|---|
| `total` | Full pre-forward overhead: arrival to GitHub forward |
| `token_extraction` | Unpacking the Authorization header, identifying ghx_/gha_ prefix |
| `border_policy_check` | Evaluating the token type border policy (block config) |
| `token_resolution` | SHA-256 hash, database lookup, expiry & revocation validation |
| `username_resolution` | Database lookup to resolve GitHub username from internal user ID |
| `scope_parsing` | JSON unmarshalling of repository and permission scope restrictions |
| `scope_enforcement` | Repository allowlist check + permission level verification |
| `github_token_resolution` | Loading, decrypting (or OAuth-refreshing) the real GitHub credential |
| `upstream_roundtrip` | Proxying the upstream GitHub request and streaming the response (network + GitHub processing + response body transfer) |
| `redirect_head_check` | HEAD request to the release redirect target to verify asset availability before issuing a 302 (releases handler only) |

Labels: `stage`, `token_type` (`proxy` for `ghx_` tokens, `agent` for `gha_` tokens, or `unknown` for pre-resolution stages).

### Guidelines for new metrics

- **Instrument every decision point.** If code determines whether a request should proceed, be blocked, or be modified, that decision must be timed.
- **Use fine-grained histogram buckets** for internal decision stages (50µs–1s range); extend to multi-second buckets (2.5s–10s) for `upstream_roundtrip` which can exceed 1s on slow networks or under GitHub load. Use default Prometheus buckets for end-to-end request durations.
- **Label cardinality matters.** Avoid unbounded label values (e.g. don't use full paths as labels). Use the existing `ObserveDecision()` and `ObserveProxyRequest()` helpers.
- **Test every metric.** New metrics must have a corresponding test in `internal/metrics/metrics_test.go` that verifies the metric increments correctly.

### Existing metrics

- `ghp_http_request_duration_seconds` / `ghp_http_request_total` — all HTTP requests by backend
- `ghp_proxy_request_duration_seconds` / `ghp_proxy_request_total` — proxied GitHub requests with full labels
- `ghp_token_active` / `ghp_token_created_total` / `ghp_token_revoked_total` — token lifecycle
- `ghp_github_ratelimit_remaining` / `ghp_github_ratelimit_limit` — GitHub rate limit gauges
- `ghp_github_token_refresh_total` — OAuth token refresh attempts
- `ghp_auth_rate_limit_total` — rate limiter rejections
- `ghp_releases_redirect_head_check_total` — HEAD check outcomes (`found`, `not_found`, `error`) for release redirect targets

## Coding Conventions

- Standard Go formatting (`gofmt`)
- Table-driven tests using `t.Run()`
- Explicit error handling (`if err != nil`)
- Unit tests colocated with source (`*_test.go`)
- `CGO_ENABLED=0` for all builds (pure Go, no C dependencies)
- Configuration via YAML files or environment variables with `GHP_` prefix

## Documentation

User-facing documentation lives in `docs/` and is built with MkDocs. When adding or modifying a feature, always update the relevant docs:

- **`docs/admin/configuration.md`** — environment variable table and full YAML reference must include any new config fields
- **`docs/how-it-works.md`** — feature behaviour, detection logic, and security model changes
- **`docs/getting-started.md`** — if the feature affects initial setup or onboarding

Document any known limitations or detection gaps (e.g. protocol version requirements, header dependencies) and explain the trade-off. If a future approach could extend coverage, note it briefly so operators and contributors have context.

## Database Migrations

SQL migrations live in `internal/database/migrations/` with separate `postgres/` and `sqlite/` subdirectories. Each migration has `*.up.sql` and `*.down.sql` files. Run with `./ghp migrate`.

## CI

PRs trigger the Test workflow (`.github/workflows/test.yml`):
1. Go unit tests + binary build
2. Playwright E2E tests against a live server with SQLite backend
