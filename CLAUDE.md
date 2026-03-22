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
- `ghp_cache_fetch_total` / `ghp_cache_lsrefs_total` / `ghp_cache_warm_total` — cache operation counters
- `ghp_cache_packfile_total` / `ghp_cache_packfile_bytes_total` — packfile response cache hit/miss counts and bytes served
- `ghp_cache_repos_active` — gauge of cache-enabled repositories
- `ghp_cache_request_total` — per-repository git requests with cache outcome (`owner`, `repo`, `result` labels)

## Coding Conventions

- Standard Go formatting (`gofmt`)
- Table-driven tests using `t.Run()`
- Explicit error handling (`if err != nil`)
- Unit tests colocated with source (`*_test.go`)
- `CGO_ENABLED=0` for all builds (pure Go, no C dependencies)
- Configuration via YAML files or environment variables with `GHP_` prefix

### Sentinel Errors

New `Store` interface methods that look up a record by ID should return `database.ErrNotFound` (wrapped via `fmt.Errorf("...: %w", database.ErrNotFound)`) when the record does not exist. Prefer this over plain `fmt.Errorf("not found")` strings. API handlers should map `ErrNotFound` → 404 and other store errors → 500. Some older methods (e.g. `RevokeProxyToken`, `UpdateProxyTokenUsage`) predate this convention and use different patterns; align them as they are touched.

### API Input Validation

Validate all user-supplied inputs at the handler level before any store call:

- **IDs:** Validate UUID format up-front and return 400 for malformed IDs. Never let invalid UUIDs reach the database driver (they produce 500s).
- **Numeric IDs:** Reject zero and negative values for GitHub App IDs and similar positive-integer fields (`> 0`).
- **URLs:** Use `validateBaseURL()` — enforce `https` scheme, reject query/fragment/userinfo, normalize trailing slashes.
- **Required fields:** Validate required fields (e.g., `private_key` for app creation) and return 400 with a clear message.
- **Token type guards:** Reject fields that are invalid for the token type (e.g., `app_record_id` on proxy tokens).
- **MaxBytesReader errors:** Always check for `*http.MaxBytesError` via `errors.As` and return 413, not 400. Apply `MaxBytesReader` and decode the body before doing store lookups.

### Partial Updates (PATCH Semantics)

When implementing partial-update API handlers, use pointer types (`*string`, `*bool`, `*int64`) in request structs to distinguish "field omitted" from "field set to zero value". Never use bare `bool` or `int` in update request structs — Go zero values make it impossible to distinguish intentional clears from absent fields. For string fields, only update when the pointer is non-nil (not just when the value is non-empty), so callers can explicitly clear a field to its default.

### Atomicity for Invariant Changes

Operations that enforce cross-record invariants (e.g., "exactly one default app") must be atomic. For SQL backends, use a transaction. For Vault, use check-and-set (CAS) or document the limitation. Never clear the old state before confirming the new state is set — if the second operation fails, the system is left invalid. Pattern: create/update the new record first (with `is_default=false`), then atomically swap the default flag within a single transaction.

### JSON API Response Conventions

- List endpoints must initialize slices with `make([]T, 0)` so JSON encodes as `[]`, not `null`.
- Use distinct JSON field names when two concepts share a word. For example, a database record ID and a GitHub numeric App ID must never both be called `app_id` — use `app_record_id` vs `github_app_id` (or similar) to prevent confusion.

### Test Requirements for New Features

Every new API endpoint or CRUD surface must have:

- Happy-path tests for each HTTP method.
- Key negative-case tests (not found, invalid input, auth/permission failures).
- If a handler uses `r.PathValue()`, tests must either use a mux route or call `req.SetPathValue()` — bare handler calls without path values will panic.
- Test-only helpers (e.g., `NewRegistryWithState`) must live in `_test.go` files, not production code. If a stub is needed in production, it must be safe to call (no nil-pointer panics on any method).

### Store Contract Tests

Every `Store` interface method must have a contract test in `store_test.go` that runs against all backends (SQLite, Postgres, Vault). Contract tests must cover:

- Happy-path round-trip of **every field** on the model (when adding a new field, add an assertion).
- Not-found paths must assert `errors.Is(err, database.ErrNotFound)`.
- Use valid UUIDs (e.g., `uuid.New().String()`) for non-existent record lookups — never use arbitrary strings like `"nonexistent-id"` as Postgres UUID columns will reject them with a driver error.
- Test cleanup (`DeleteApp`, etc.) must assert errors, not silently ignore them.

## Documentation

User-facing documentation lives in `docs/` and is built with MkDocs. When adding or modifying a feature, always update the relevant docs:

- **`docs/admin/configuration.md`** — environment variable table and full YAML reference must include any new config fields
- **`docs/how-it-works.md`** — feature behaviour, detection logic, and security model changes
- **`docs/getting-started.md`** — if the feature affects initial setup or onboarding

Document any known limitations or detection gaps (e.g. protocol version requirements, header dependencies) and explain the trade-off. If a future approach could extend coverage, note it briefly so operators and contributors have context.

### Documentation Accuracy

Docs must match code. When adding CLI flags, API fields, or UI elements:

- Verify the CLI flag actually exists and is wired through before documenting it.
- If docs reference a UI element (e.g., "shown in the admin table"), verify the element is rendered in the template.
- When a field name has different meanings in different contexts, use distinct names and document which is which.

## Database Migrations

SQL migrations live in `internal/database/migrations/` with separate `postgres/` and `sqlite/` subdirectories. Each migration has `*.up.sql` and `*.down.sql` files. Run with `./ghp migrate`.

### Schema Design Rules

- **Foreign keys must specify ON DELETE behavior.** Never leave FK constraints with implicit `NO ACTION`. Choose explicitly: `ON DELETE RESTRICT` (prevent deletion of referenced records), `ON DELETE CASCADE`, or `ON DELETE SET NULL` — and document the rationale. Prefer `ON DELETE RESTRICT` when deletion semantics are unclear; it is safer to block and force the caller to handle cleanup than to silently cascade or null-out references.
- **Enforce uniqueness invariants at the database level.** Application-level invariants (e.g., at most one default app) must be backed by a database constraint such as a partial unique index (`CREATE UNIQUE INDEX ... WHERE is_default = TRUE`). Do not rely solely on application code for uniqueness — concurrent requests and direct DB access can violate it.
- **Upsert statements must use `RETURNING`** to sync the in-memory ID/timestamps with the persisted row. Never generate a new UUID client-side and assume it was inserted — on conflict-update paths the existing row ID must be returned.
- **Migrations must be consistent across backends.** Every schema change in `postgres/` must have an equivalent in `sqlite/` (and vice versa). Constraints, indexes, and ON DELETE behavior must match semantically even if syntax differs.

## Vault Backend

When working on the Vault storage backend (`internal/database/vault.go`):

- **All KV operations must be wrapped in `withRelogin`.** This includes `kvRead`, `kvWrite`, `kvList`, and `kvDelete`. When adding a new KV helper, always wrap it — otherwise the operation will fail permanently after Vault token expiry while other operations recover.
- **Vault API calls must accept and propagate `context.Context`** for cancellation and timeout support. Never use bare `client.Logical().Write(...)` without context.
- **Avoid `json.Marshal` → `map[string]interface{}` round-trips for numeric fields.** This conversion routes all numbers through `float64`, which silently loses `int64` precision for large values (e.g., `RequestCount`). Use `json.Decoder` with `UseNumber()` when decoding into maps, or handle numeric fields explicitly.
- **Error detection for auth failures must use structured error types or HTTP status codes**, not substring matching on error messages (e.g., checking for `"403"` in error text). Error message formats can change across Vault versions.
- **Document concurrency limitations.** Vault KV does not support atomic increments. Read-modify-write patterns (e.g., usage counter updates) are subject to lost updates under concurrent load. Use KV v2 check-and-set (`cas`) with retry loops where accuracy matters, or document that the value is best-effort.

## Web UI

The admin web UI lives in `internal/web/templates/` as Go HTML templates with embedded vanilla JavaScript.

- **No inline JS event handlers.** Never use `onclick="..."` with string concatenation. HTML entity escaping (`esc()`) is not safe for JavaScript string contexts — the browser decodes entities before executing the handler, so quotes can escape the string. Add event listeners programmatically via `addEventListener` or use `document.createElement` to build DOM elements.
- **The `api()` helper must check `resp.ok`.** It must throw or return an error object on non-2xx responses. All callers must handle errors with `try/catch` or `.catch()` and render an error state in the UI. Never leave the UI stuck on "Loading..." when an API call fails.
- **Handle async rejections.** `navigator.clipboard.writeText()` and similar async browser APIs can reject. Always add a `.catch()` handler or use `try/await/catch`.
- **Graceful degradation on load.** When an API call fails during page initialization, render an empty or error state rather than leaving the form/table in a partially-initialized "Loading..." state. For multi-select flows (e.g., app selector → installation list), do not call the dependent loader until the parent selector has a valid selection.
- **Client-side validation must match server-side.** If the API requires a field (e.g., `private_key` for app creation), the form must validate it before submission to avoid confusing round-trip 400 errors.

## AppRegistry / Provider Lifecycle

When working on `internal/github/registry.go`:

- **`LoadAll()` and `Reload()` must reset state** (clear the `providers` map and reset `defaultID`) before rebuilding from the store. Stale providers from deleted apps must not persist in memory.
- **Failed provider loads must be cleaned up.** If `loadAppLocked(app)` fails, remove the provider entry from the map and do not set it as default.
- **Detect multiple defaults.** If more than one app has `is_default=true`, pick deterministically (e.g., by `created_at`) and log a warning. Never silently let "last one wins" determine the default.
- **The proxy/resolver must reference `AppRegistry` dynamically** — not capture a single `AppTokenProvider` at startup. Apps created via the admin UI/API must take effect without a server restart. Always wire `appRegistry` as the `appTokenProvider`, even when the registry is initially empty.
- **Distinguish "no apps in store" from "apps exist but none loaded."** Expose both `Count()` (loaded providers) and `TotalApps()` (store records). Config-based fallback should only activate when the store genuinely has zero app records and `LoadAll` succeeded — never as a silent fallback when apps failed to load.
- **Reject agent token creation when no usable provider exists.** If `TotalApps() > 0` but `Count() == 0` (all apps failed to load), return 503 rather than creating tokens that will fail at use-time.

## CI

PRs trigger the Test workflow (`.github/workflows/test.yml`):
1. Go unit tests + binary build
2. Playwright E2E tests against a live server with SQLite backend
