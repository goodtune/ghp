# Per-Repository Cache Timeout

**Date:** 2026-03-22
**Status:** Approved

## Problem

The gitcache handler's HTTP client uses a hardcoded 30-second timeout for upstream requests. Large repositories (e.g. torvalds/linux at ~4.5 GB) need minutes to transfer their pack data. The connection is killed mid-stream, producing `early EOF` errors on the client.

## Solution

Add an optional `timeout_seconds` column to `cached_repositories`. When set, the gitcache handler uses it as a per-request context timeout for upstream HTTP calls. When NULL, the existing 30-second client timeout applies as the default.

## Design

### Database

New migration `007_add_cache_timeout`:

- **Postgres:** `ALTER TABLE cached_repositories ADD COLUMN timeout_seconds INTEGER;`
- **SQLite:** `ALTER TABLE cached_repositories ADD COLUMN timeout_seconds INTEGER;`

NULL means "use the default 30s". This distinguishes "not configured" from "explicitly set to 30".

Down migrations drop the column.

### Model

Add to `CachedRepository` in `internal/database/models.go`:

```go
TimeoutSeconds *int `json:"timeout_seconds,omitempty"`
```

Pointer type distinguishes null (no override) from zero.

### Store

All SELECT, INSERT, and UPDATE queries in both `sqlite.go` and `postgres.go` include the new column. No interface signature changes — the field rides on the existing struct.

Store contract test (`store_test.go`) gains assertions that `TimeoutSeconds` round-trips correctly for both nil and non-nil values.

### API

**Create** (`POST /api/cached-repos`):
- `createCachedRepoRequest` gains `TimeoutSeconds *int`
- Validation: if non-nil, must be > 0 and <= 3600
- Passed through to `CachedRepository` on creation

**Update** (`PATCH /api/cached-repos/{id}`):
- `updateCachedRepoRequest` gains `TimeoutSeconds *int`
- Same validation
- Applied to existing record when non-nil

**Response** (`cachedRepoResponse`):
- Gains `TimeoutSeconds *int` field
- `cachedRepoToResponse` maps it through

### Gitcache Handler

The `CacheLookup` middleware already queries `CachedRepository` from the database. The timeout value is passed through request context to the handler.

In `proxyUploadPackToUpstream()` and the upstream fetch path in `handleFetch()`, if the cached repo has a non-nil timeout, a `context.WithTimeout` wraps the request using that value. Otherwise the client's existing 30-second timeout applies.

The `httpClient` on the handler keeps `Timeout: 30 * time.Second` as the default safety net. Per-repo context timeouts override it when set to a higher value (context cancellation fires first when the context deadline is shorter than the client timeout; when the context deadline is longer, the client timeout would fire first — so the client timeout is effectively removed for requests that set a per-repo override by using `Timeout: 0` on the cloned request's client, or more simply, the handler uses a client without a timeout and relies entirely on context).

**Revised approach:** Set the handler's `httpClient.Timeout` to 0 (no default). Add a constant `defaultUpstreamTimeout = 30 * time.Second`. When making upstream requests, always create a `context.WithTimeout` using either the repo's configured timeout or the default. This keeps the timeout mechanism uniform and avoids the client-timeout-vs-context-timeout interaction complexity.

### Admin UI

**Add form:** Optional "Timeout (seconds)" number input below the Enabled checkbox. Empty means null.

**Table:** New "Timeout" column showing the configured value or "default" when null.

**Edit:** The PATCH endpoint already supports partial updates via pointer fields. The UI sends `timeout_seconds` when the admin edits it.

### Benchmark Test

- `repoConfig` struct gains `TimeoutSeconds int` (0 = don't set)
- `registerCachedRepo` sends `"timeout_seconds"` in the POST body when non-zero
- `torvalds/linux` config: `TimeoutSeconds: 600`

### Documentation

- `docs/features/git-cache.md`: document per-repo timeout in the "Adding repositories" section, note the default is 30s, mention that large repos may need higher values
- `docs/admin/configuration.md`: add timeout_seconds to the cached repos API reference

## Validation

1. Unit tests: store contract test for timeout round-trip
2. Local benchmark: `REPO=django/django WARM_RUNS=1 go test -tags bench -v -timeout 10m ./bench/`
3. CI benchmark: full run with django (10 warm) and linux (3 warm, 600s timeout)
