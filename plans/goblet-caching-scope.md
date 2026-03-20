# Goblet Git Caching Integration — Feasibility & Scope

## Executive Summary

Adding goblet-based git clone/fetch caching to ghp is **feasible but carries significant risk** due to the library's unmaintained state. The integration point is clean — ghp already intercepts git smart HTTP traffic at a well-defined layer — but goblet itself needs careful evaluation before committing.

## Goblet Library Assessment

### What it does well
- Provides an `http.Handler` that can be dropped into any Go HTTP server
- Caches `git-upload-pack` (clone/fetch) responses using local bare repos
- Only caches when all requested objects are already local — safe cache semantics
- Parses Git protocol v2 at the wire level to determine cacheability
- Apache 2.0 license — fully compatible

### Compatibility Concerns

| Factor | Status | Risk |
|--------|--------|------|
| **Last commit** | July 2021 (~5 years ago) | **High** — unmaintained |
| **Go version** | go 1.12 in go.mod | **Medium** — ghp uses go 1.25; may need module graph fixes |
| **Git binary dependency** | Shells out to `git` via `exec.LookPath` | **Medium** — ghp currently has zero runtime deps (single static binary) |
| **Google Cloud deps** | OpenCensus, Stackdriver, Cloud Storage | **High** — heavy transitive deps ghp doesn't need |
| **CGO** | Not required (uses os/exec, not cgo) | **OK** — compatible with CGO_ENABLED=0 |
| **Git protocol v2 only** | Rejects non-v2 clients | **Low** — modern git defaults to v2 |
| **Read-only** | `git-receive-pack` returns "unimplemented" | **OK** — matches our goal |
| **ls-refs always forwarded** | Reference listings always hit upstream | **OK** — means cache is always fresh for ref names |

### Critical Risk: Unmaintained + Heavy Dependencies

Goblet's dependency tree pulls in Google Cloud SDK, OpenCensus (deprecated in favor of OpenTelemetry), gRPC, and Stackdriver. These add significant binary bloat and potential version conflicts with ghp's existing deps. The library hasn't been updated in 5 years, meaning these dependencies are at ancient versions.

**Recommendation:** Before proceeding, attempt `go get github.com/google/goblet@latest` in a throwaway branch and evaluate whether the dependency graph resolves cleanly. If it doesn't, consider forking goblet and stripping the Google Cloud dependencies (they're used for metrics/logging, not core caching logic).

## Integration Architecture

### Where goblet fits in the request path

```
Client (git clone)
  → ghp (github.com host handler)
    → Scoped Passthrough Handler (token resolution + scope enforcement)
      → [NEW] Goblet Cache Check
        → Cache HIT:  serve from local bare repo
        → Cache MISS: forward to github.com (existing passthrough)
```

The insertion point is **after** scope enforcement but **before** the upstream roundtrip in the scoped passthrough handler (`internal/proxy/passthrough.go`). This ensures:
1. Token validation and scope checks still happen
2. Only authorized repos get cached responses
3. The cache layer is invisible to the auth pipeline

### URL routing

Goblet expects URLs like `/{owner}/{repo}.git/git-upload-pack` and `/{owner}/{repo}.git/info/refs`. GHP already parses these exact patterns in `internal/proxy/scope.go` (the `gitSmartHTTPPattern`). The integration would intercept matching requests where the repo is in the cache-enabled set.

### Configuration: Database-Driven Cache Policy

New `CachedRepository` model in the store:

```go
type CachedRepository struct {
    ID          string    // UUID
    Owner       string    // e.g. "google"
    Name        string    // e.g. "goblet"
    FullName    string    // "google/goblet" (unique index)
    Enabled     bool      // soft disable without deleting
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

Store interface additions:
```go
CreateCachedRepository(ctx, repo) error
GetCachedRepository(ctx, owner, name string) (*CachedRepository, error)
ListCachedRepositories(ctx) ([]CachedRepository, error)
DeleteCachedRepository(ctx, id string) error
UpdateCachedRepository(ctx, id string, updates) error
IsCacheEnabled(ctx, owner, name string) (bool, error)  // hot-path lookup
```

### Request flow (detailed)

1. Git smart HTTP request arrives at scoped passthrough
2. Token is resolved and scope is enforced (existing logic)
3. **New:** Extract `owner/repo` from the git URL pattern
4. **New:** Check `IsCacheEnabled(ctx, owner, repo)` against the store
5. If caching **disabled** → existing passthrough to github.com (no change)
6. If caching **enabled** → delegate to goblet's `http.Handler`
   - Goblet checks its local cache
   - On miss, goblet fetches from upstream (using the resolved GitHub token)
   - On hit, goblet serves from local bare repo

### Admin API endpoints

```
POST   /api/cached-repos          — Enable caching for a repository
GET    /api/cached-repos          — List cached repositories
GET    /api/cached-repos/{id}     — Get cached repo details
PATCH  /api/cached-repos/{id}     — Update (enable/disable)
DELETE /api/cached-repos/{id}     — Remove from cache policy + purge local cache
```

### Admin UI

Add a "Cache" section to the web UI showing:
- Table of cached repositories with enabled/disabled toggle
- Form to add new repositories
- Cache size / last-fetched metadata per repo (from goblet's `ManagedRepository.LastUpdateTime()`)

### Config additions

```yaml
cache:
  enabled: true                    # master switch
  directory: /var/cache/ghp/git    # local disk path for bare repos
  max_size_gb: 50                  # optional disk quota
```

Environment variables: `GHP_CACHE_ENABLED`, `GHP_CACHE_DIRECTORY`, `GHP_CACHE_MAX_SIZE_GB`

Hot-reloadable: `enabled` (master switch). Not hot-reloadable: `directory`.

### Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `ghp_cache_request_total` | Counter | `owner`, `repo`, `result` (hit/miss/bypass) |
| `ghp_cache_request_duration_seconds` | Histogram | `owner`, `repo`, `result` |
| `ghp_proxy_decision_duration_seconds` | Histogram | stage=`cache_policy_check` (new stage) |
| `ghp_cache_repository_size_bytes` | Gauge | `owner`, `repo` |

### Database migrations

New table `cached_repositories` in both postgres and sqlite:
- `id` UUID primary key
- `owner` TEXT NOT NULL
- `name` TEXT NOT NULL
- `enabled` BOOLEAN NOT NULL DEFAULT TRUE
- `created_at` TIMESTAMP
- `updated_at` TIMESTAMP
- UNIQUE INDEX on `(owner, name)`

## Implementation Plan (Ordered)

### Phase 0: Validate goblet dependency (1 task)
1. Attempt to add goblet to go.mod, resolve dependency conflicts
2. If conflicts are severe, evaluate forking and stripping GCP deps

### Phase 1: Data model + API (5 tasks)
1. Database migration for `cached_repositories` table (postgres + sqlite)
2. `CachedRepository` model + Store interface methods
3. SQLite + Postgres + Vault backend implementations
4. Store contract tests
5. Admin API endpoints + handler tests

### Phase 2: Cache integration (4 tasks)
1. Configuration additions (`cache.*` fields)
2. Goblet `ServerConfig` wiring (token source, cache dir, logging)
3. Intercept in scoped passthrough handler — route cache-enabled repos to goblet
4. Decision pipeline metrics for cache stage

### Phase 3: Admin UI + docs (3 tasks)
1. Web UI for managing cached repositories
2. Documentation updates (configuration.md, how-it-works.md)
3. E2E test coverage

## Open Questions

1. **Fork or use as-is?** Goblet's GCP dependencies are heavy. A minimal fork stripping OpenCensus/Stackdriver/Cloud Storage would reduce binary size and dep conflicts significantly. The core caching logic (~4 files) is self-contained.

2. **Token injection into goblet.** Goblet uses `oauth2.TokenSource` for upstream auth. GHP resolves tokens per-request (different users have different credentials). We'd need to either (a) create a per-request `TokenSource` adapter or (b) modify goblet's handler to accept tokens from the request context.

3. **Cache invalidation.** Goblet caches git objects (immutable) but forwards `ls-refs` upstream (always fresh). This means clients always see current branch tips but fetch object data from cache. This is correct behavior — git objects are content-addressed and immutable.

4. **Disk management.** Should ghp manage cache disk usage, or leave it to operators? A background goroutine that prunes least-recently-used repos when disk exceeds `max_size_gb` would be nice but adds complexity.

5. **Multi-instance deployments.** Each ghp instance would have its own local cache. No shared state needed — each instance warms independently. This is simple but means cache hit rates scale with instance stickiness.
