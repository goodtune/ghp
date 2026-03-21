# Git Clone/Fetch Caching — Feasibility & Scope

## Executive Summary

We will implement a Git protocol v2 caching proxy within ghp, inspired by Google's [goblet](https://github.com/google/goblet) (Apache 2.0). Rather than importing goblet as a dependency — it's unmaintained (last commit 2021), drags in GCP/gRPC/OpenCensus, and shells out to the `git` binary — we'll reimplement the core caching technique using pure Go libraries. The technique is well-understood and the code is compact (~600 lines across 5 files).

## Goblet's Technique — Deep Analysis

### How the caching works

Goblet operates as a Git protocol v2 HTTP proxy. It intercepts the two smart HTTP endpoints (`/info/refs?service=git-upload-pack` and `/git-upload-pack`) and makes per-command caching decisions:

**1. `/info/refs` — Capability advertisement (synthetic)**

The cache server returns a hardcoded capability list — it does NOT proxy this to upstream:
```
version 2
ls-refs
fetch=filter shallow
server-option
```
This tells the git client "I support protocol v2 with these commands." The client never negotiates directly with GitHub for capabilities.

**2. `/git-upload-pack` — Command processing**

Git protocol v2 sends multiple commands in a single POST body. Goblet parses the request using `gitprotocolio.NewProtocolV2Request()` scanner, extracting structured `ProtocolV2RequestChunk` objects. Each command is handled independently:

**`ls-refs` command (always proxied upstream):**
- Forwards the raw protocol v2 request to GitHub's `/git-upload-pack` endpoint via HTTP POST
- Parses the response to extract ref→hash mappings
- Compares against locally cached refs via `go-git`'s `Reference()` API
- If any refs have changed → triggers async `fetchUpstream()` to update the local cache
- Returns the upstream response verbatim to the client
- This ensures clients always see current branch tips

**`fetch` command (cache-or-fetch):**
- Parses `want <hash>` and `want-ref <refname>` arguments from the request
- Checks `hasAllWants()` — do all requested objects/refs exist in our local bare repo?
  - Uses `go-git`'s `repo.Object(plumbing.AnyObject, hash)` for object existence
  - Uses `go-git`'s `repo.Reference(name, true)` for ref existence
- **Cache HIT**: All wants satisfied locally → serve pack data from local bare repo
- **Cache MISS**: Trigger `fetchUpstream()`, poll every 1s until objects appear, then serve locally

**3. Local serving — `git upload-pack --stateless-rpc` (exec to git binary)**

When serving from cache, goblet pipes the parsed request back into `git upload-pack --stateless-rpc <bare-repo-dir>` and streams stdout to the HTTP response. This generates a client-specific packfile containing exactly the objects the client needs (based on their `have`/`want` negotiation).

**4. Upstream fetching — `git fetch origin` (exec to git binary)**

Populates the local bare repo cache by running `git fetch` with an OAuth bearer token injected via `-c http.extraHeader=Authorization: Bearer <token>`.

### Why this works for caching

Git objects are content-addressed and immutable — a SHA identifies exactly one object forever. The cache only needs to store objects, not responses. Different clients requesting the same objects get different pack encodings (based on what they already have), but the underlying data is identical. By maintaining a local bare repo mirror and using `upload-pack` to generate packs, each client gets a correctly negotiated response from cached data.

### What uses the git binary (and our pure Go replacements)

| Goblet operation | Git binary call | Pure Go replacement |
|---|---|---|
| Init bare cache repo | `git init --bare` | `go-git` `git.PlainInit(path, true)` |
| Configure protocol v2 | `git config protocol.version 2` etc. | `go-git` config API or direct file write |
| Add upstream remote | `git remote add --mirror=fetch origin <url>` | `go-git` `repo.CreateRemote()` |
| Fetch from upstream | `git fetch -f origin` | `go-git` `repo.Fetch()` with custom auth |
| **Serve pack to client** | `git upload-pack --stateless-rpc` | **See analysis below** |
| Bundle create/restore | `git bundle create/fetch` | Not needed for our use case |

### The hard problem: pure Go upload-pack serving

This is the most critical piece. `git upload-pack --stateless-rpc` reads a protocol v2 fetch request, performs pack negotiation (comparing client's `have` objects against server's objects), and streams back a packfile.

**Options for pure Go:**

1. **`go-git` transport server** (`github.com/go-git/go-git/v5/plumbing/transport/server`):
   - Has `ServeUploadPack(ctx, endpoint, session)` that implements the server side
   - Designed for protocol v1; protocol v2 support is limited
   - Would need adaptation to accept pre-parsed protocol v2 request chunks

2. **`go-git` plumbing directly** — build pack generation from primitives:
   - Use `plumbing/format/packfile.Encoder` to write packfiles
   - Use `plumbing/revlist.Objects()` to compute the object set (wants minus haves)
   - More work but full control, no protocol version mismatch
   - This is essentially reimplementing the core of upload-pack in ~100-200 lines

3. **HTTP reverse proxy with response caching** (alternative architecture):
   - Instead of maintaining a bare repo and generating packs, cache raw HTTP responses keyed by the normalized request
   - Simpler but less effective — git requests are client-specific (haves differ per client)
   - Only works well for initial clones where all clients have zero haves

**Recommendation:** Start with option 2 (go-git plumbing). The object set computation is straightforward with go-git, and packfile encoding is a well-tested primitive. This avoids the protocol v1/v2 impedance mismatch of option 1. If we hit go-git limitations (e.g., shallow clone support, delta compression quality), we can evaluate adding the git binary as an optional runtime dependency later.

### The protocol parsing layer

`gitprotocolio` (github.com/google/gitprotocolio) is a **zero-dependency** pure Go library that parses Git protocol v2 wire format. It provides:

- `NewProtocolV2Request(io.Reader)` → scanner yielding `ProtocolV2RequestChunk` (command, arguments, capabilities)
- `NewProtocolV2Response(io.Reader)` → scanner yielding `ProtocolV2ResponseChunk`
- `InfoRefsResponseChunk` for capability advertisement
- `EncodeToPktLine()` on all types for serialization
- `ErrorPacket` for protocol-level errors

The library is archived (Jan 2023) but stable and trivially small. We can either import it directly (zero transitive deps) or vendor the ~500 lines of parsing code.

## Access Control: Preserving GitHub's Authorization

### The problem

GHP currently relies on **two layers** of access control:

1. **GHP scope check** — does the `ghx_`/`gha_` token's declared scope include this repo? (narrowing filter)
2. **GitHub's own check** — does the underlying GitHub token actually have access? (authoritative)

Layer 2 happens because the real GitHub credential is forwarded to GitHub on every request. GitHub returns 403/404 if the user lacks access. This is the definitive authorization — GHP never needs to track GitHub's permission model.

With caching, a **cache hit skips the upstream roundtrip**, which would eliminate layer 2. A user whose GitHub access was revoked could still read cached objects. This is an authorization bypass.

### Solution: ls-refs as mandatory authorization gate

Goblet's design already solves this, and we must preserve the invariant:

**Rule: `ls-refs` is ALWAYS forwarded to GitHub with the per-request token. No cached data is served unless ls-refs succeeds first.**

Normal Git protocol v2 flow:
1. Client sends `POST /git-upload-pack` with `ls-refs` command followed by `fetch` command
2. `ls-refs` is forwarded to GitHub using the caller's resolved GitHub token
3. GitHub verifies the token has access → returns refs (success) or 403/404 (failure)
4. Only if `ls-refs` succeeds does the `fetch` command execute (potentially from cache)

This means every cached response is preceded by a live GitHub access check. The cost is one HTTP roundtrip to GitHub per git operation — but this is the `ls-refs` call which is lightweight (returns ref names + SHAs, no object data), and is the exact call that goblet makes on every request too.

### Hardening: fetch-without-ls-refs

A malicious client could craft a protocol v2 request containing only a `fetch` command (no `ls-refs`), bypassing the authorization gate. Normal git clients never do this, but we must defend against it.

**Policy: Reject `fetch` commands that are not preceded by a successful `ls-refs` in the same request.**

Implementation:
```go
func (h *handler) uploadPackHandler(w http.ResponseWriter, r *http.Request) {
    commands := parseAllCommands(r.Body)
    lsRefsSucceeded := false

    for _, cmd := range commands {
        switch cmd[0].Command {
        case "ls-refs":
            // Forward to GitHub — this IS the access check
            if err := h.handleLsRefs(ctx, cmd, w); err != nil {
                return // GitHub rejected — stop processing
            }
            lsRefsSucceeded = true
        case "fetch":
            if !lsRefsSucceeded {
                // No ls-refs preceded this fetch — deny
                writeError(w, "fetch requires ls-refs first")
                return
            }
            h.handleFetch(ctx, cmd, w) // safe to serve from cache
        }
    }
}
```

### Access control summary

| Request type | Access verified by | Cache can serve? |
|---|---|---|
| `/info/refs` | N/A (synthetic capabilities, no repo data) | Always (no objects exposed) |
| `ls-refs` command | GitHub (forwarded with user's token) | Never (always upstream) |
| `fetch` after successful `ls-refs` | GitHub (via preceding ls-refs) | Yes — cache hit serves locally |
| `fetch` without preceding `ls-refs` | **Rejected by ghp** | No — request denied |
| Any request for non-cached repo | GitHub (normal passthrough) | N/A — passthrough unchanged |

### What this means for revoked access

- User loses GitHub access to a cached repo
- Next `git fetch` sends `ls-refs` → forwarded to GitHub → GitHub returns 403
- ghp returns error to client, no cached data served
- Latency: access revocation takes effect on the **next request** — no stale window beyond a single operation

### Private repo considerations

The cache stores git objects on local disk. For private repos, this means:
- Source code exists in the cache directory in cleartext (bare git repo)
- Disk-level encryption (LUKS, encrypted EBS, etc.) is the operator's responsibility
- The `cached_repositories` admin API should warn when adding private repos
- Docs should state: "the cache directory contains a full mirror of cached repositories; protect it accordingly"

## Integration Architecture

### Request flow in ghp

```
git clone https://ghp.example.com/owner/repo.git
  → ghp host dispatch (github.com handler)
    → Scoped Passthrough Handler
      → Token extraction + border policy check
      → Token resolution (ghx_ → GitHub credential)
      → Scope enforcement (repo allowlist + permissions)
      → [NEW] Cache policy check: IsCacheEnabled(owner, repo)?
        → NO:  existing passthrough to github.com (unchanged)
        → YES: delegate to git cache handler
          → /info/refs: return synthetic capabilities
          → /git-upload-pack:
            → ls-refs: forward to GitHub WITH USER'S TOKEN (access check)
              → GitHub 403/404? → return error, stop
              → GitHub 200? → return refs, continue
            → fetch (only after ls-refs succeeded):
              → check local objects → serve from cache or fetch-then-serve
```

The insertion point is **after** scope enforcement but **before** the upstream roundtrip. This ensures:
1. Token validation and scope checks still happen for every request
2. Only authorized, scope-allowed repos can be cached
3. The resolved GitHub credential is available for upstream ls-refs verification
4. The cache layer is invisible to the auth pipeline
5. **GitHub verifies access on every operation via the mandatory ls-refs call**

### New package: `internal/gitcache/`

```
internal/gitcache/
  handler.go         — http.Handler implementing the cache proxy
  repository.go      — managed bare repo: init, fetch, object queries
  protocol.go        — Git protocol v2 command parsing and response writing
  packserve.go       — Pure Go pack generation from local objects
  handler_test.go    — Unit tests with in-memory repos
  repository_test.go — Repo management tests
```

### Token injection

Goblet uses a single `oauth2.TokenSource` for all upstream requests. GHP resolves tokens per-request (different users have different GitHub credentials). Our design:

- The cache handler receives the **already-resolved GitHub token** from the scoped passthrough handler via request context
- For `ls-refs` upstream forwarding: use the per-request token
- For `fetchUpstream()` (async cache warming): use a **service credential** (GitHub App installation token from the app registry) rather than a user token, since the fetch happens asynchronously and the user's token may expire

### Configuration: database-driven cache policy

New `CachedRepository` model:

```go
type CachedRepository struct {
    ID        string    // UUID
    Owner     string    // e.g. "google"
    Name      string    // e.g. "goblet"
    FullName  string    // "google/goblet" (unique, derived)
    Enabled   bool      // soft disable without deleting
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

Store interface additions:
```go
CreateCachedRepository(ctx context.Context, repo *CachedRepository) error
GetCachedRepository(ctx context.Context, id string) (*CachedRepository, error)
ListCachedRepositories(ctx context.Context) ([]CachedRepository, error)
DeleteCachedRepository(ctx context.Context, id string) error
UpdateCachedRepository(ctx context.Context, id string, updates *CachedRepositoryUpdate) error
IsCacheEnabled(ctx context.Context, owner, name string) (bool, error)  // hot-path
```

`IsCacheEnabled` should be backed by an in-memory cache (LRU or sync.Map) with short TTL, since it's called on every git request. The database is the source of truth; the memory cache avoids a DB round-trip on the hot path.

### Admin API endpoints

```
POST   /api/cached-repos          — Enable caching for a repository
GET    /api/cached-repos          — List cached repositories
GET    /api/cached-repos/{id}     — Get details
PATCH  /api/cached-repos/{id}     — Update (enable/disable)
DELETE /api/cached-repos/{id}     — Remove + purge local cache
```

### Metrics

#### What goblet tracked (OpenCensus → our Prometheus equivalents)

Goblet instrumented six metrics with OpenCensus, using tag keys for `command_type` (ls-refs, fetch), `cache_state` (locally-served, queried-upstream), and `canonical_status` (OK, Internal, etc.):

| Goblet metric (OpenCensus) | What it measured | Our equivalent |
|---|---|---|
| `InboundCommandCount` | Commands received, by type + status | `ghp_cache_command_total` |
| `InboundCommandProcessingTime` | Per-command processing latency | `ghp_cache_command_duration_seconds` |
| `OutboundCommandCount` | Upstream commands sent (ls-refs, fetch) | Captured by existing `ghp_proxy_decision_duration_seconds` stage=`upstream_roundtrip` |
| `OutboundCommandProcessingTime` | Upstream command latency | Same as above |
| `UpstreamFetchWaitingTime` | Time blocked waiting for upstream fetch to complete (polling loop) | `ghp_cache_fetch_wait_duration_seconds` |
| `CommandCacheState` tag | "locally-served" vs "queried-upstream" per command | Label `cache_state` on command metrics |

#### New Prometheus metrics

| Metric | Type | Labels | Buckets | Description |
|--------|------|--------|---------|-------------|
| `ghp_cache_command_total` | Counter | `command` (ls-refs, fetch), `cache_state` (hit, miss, rejected), `status` (ok, error) | — | Git protocol v2 commands processed by the cache layer |
| `ghp_cache_command_duration_seconds` | Histogram | `command`, `cache_state` | Fine-grained (50µs–1s) for locally-served; extended (2.5s–10s) for upstream | Per-command processing time |
| `ghp_cache_fetch_wait_duration_seconds` | Histogram | — | Extended (100ms–30s) | Time spent waiting for async upstream fetch before serving |
| `ghp_cache_upstream_fetch_duration_seconds` | Histogram | — | Extended (1s–60s) | Duration of `fetchUpstream()` background operations |
| `ghp_cache_objects_total` | Gauge | — | — | Total cached git objects across all repos (periodic scan) |

**Decision pipeline additions** (recorded via existing `ObserveDecision()` helper):

| Stage | What it measures |
|---|---|
| `cache_policy_check` | `IsCacheEnabled()` lookup (memory cache + DB fallback) |
| `cache_object_check` | `hasAllWants()` — checking if requested objects exist locally |
| `cache_pack_serve` | Time to generate and stream packfile from local objects |

**Existing metrics that apply unchanged:**
- `ghp_proxy_request_duration_seconds` / `ghp_proxy_request_total` — the cache handler still records these with `type=git` and the new `cache_state` label value
- `ghp_http_request_duration_seconds` / `ghp_http_request_total` — recorded by access log middleware, unaffected by cache

Note: no `owner`/`repo` labels on any counter — unbounded cardinality per CLAUDE.md guidelines.

### Access logging

The existing access log (`accessLogEntry` in `internal/server/accesslog.go`) writes Caddy-compatible JSON with fields for `user_id`, `status`, `duration`, `size`, request/response headers, etc. The cache feature adds two new fields to the access log entry:

```go
type accessLogEntry struct {
    // ... existing fields ...
    CacheState string `json:"cache_state,omitempty"` // "hit", "miss", "rejected", "error", or "" (non-git)
    CacheRepo  string `json:"cache_repo,omitempty"`  // "owner/repo" when request targets a cached repo
}
```

**`cache_state`** values:
- `"hit"` — fetch command served entirely from local cache
- `"miss"` — fetch command required upstream fetch before serving
- `"rejected"` — access denied or fetch-before-ls-refs violation
- `"error"` — cache or upstream failure
- `""` (omitted) — request is not a git smart HTTP operation, or repo is not in the cached set

**`cache_repo`** — the `owner/repo` identifier when the target repository is in the `cached_repositories` table (regardless of whether caching was used for this specific request). This lets operators filter logs to see all traffic to cached repos, including pushes and API calls that bypass caching.

**Implementation:** The cache handler sets these values via new context slots (same pattern as `SetUsername`/`SetUserID`):
```go
proxy.SetCacheState(r, "hit")
proxy.SetCacheRepo(r, "owner/repo")
```

The access log middleware reads them after the request completes, alongside the existing username/userID slots.

### Database migrations

New table `cached_repositories` in both postgres and sqlite:
```sql
CREATE TABLE cached_repositories (
    id TEXT PRIMARY KEY,          -- UUID
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_cached_repos_owner_name ON cached_repositories (owner, name);
```

## Storage Backend: Local Filesystem vs S3

### The scalability concern

ghp is designed as a stateless, horizontally-scalable proxy. Adding a local disk cache breaks this: each instance has its own cache, cache hit rates depend on request routing stickiness, and local disk introduces a capacity/provisioning concern.

### Storage abstraction via go-git's `Storer` interface

go-git already defines a `storage.Storer` interface that abstracts where git objects, references, and config live. It ships with `filesystem` and `memory` implementations. We can plug in an S3-backed implementation:

```go
// internal/gitcache/storage.go

// CacheStorage abstracts where cached git objects are stored.
// go-git's Storer interface is the foundation — our S3 backend
// implements the same interface, making it transparent to the
// rest of the cache layer.
type CacheStorageFactory interface {
    // Open returns a go-git Storer for the given repository.
    // Creates the backing storage if it doesn't exist.
    Open(owner, repo string) (storage.Storer, error)

    // Delete removes all cached data for a repository.
    Delete(owner, repo string) error
}
```

**Implementations:**

| Backend | Config value | Description |
|---|---|---|
| `filesystem` (default) | `cache.storage: filesystem` | Bare repos on local disk under `cache.directory`. Simple, fast, single-instance. |
| `s3` | `cache.storage: s3` | Git objects stored in S3 keyed by SHA. All instances share the cache. |

### S3 backend design

```yaml
cache:
  enabled: true
  storage: s3
  s3:
    bucket: my-ghp-cache
    prefix: git-objects/      # optional key prefix
    region: us-east-1
```

**Object layout in S3:**
```
s3://my-ghp-cache/git-objects/{owner}/{repo}/objects/{sha[0:2]}/{sha[2:]}
s3://my-ghp-cache/git-objects/{owner}/{repo}/refs/{refname}
s3://my-ghp-cache/git-objects/{owner}/{repo}/pack/pack-{sha}.{idx,pack}
```

This maps directly to git's loose object and packfile layout. The go-git `Storer` interface reads/writes at this level, so the rest of the cache handler is unchanged.

**Benefits:**
- All ghp instances share a single cache — no stickiness required
- No local disk provisioning — S3 is effectively unlimited
- Objects are durable (S3 replication) — a restarted instance doesn't cold-start
- S3 lifecycle rules can handle eviction (e.g., expire objects untouched for 30 days)

### Why redirect-to-S3 doesn't cleanly work (and what does)

The idea of returning an HTTP redirect to an S3 URL for the packfile response hits a protocol constraint:

1. **Packfiles are client-specific.** The `fetch` response is a packfile containing exactly the objects the client needs (wants minus haves). Different clients get different packfiles. You can't pre-generate a single S3 object to redirect to.

2. **POST redirects lose the body.** Git's `/git-upload-pack` is a POST. HTTP redirects (301/302) cause clients to resend as GET, losing the request body containing wants/haves. Git does handle some redirects, but not for the upload-pack POST.

3. **The response is pkt-line framed.** Even if we pre-generated a packfile, the HTTP response wraps it in Git protocol v2 pkt-line framing. An S3 object would need to contain the exact framed response.

**What DOES work with S3:**

- **S3 as shared object store** (described above) — all instances read/write objects to S3. Pack generation still happens on the ghp instance (CPU work), but object data comes from S3. This is the right horizontal scaling approach.

- **Pre-generated clone packs (future optimization):** For the narrow case of initial clones (client has zero objects), the packfile IS deterministic for a given set of refs. We could pre-generate a full clone pack after each `fetchUpstream()`, store it in S3, and serve it directly for clone requests. This would be detected by an empty `have` set in the fetch command. This is a meaningful optimization since the most common agent workflow is "clone the repo" — but it's additive and can come later.

### Configuration

```yaml
cache:
  enabled: true                    # master switch (hot-reloadable)
  storage: filesystem              # "filesystem" or "s3"
  directory: /var/cache/ghp/git    # for filesystem backend
  s3:                              # for s3 backend
    bucket: my-ghp-cache
    prefix: git-objects/
    region: us-east-1
```

Environment variables: `GHP_CACHE_ENABLED`, `GHP_CACHE_STORAGE`, `GHP_CACHE_DIRECTORY`, `GHP_CACHE_S3_BUCKET`, `GHP_CACHE_S3_PREFIX`, `GHP_CACHE_S3_REGION`

Hot-reloadable: `enabled`. Not hot-reloadable: `storage`, `directory`, `s3.*`.

## Implementation Plan (Phased)

### Phase 1: Protocol layer + local repo management
1. Add `gitprotocolio` dependency (zero transitive deps) or vendor the parsing code
2. Implement `internal/gitcache/storage.go` — `CacheStorageFactory` interface + filesystem implementation
3. Implement `internal/gitcache/repository.go` — managed bare repo: init, fetch via go-git, object/ref queries
4. Implement `internal/gitcache/protocol.go` — parse v2 requests, write v2 responses, capability advertisement
5. Implement `internal/gitcache/packserve.go` — pure Go pack generation using go-git plumbing
6. Unit tests with in-memory/temp-dir repos

### Phase 2: Data model + API
1. Database migration for `cached_repositories` (postgres + sqlite)
2. `CachedRepository` model + Store interface methods
3. SQLite + Postgres backend implementations (+ Vault if applicable)
4. Store contract tests
5. Admin API endpoints with handler tests

### Phase 3: HTTP handler + integration
1. `internal/gitcache/handler.go` — the `http.Handler` wiring protocol parsing to repo operations
2. Configuration additions (`cache.*` fields)
3. Intercept in scoped passthrough — route cache-enabled repos to git cache handler
4. Cache metrics (command counters, durations, decision pipeline stages)
5. Access log fields (`cache_state`, `cache_repo`) via new context slots
6. Integration tests

### Phase 4: Admin UI + docs
1. Web UI section for managing cached repositories
2. Documentation updates (configuration.md, how-it-works.md)
3. E2E test coverage

### Phase 5: S3 storage backend
1. Implement S3-backed `CacheStorageFactory` using go-git `Storer` interface
2. S3 configuration fields + environment variables
3. Integration tests against localstack/minio
4. (Future) Pre-generated clone packs in S3 for initial clone optimization

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| go-git `Fetch()` doesn't support all GitHub edge cases (LFS, shallow, partial clone) | Start with basic clone/fetch; LFS and partial clone are passthrough-only initially |
| Pure Go pack serving produces suboptimal delta compression vs C git | Acceptable — network savings from local serving outweigh compression delta |
| go-git protocol v2 server-side gaps | We handle protocol v2 ourselves via gitprotocolio; go-git is only used for object storage and enumeration |
| Large repos exhaust disk (filesystem backend) | S3 backend avoids this; filesystem backend is operator responsibility; can add eviction later |
| Concurrent fetch storms (many clients trigger fetchUpstream simultaneously) | Goblet uses a mutex per repo — same pattern. Only one fetch runs at a time per cached repo. |
| S3 latency for object reads during pack generation | S3 reads are typically 5-50ms per object; for large packs, use packfile index to batch reads. Local filesystem is always faster for single-instance deployments. |
| Authorization bypass via crafted fetch-without-ls-refs | Explicitly rejected — fetch commands require a preceding successful ls-refs in the same request |

## Open Questions

1. **Shallow clone support.** Goblet's `infoRefsHandler` advertises `fetch=filter shallow`. Pure Go pack serving may not support shallow boundaries initially. Fallback: passthrough to GitHub for shallow requests.

2. **go-git's `Fetch()` auth model.** go-git uses `transport.AuthMethod`. We'll need an adapter that converts our resolved GitHub tokens into go-git's `http.BasicAuth` or `http.TokenAuth`. For async fetches, the app installation token from the registry is the right credential.

3. **Vendoring vs importing gitprotocolio.** It's archived but zero-dep and stable. Importing is simpler; vendoring gives us the option to fix bugs. Recommend importing initially — it's 500 lines total and unlikely to cause issues.

4. **Cache warming.** Should we pre-populate the cache when a repo is added to the cached list? Or lazy-populate on first request? Goblet lazy-populates (init bare repo on first request, fetch on first ls-refs). This is simpler and we should follow suit.
