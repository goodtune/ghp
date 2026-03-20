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
            → ls-refs command: proxy to GitHub, trigger async cache refresh
            → fetch command: check local objects → serve from cache or fetch-then-serve
```

The insertion point is **after** scope enforcement but **before** the upstream roundtrip. This ensures:
1. Token validation and scope checks still happen for every request
2. Only authorized, scope-allowed repos can be cached
3. The resolved GitHub credential is available for upstream requests
4. The cache layer is invisible to the auth pipeline

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

### Static config additions

```yaml
cache:
  enabled: true                    # master switch (hot-reloadable)
  directory: /var/cache/ghp/git    # local disk path for bare repos
```

Environment variables: `GHP_CACHE_ENABLED`, `GHP_CACHE_DIRECTORY`

Hot-reloadable: `enabled`. Not hot-reloadable: `directory`.

### Admin API endpoints

```
POST   /api/cached-repos          — Enable caching for a repository
GET    /api/cached-repos          — List cached repositories
GET    /api/cached-repos/{id}     — Get details
PATCH  /api/cached-repos/{id}     — Update (enable/disable)
DELETE /api/cached-repos/{id}     — Remove + purge local cache
```

### Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `ghp_cache_request_total` | Counter | `result` (hit/miss/bypass/error) |
| `ghp_cache_request_duration_seconds` | Histogram | `result` |
| `ghp_cache_fetch_upstream_duration_seconds` | Histogram | (none) |
| `ghp_proxy_decision_duration_seconds` | Histogram | stage=`cache_policy_check` |

Note: no `owner`/`repo` labels on counters — unbounded cardinality per CLAUDE.md guidelines.

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

## Implementation Plan (Phased)

### Phase 1: Protocol layer + local repo management
1. Add `gitprotocolio` dependency (zero transitive deps) or vendor the parsing code
2. Implement `internal/gitcache/repository.go` — bare repo init, fetch via go-git, object/ref queries
3. Implement `internal/gitcache/protocol.go` — parse v2 requests, write v2 responses, capability advertisement
4. Implement `internal/gitcache/packserve.go` — pure Go pack generation using go-git plumbing
5. Unit tests with in-memory/temp-dir repos

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
4. Decision pipeline metrics
5. Integration tests

### Phase 4: Admin UI + docs
1. Web UI section for managing cached repositories
2. Documentation updates (configuration.md, how-it-works.md)
3. E2E test coverage

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| go-git `Fetch()` doesn't support all GitHub edge cases (LFS, shallow, partial clone) | Start with basic clone/fetch; LFS and partial clone are passthrough-only initially |
| Pure Go pack serving produces suboptimal delta compression vs C git | Acceptable — network savings from local serving outweigh compression delta |
| go-git protocol v2 server-side gaps | We handle protocol v2 ourselves via gitprotocolio; go-git is only used for object storage and enumeration |
| Large repos exhaust disk | Operator responsibility initially; can add eviction later |
| Concurrent fetch storms (many clients trigger fetchUpstream simultaneously) | Goblet uses a mutex per repo — same pattern. Only one fetch runs at a time per cached repo. |

## Open Questions

1. **Shallow clone support.** Goblet's `infoRefsHandler` advertises `fetch=filter shallow`. Pure Go pack serving may not support shallow boundaries initially. Fallback: passthrough to GitHub for shallow requests.

2. **go-git's `Fetch()` auth model.** go-git uses `transport.AuthMethod`. We'll need an adapter that converts our resolved GitHub tokens into go-git's `http.BasicAuth` or `http.TokenAuth`. For async fetches, the app installation token from the registry is the right credential.

3. **Vendoring vs importing gitprotocolio.** It's archived but zero-dep and stable. Importing is simpler; vendoring gives us the option to fix bugs. Recommend importing initially — it's 500 lines total and unlikely to cause issues.

4. **Cache warming.** Should we pre-populate the cache when a repo is added to the cached list? Or lazy-populate on first request? Goblet lazy-populates (init bare repo on first request, fetch on first ls-refs). This is simpler and we should follow suit.
