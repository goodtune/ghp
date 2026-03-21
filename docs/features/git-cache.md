# Git Cache

The git cache feature stores frequently-cloned repository data locally, serving
subsequent `git clone` and `git fetch` requests from cache rather than
forwarding every request to GitHub. This reduces load on GitHub, improves clone
performance for agents, and decreases egress bandwidth.

## How It Works

The cache operates at the Git smart HTTP protocol level (protocol v2):

1. **`ls-refs` is always forwarded to GitHub.** This serves as the access
   verification gate — GitHub checks the user's token and returns the
   repository's current refs. If GitHub rejects the request, no cached data is
   exposed.

2. **`fetch` is served from cache when possible.** If all requested objects
   (wants) are present in the local cache, the packfile is generated locally
   using pure Go (no `git` binary required). On a cache miss, GHP fetches
   from upstream using the per-request credential and then serves from cache.
   When a GitHub App service token is configured, async cache warming keeps
   the cache hot so most requests are served as hits.

3. **Async cache warming.** When `ls-refs` detects that upstream refs have
   changed since the last fetch, a background goroutine fetches the latest
   objects so subsequent requests benefit from the cache.

This design ensures that **GitHub's access control is always enforced** — a
user who cannot access a repository via GitHub will never receive cached data.

## Enabling the Cache

### 1. Enable in configuration

```yaml
cache:
  enabled: true
  storage_path: "/var/lib/ghp/cache"  # path for cached bare repos
```

Or via environment variables:

```bash
export GHP_CACHE_ENABLED=true
export GHP_CACHE_STORAGE_PATH=/var/lib/ghp/cache
```

### 2. Add repositories to cache

Use the admin UI or API to specify which repositories should be cached.
Repositories not listed pass through to GitHub as normal.

**Admin UI:** Navigate to the admin panel and use the "Cached Repositories"
section to add repositories by owner and name.

**API:**

```bash
# Add a repository to the cache list
curl -X POST https://ghp.example.com/api/cached-repos \
  -H "Authorization: Bearer ghpr_..." \
  -H "Content-Type: application/json" \
  -d '{"owner": "myorg", "name": "myrepo"}'

# List cached repositories
curl https://ghp.example.com/api/cached-repos \
  -H "Authorization: Bearer ghpr_..."

# Disable caching for a repository (keeps the record)
curl -X PATCH https://ghp.example.com/api/cached-repos/{id} \
  -H "Authorization: Bearer ghpr_..." \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Remove a repository from the cache list
curl -X DELETE https://ghp.example.com/api/cached-repos/{id} \
  -H "Authorization: Bearer ghpr_..."
```

## Metrics

The cache exposes Prometheus metrics at the `/metrics` endpoint:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ghp_cache_fetch_total` | Counter | `result` | Git fetch requests by result (`hit`, `miss`, `rejected`, `error`) |
| `ghp_cache_lsrefs_total` | Counter | — | ls-refs commands forwarded to upstream |
| `ghp_cache_warm_total` | Counter | `result` | Cache warming operations by result (`success`, `error`) |
| `ghp_cache_repos_active` | Gauge | — | Number of repositories with caching enabled |
| `ghp_cache_request_total` | Counter | `owner`, `repo`, `result` | Per-repository git requests with cache outcome |

The `ghp_proxy_decision_duration_seconds` histogram includes a `cache_lookup`
stage measuring the time spent checking whether a request targets a cached
repository.

### Identifying cache candidates

The `ghp_cache_request_total` metric tracks every git smart HTTP request with
per-repository labels and a `result` indicating the cache outcome: `hit`,
`miss`, `nocache` (not configured), `bypass` (configured but disabled),
`error`, `rejected`, or `passthrough`.

Use these queries to find repositories that would benefit from caching:

```promql
# Top uncached repos by request volume
topk(10, sum by (owner, repo) (ghp_cache_request_total{result="nocache"}))

# Cache hit rate per repo
sum by (owner, repo) (ghp_cache_request_total{result="hit"})
/ sum by (owner, repo) (ghp_cache_request_total)
```

See [Monitoring](../admin/monitoring.md#identifying-cache-candidates) for the
full set of example queries.

## Access Logs

When the cache feature is active, two additional fields appear in access log
entries:

- `cache_state` — the cache result for the request: `hit`, `miss`, `rejected`,
  `error`, `passthrough`, or empty for non-cached requests
- `cache_repo` — the `owner/repo` identifier when the request targets a
  cache-enabled repository

## Security Model

The cache maintains GitHub's access control invariant:

- **ls-refs is the authorization gate.** Every session begins with an `ls-refs`
  command forwarded to GitHub using the user's own token. If GitHub returns an
  error (401, 403, 404), the session stops and no cached data is returned.

- **fetch requires prior ls-refs.** A `fetch` command without a preceding
  successful `ls-refs` in the same request is rejected with an error. This
  prevents clients from directly requesting cached objects without proving
  access.

- **Cached objects are content-addressed.** Git objects are immutable and
  identified by a content hash (SHA-1 by default, or SHA-256 in SHA-256-mode
  repositories). A cache hit serves the same bytes GitHub would return.

## Limitations

- **Protocol v2 only.** The cache requires Git protocol v2 (`Git-Protocol:
  version=2` header). Protocol v1 and dumb HTTP requests pass through to
  GitHub without caching.

- **Read-only operations.** Only `git-upload-pack` (clone/fetch) is cached.
  Push operations (`git-receive-pack`) always go directly to GitHub.

- **No push notification.** The cache relies on `ls-refs` to detect ref changes.
  If a push occurs between two fetch requests, the second fetch may trigger a
  cache miss and upstream fetch.

## S3 Storage Backend

For horizontally-scaled deployments, the cache can store objects in an
S3-compatible bucket instead of local filesystem:

```yaml
cache:
  enabled: true
  s3_bucket: "ghp-cache"
  s3_region: "us-east-1"
  # s3_endpoint: "https://minio.internal:9000"  # for non-AWS S3
```

When `s3_bucket` is set, `storage_path` is used as the key prefix within the
bucket. All ghp instances sharing the same bucket and prefix will share the
cache.

!!! note "S3 backend is planned"
    The S3 storage backend is under development. Currently only local
    filesystem storage is available.
