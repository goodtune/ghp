package gitcache

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/proxy"
)

// CacheLookup checks whether a git smart HTTP request targets a
// cache-enabled repository and routes it to the cache handler if so.
// Non-git paths and uncached repos pass through to the inner handler.
type CacheLookup struct {
	inner   http.Handler
	cache   *Handler
	store   database.Store
	logger  *slog.Logger
}

// NewCacheLookup creates a middleware that intercepts git smart HTTP requests
// for cache-enabled repositories.
func NewCacheLookup(inner http.Handler, cache *Handler, store database.Store, logger *slog.Logger) http.Handler {
	return &CacheLookup{
		inner:  inner,
		cache:  cache,
		store:  store,
		logger: logger,
	}
}

// ServeHTTP checks if the request targets a cached repository's git
// endpoints and routes accordingly.
func (cl *CacheLookup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rawOwner, rawRepo, gitPath := parseGitPath(r.URL.Path)
	if rawOwner == "" || rawRepo == "" || gitPath == "" {
		cl.inner.ServeHTTP(w, r)
		return
	}

	// Normalize to lowercase for case-insensitive matching (GitHub is case-insensitive).
	owner := strings.ToLower(rawOwner)
	repo := strings.ToLower(rawRepo)

	// Check if this repository has caching enabled.
	// NOTE: This deliberately queries the database on every request rather than
	// using an in-memory cache. The cache-enabled repo set is small (admin-configured),
	// the lookup is indexed, and the StageCacheLookup metric provides latency visibility.
	// An in-memory TTL cache would add invalidation complexity without meaningful benefit
	// at current traffic levels. Revisit if monitoring shows this becomes a bottleneck.
	lookupStart := time.Now()
	cached, err := cl.store.GetCachedRepositoryByOwnerName(r.Context(), owner, repo)
	if err != nil {
		metrics.ObserveDecision(metrics.StageCacheLookup, "", time.Since(lookupStart))
		cl.logger.Error("cache lookup failed", "error", err, "owner", owner, "repo", repo)
		cl.inner.ServeHTTP(w, r)
		return
	}
	if cached == nil {
		metrics.ObserveDecision(metrics.StageCacheLookup, "", time.Since(lookupStart))
		metrics.CacheRequestTotal.WithLabelValues(owner, repo, "nocache").Inc()
		cl.inner.ServeHTTP(w, r)
		return
	}
	if !cached.Enabled {
		metrics.ObserveDecision(metrics.StageCacheLookup, "", time.Since(lookupStart))
		metrics.CacheRequestTotal.WithLabelValues(owner, repo, "bypass").Inc()
		cl.inner.ServeHTTP(w, r)
		return
	}
	metrics.ObserveDecision(metrics.StageCacheLookup, "", time.Since(lookupStart))

	// Set access log context for cache tracking.
	proxy.SetCacheRepo(r, owner+"/"+repo)

	// Emit per-repo cache metric after the handler sets cache_state.
	defer func() {
		result := proxy.GetCacheState(r)
		if result == "" {
			result = "hit" // info/refs and other synthetic responses
		}
		metrics.CacheRequestTotal.WithLabelValues(owner, repo, result).Inc()
	}()

	switch {
	case gitPath == "info/refs" && r.Method == "GET":
		// Only intercept protocol v2 upload-pack discovery requests;
		// v1/dumb HTTP passes through to GitHub unchanged.
		if r.URL.Query().Get("service") == "git-upload-pack" && r.Header.Get("Git-Protocol") == "version=2" {
			proxy.SetCacheState(r, "hit")
			cl.cache.ServeInfoRefs(w, r)
		} else {
			cl.inner.ServeHTTP(w, r)
		}

	case gitPath == "git-upload-pack" && r.Method == "POST":
		// Only intercept protocol v2 upload-pack requests.
		if r.Header.Get("Git-Protocol") == "version=2" {
			cl.cache.ServeUploadPack(w, r, owner, repo)
			// CacheState is set by the handler based on hit/miss/error
		} else {
			cl.inner.ServeHTTP(w, r)
		}

	default:
		// Other git paths (e.g. git-receive-pack) pass through.
		cl.inner.ServeHTTP(w, r)
	}
}

// parseGitPath extracts owner, repo, and the git endpoint path from a URL
// path like /owner/repo.git/info/refs or /owner/repo.git/git-upload-pack.
// Returns empty strings if the path doesn't match a git smart HTTP pattern.
func parseGitPath(path string) (owner, repo, gitPath string) {
	// Trim leading slash.
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 3 {
		return "", "", ""
	}
	owner = parts[0]
	repoFull := parts[1]
	rest := parts[2]

	// Handle both /owner/repo.git/... and /owner/repo/...
	repo = strings.TrimSuffix(repoFull, ".git")

	// Match known git endpoints.
	switch {
	case rest == "info/refs":
		return owner, repo, "info/refs"
	case rest == "git-upload-pack":
		return owner, repo, "git-upload-pack"
	case rest == "git-receive-pack":
		return owner, repo, "git-receive-pack"
	default:
		return "", "", ""
	}
}

// SyncCacheReposMetric queries the store and updates the CacheReposActive gauge.
func SyncCacheReposMetric(ctx context.Context, store database.Store) {
	repos, err := store.ListCachedRepositories(ctx)
	if err != nil {
		return
	}
	count := 0
	for _, r := range repos {
		if r.Enabled {
			count++
		}
	}
	metrics.CacheReposActive.Set(float64(count))
}
