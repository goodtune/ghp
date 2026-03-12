package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	// usernameCacheTTL is how long a GitHub username resolved from a raw token
	// is kept in the cache before being re-fetched.
	usernameCacheTTL = 24 * time.Hour

	// maxCachedUsernames is the upper bound on cached token-hash → username entries.
	maxCachedUsernames = 10_000
)

const (
	// defaultGraphQLURL is the GitHub GraphQL API endpoint.
	defaultGraphQLURL = "https://api.github.com/graphql"

	// viewerQuery is the GraphQL query used to resolve the authenticated
	// user's login. It works for both human users and bot accounts.
	viewerQuery = `{"query":"query UserCurrent{viewer{login}}"}`
)

// UsernameResolver resolves GitHub usernames from proxy token user IDs (via
// the database) and from raw GitHub tokens (via the GitHub GraphQL API).
// Results are kept in a long-lived in-memory cache keyed by a one-way SHA-256
// hash of the token so the actual credential is never stored.
type UsernameResolver struct {
	store      database.Store
	cache      *expirable.LRU[string, string]
	logger     *slog.Logger
	inflight   sync.Map   // tracks in-progress lookups to prevent duplicate goroutines
	graphqlURL string     // GraphQL endpoint URL (overridable for tests)
	httpClient *http.Client // HTTP client for GraphQL requests
}

// NewUsernameResolver creates a resolver backed by store for database lookups
// and an LRU cache for GitHub GraphQL API lookups. Optional functional options
// (e.g. WithGraphQLURL) may be applied for customisation.
func NewUsernameResolver(store database.Store, logger *slog.Logger, opts ...func(*UsernameResolver)) *UsernameResolver {
	r := &UsernameResolver{
		store:      store,
		cache:      expirable.NewLRU[string, string](maxCachedUsernames, nil, usernameCacheTTL),
		logger:     logger,
		graphqlURL: defaultGraphQLURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// WithGraphQLURL returns an option that overrides the GitHub GraphQL endpoint
// URL. This is primarily intended for testing with mock servers.
func WithGraphQLURL(url string) func(*UsernameResolver) {
	return func(u *UsernameResolver) {
		u.graphqlURL = url
	}
}

// GitHubTokenResolver resolves a proxy token database record to the underlying
// plaintext GitHub credential. This interface is satisfied by ProxyTokenResolver
// and enables cache warming without depending on the full proxy handler.
type GitHubTokenResolver interface {
	ResolveProxyTokenToGitHub(ctx context.Context, pt *database.ProxyToken) (string, error)
}

// WarmCache loads all unexpired, non-revoked proxy tokens from the database,
// resolves each to its underlying GitHub credential, and triggers an async
// GraphQL viewer lookup to populate the username cache. This runs in a
// background goroutine so server startup is not blocked.
// It is safe to call with a nil resolver or on a resolver with no store —
// in those cases the warm is silently skipped.
// ctx is threaded into the warm goroutine so it is cancelled when the caller
// (e.g. Server.Run) shuts down or returns early due to a startup failure.
func (u *UsernameResolver) WarmCache(ctx context.Context, resolver GitHubTokenResolver) {
	if u == nil || resolver == nil || u.store == nil {
		return
	}
	go u.warmCacheSync(ctx, resolver)
}

// warmCacheMaxConcurrent is the maximum number of simultaneous GraphQL viewer
// requests issued during a cache warm. This prevents a startup burst of
// goroutines/HTTP connections on instances with many active tokens.
const warmCacheMaxConcurrent = 5

func (u *UsernameResolver) warmCacheSync(parentCtx context.Context, resolver GitHubTokenResolver) {
	ctx, cancel := context.WithTimeout(parentCtx, 60*time.Second)
	defer cancel()

	tokens, err := u.store.ListActiveProxyTokens(ctx)
	if err != nil {
		if u.logger != nil {
			u.logger.Error("username cache warm: failed to list tokens", "error", err)
		}
		return
	}

	sem := make(chan struct{}, warmCacheMaxConcurrent)
	var wg sync.WaitGroup

	// seen tracks token hashes already queued in this warm pass so that
	// multiple proxy tokens backed by the same GitHub credential don't
	// trigger redundant concurrent GraphQL lookups.
	seen := make(map[string]struct{})
	var seenMu sync.Mutex

	var queued int
	for _, pt := range tokens {
		// Stop queuing work if the warm-cache context has expired (e.g.
		// server shutdown or the 60s budget elapsed).
		if err := ctx.Err(); err != nil {
			if u.logger != nil {
				u.logger.Debug("username cache warm: context cancelled, stopping early",
					"queued", queued, "error", err)
			}
			break
		}
		// Acquire the semaphore before resolving the GitHub token so that
		// installation-token minting (required for gha_ agent tokens) is also
		// bounded by the same concurrency limit as the GraphQL viewer lookups.
		sem <- struct{}{}
		wg.Add(1)
		queued++
		pt := pt
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			ghToken, err := resolver.ResolveProxyTokenToGitHub(ctx, pt)
			if err != nil {
				if u.logger != nil {
					u.logger.Debug("username cache warm: skipping token",
						"token_id", pt.ID, "error", err)
				}
				return
			}
			if !isResolvableGitHubToken(ghToken) {
				return
			}
			key := hashToken(ghToken)

			if _, ok := u.cache.Get(key); ok {
				// Already cached from a previous warm or request — skip.
				return
			}

			// Avoid duplicate GraphQL lookups for the same underlying GitHub
			// credential within this warm pass.
			seenMu.Lock()
			if _, ok := seen[key]; ok {
				seenMu.Unlock()
				return
			}
			seen[key] = struct{}{}
			seenMu.Unlock()

			// Use the same inflight guard as ResolveFromGitHubToken so that
			// warm-up and request-driven resolution for the same token hash
			// deduplicate consistently and avoid redundant GraphQL calls when
			// real traffic overlaps with the warm-up pass.
			if _, loaded := u.inflight.LoadOrStore(key, struct{}{}); loaded {
				return
			}
			defer u.inflight.Delete(key)
			u.resolveAndCacheGitHubUsername(ctx, key, ghToken)
		}()
	}
	wg.Wait()

	if u.logger != nil {
		u.logger.Info("username cache warmed", "tokens", queued)
	}
}

// ResolveFromUserID looks up the GitHub username for an internal user ID via
// the database. Returns "" if the user cannot be found.
func (u *UsernameResolver) ResolveFromUserID(ctx context.Context, userID string) string {
	if userID == "" {
		return ""
	}
	user, err := u.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return ""
	}
	return user.GitHubUsername
}

// ResolveFromGitHubToken determines the GitHub username that owns the given
// raw GitHub token (e.g. gho_, ghp_, ghu_, ghs_ prefixed). The result is cached
// with a SHA-256 hash of the token as key. On a cache miss the lookup is
// performed asynchronously so GitHub API latency does not block the caller;
// empty string is returned for that first request. Only one in-flight lookup
// is allowed per token to prevent goroutine storms under load. On any error
// the empty string is returned silently so callers can treat this as
// best-effort.
func (u *UsernameResolver) ResolveFromGitHubToken(ctx context.Context, rawToken string) string {
	if rawToken == "" || !isResolvableGitHubToken(rawToken) {
		return ""
	}

	key := hashToken(rawToken)
	if username, ok := u.cache.Get(key); ok {
		return username
	}

	// Guard against unbounded goroutine spawning: only one in-flight lookup
	// is allowed per token hash at a time.
	if _, loaded := u.inflight.LoadOrStore(key, struct{}{}); loaded {
		return ""
	}

	// Cache miss: resolve the username asynchronously so that GitHub API
	// latency does not impact the current request. The eventual result will be
	// stored in the cache for future calls. Use a fresh background context so
	// the lookup is not cancelled when the triggering request context ends.
	go func() {
		defer u.inflight.Delete(key)
		u.resolveAndCacheGitHubUsername(context.Background(), key, rawToken)
	}()

	// Best-effort: if the username is not yet cached, return empty string.
	return ""
}

// CheckCache returns the cached GitHub username for the given raw token without
// triggering a background lookup. Returns "" if the token is not yet cached.
// Use this after an upstream roundtrip to pick up usernames that an in-flight
// async lookup (started earlier in the same request) may have resolved by then.
func (u *UsernameResolver) CheckCache(rawToken string) string {
	if rawToken == "" {
		return ""
	}
	key := hashToken(rawToken)
	if username, ok := u.cache.Get(key); ok {
		return username
	}
	return ""
}

// graphQLError represents a single error entry in a GraphQL error response.
type graphQLError struct {
	Message string `json:"message"`
}

// graphQLResponse is the minimal structure for parsing the viewer login from
// a GraphQL response. GitHub GraphQL returns HTTP 200 even for auth/rate-limit
// failures, signalling them via a top-level "errors" array instead of a
// non-200 status code.
type graphQLResponse struct {
	Data struct {
		Viewer struct {
			Login string `json:"login"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []graphQLError `json:"errors"`
}

// resolveAndCacheGitHubUsername queries the GitHub GraphQL API to resolve the
// authenticated identity (user or bot) for the given token and stores the
// result in the cache. It is intended to be called from a goroutine so that
// GitHub API latency does not impact the request that triggered the lookup.
// parentCtx provides a deadline ceiling (e.g. the warm-cache 60s budget);
// a 5s per-lookup timeout is derived from it so the lookup is bounded both
// individually and within the overall warm-pass budget.
func (u *UsernameResolver) resolveAndCacheGitHubUsername(parentCtx context.Context, key, rawToken string) {
	// Derive a per-lookup timeout from the parent context. Using the parent
	// as the base means the warm-cache 60s deadline is inherited: if the
	// overall budget expires the child context (and in-flight HTTP request)
	// is cancelled automatically, while each individual lookup is still
	// bounded to at most 5s even when the parent has a longer deadline.
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.graphqlURL, bytes.NewBufferString(viewerQuery))
	if err != nil {
		if u.logger != nil {
			u.logger.Debug("github username lookup: failed to create request", "error", err)
		}
		return
	}
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		if u.logger != nil {
			u.logger.Debug("github username lookup failed", "error", err)
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1 MB
	if err != nil {
		if u.logger != nil {
			u.logger.Debug("github username lookup: failed to read response", "error", err)
		}
		return
	}

	if resp.StatusCode != http.StatusOK {
		if u.logger != nil {
			u.logger.Debug("github username lookup: non-200 response", "status", resp.StatusCode)
		}
		return
	}

	var result graphQLResponse
	if err := json.Unmarshal(body, &result); err != nil {
		if u.logger != nil {
			u.logger.Debug("github username lookup: failed to parse response", "error", err)
		}
		return
	}

	// GitHub GraphQL returns HTTP 200 even for auth/rate-limit/abuse failures,
	// signalling them via a top-level "errors" array. Treat any errors entry as
	// a failed lookup so we don't cache an empty username and retry on every call.
	if len(result.Errors) > 0 {
		if u.logger != nil {
			u.logger.Debug("github username lookup: graphql error", "message", result.Errors[0].Message)
		}
		return
	}

	username := result.Data.Viewer.Login
	if username == "" {
		if u.logger != nil {
			u.logger.Debug("github username lookup: empty login in response")
		}
		return
	}
	u.cache.Add(key, username)
}

// hashToken returns a hex-encoded SHA-256 digest of the token. This is used
// as the cache key so the actual token value is never stored.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// extractRawGitHubToken pulls a raw GitHub token from the Authorization header
// of a request. It recognises Bearer/token schemes and Basic auth with any
// username (e.g. the actual GitHub login or "x-access-token"), extracting the
// password field when it is a resolvable GitHub token. Only tokens with a
// resolvable GitHub prefix (gho_, ghp_, ghu_, ghs_) are returned; all other
// values yield "".
func extractRawGitHubToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	scheme := strings.ToLower(parts[0])
	credential := parts[1]

	switch scheme {
	case "bearer", "token":
		if isResolvableGitHubToken(credential) {
			return credential
		}
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return ""
		}
		_, pass, ok := strings.Cut(string(decoded), ":")
		if ok && isResolvableGitHubToken(pass) {
			return pass
		}
	}
	return ""
}

// nativeGitHubTokenPrefixes lists the token prefixes for native GitHub
// credentials whose identity can be resolved via the GitHub API. This
// includes human user tokens (gho_, ghp_, ghu_) and GitHub App
// installation tokens (ghs_) which identify bot accounts.
var nativeGitHubTokenPrefixes = []string{"gho_", "ghp_", "ghu_", "ghs_"}

// isResolvableGitHubToken returns true for tokens with prefixes whose
// identity can be resolved via the GitHub GraphQL viewer query.
func isResolvableGitHubToken(t string) bool {
	for _, prefix := range nativeGitHubTokenPrefixes {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

// passthroughTokenType returns the token type prefix (without the trailing
// underscore) for native GitHub tokens. For example, "gho_abc" returns "gho".
// Returns "unknown" if the token does not match any known prefix.
func passthroughTokenType(rawToken string) string {
	for _, prefix := range nativeGitHubTokenPrefixes {
		if strings.HasPrefix(rawToken, prefix) {
			return strings.TrimSuffix(prefix, "_")
		}
	}
	return "unknown"
}
