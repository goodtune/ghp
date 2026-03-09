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
// raw GitHub token (e.g. gho_, ghp_, ghu_ prefixed). The result is cached
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
	// stored in the cache for future calls.
	go func() {
		defer u.inflight.Delete(key)
		u.resolveAndCacheGitHubUsername(key, rawToken)
	}()

	// Best-effort: if the username is not yet cached, return empty string.
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
func (u *UsernameResolver) resolveAndCacheGitHubUsername(key, rawToken string) {
	// Use a bounded background context so the lookup is not tied to the
	// request lifetime, but also cannot hang indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	resp, err := u.httpClient.Do(req)
	if err != nil {
		if u.logger != nil {
			u.logger.Debug("github username lookup failed", "error", err)
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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
// of a request. It recognises Bearer/token schemes and Basic auth with the
// x-access-token username convention. Only tokens with a resolvable GitHub
// prefix (gho_, ghp_, ghu_, ghs_) are returned; all other values yield "".
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
		user, pass, ok := strings.Cut(string(decoded), ":")
		if ok && strings.EqualFold(user, "x-access-token") && isResolvableGitHubToken(pass) {
			return pass
		}
	}
	return ""
}

// isResolvableGitHubToken returns true for tokens with prefixes whose
// identity can be resolved via the GitHub GraphQL viewer query. This
// includes human user tokens (gho_, ghp_, ghu_) and GitHub App
// installation tokens (ghs_) which identify bot accounts.
func isResolvableGitHubToken(t string) bool {
	return strings.HasPrefix(t, "gho_") ||
		strings.HasPrefix(t, "ghp_") ||
		strings.HasPrefix(t, "ghu_") ||
		strings.HasPrefix(t, "ghs_")
}
