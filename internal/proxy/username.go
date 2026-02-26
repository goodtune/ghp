package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	ghub "github.com/google/go-github/v68/github"
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

// UsernameResolver resolves GitHub usernames from proxy token user IDs (via
// the database) and from raw GitHub tokens (via the GitHub API). Results from
// the API are kept in a long-lived in-memory cache keyed by a one-way SHA-256
// hash of the token so the actual credential is never stored.
type UsernameResolver struct {
	store  database.Store
	cache  *expirable.LRU[string, string]
	logger *slog.Logger
}

// NewUsernameResolver creates a resolver backed by store for database lookups
// and an LRU cache for GitHub API lookups.
func NewUsernameResolver(store database.Store, logger *slog.Logger) *UsernameResolver {
	return &UsernameResolver{
		store:  store,
		cache:  expirable.NewLRU[string, string](maxCachedUsernames, nil, usernameCacheTTL),
		logger: logger,
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
// empty string is returned for that first request. On any error the empty
// string is returned silently so callers can treat this as best-effort.
func (u *UsernameResolver) ResolveFromGitHubToken(ctx context.Context, rawToken string) string {
	if rawToken == "" {
		return ""
	}

	key := hashToken(rawToken)
	if username, ok := u.cache.Get(key); ok {
		return username
	}

	// Cache miss: resolve the username asynchronously so that GitHub API
	// latency does not impact the current request. The eventual result will be
	// stored in the cache for future calls.
	go u.resolveAndCacheGitHubUsername(key, rawToken)

	// Best-effort: if the username is not yet cached, return empty string.
	return ""
}

// resolveAndCacheGitHubUsername performs the GitHub API call to resolve the
// username for the given token hash and stores it in the cache. It is intended
// to be called from a goroutine so that GitHub API latency does not impact
// the request that triggered the lookup.
func (u *UsernameResolver) resolveAndCacheGitHubUsername(key, rawToken string) {
	// Use a bounded background context so the lookup is not tied to the
	// request lifetime, but also cannot hang indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := ghub.NewClient(nil).WithAuthToken(rawToken)
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		if u.logger != nil {
			u.logger.Debug("github username lookup failed", "error", err)
		}
		return
	}

	username := user.GetLogin()
	if username != "" {
		u.cache.Add(key, username)
	}
}

// hashToken returns a hex-encoded SHA-256 digest of the token. This is used
// as the cache key so the actual token value is never stored.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// extractRawGitHubToken pulls a raw GitHub token from the Authorization header
// of a request. It recognises Bearer/token schemes and Basic auth with the
// x-access-token username convention. Only tokens with a known GitHub prefix
// (gho_, ghp_, ghu_) are returned; all other values yield "".
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
		if isGitHubUserToken(credential) {
			return credential
		}
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return ""
		}
		user, pass, ok := strings.Cut(string(decoded), ":")
		if ok && strings.EqualFold(user, "x-access-token") && isGitHubUserToken(pass) {
			return pass
		}
	}
	return ""
}

// isGitHubUserToken returns true for tokens with prefixes that identify a
// GitHub user (OAuth, personal access token, or user-to-server).
func isGitHubUserToken(t string) bool {
	return strings.HasPrefix(t, "gho_") ||
		strings.HasPrefix(t, "ghp_") ||
		strings.HasPrefix(t, "ghu_")
}
