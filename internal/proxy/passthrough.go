package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// TokenResolver resolves a client token (ghx_/gha_) to a real GitHub access token.
type TokenResolver interface {
	ResolveToGitHubToken(ctx context.Context, clientToken string) (string, error)
}

// NewPassthroughHandler creates a transparent reverse proxy to the given
// upstream URL. If a client token (ghx_/gha_) is found in the Authorization
// header, it is resolved and replaced with the real GitHub credential.
// If enterpriseSlug is non-empty, the sec-GitHub-allowed-enterprise header
// is injected on every request.
// The transport parameter allows callers to supply a custom RoundTripper
// (e.g. for test TLS); pass nil to use http.DefaultTransport.
func NewPassthroughHandler(upstream string, resolver TokenResolver, enterpriseSlug string, logger *slog.Logger, transport http.RoundTripper) http.Handler {
	target, _ := url.Parse(upstream)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host

			if enterpriseSlug != "" {
				req.Header.Set("sec-GitHub-allowed-enterprise", enterpriseSlug)
			}

			if resolver != nil {
				if clientTok, rewriteAuth := extractClientToken(req); clientTok != "" {
					realToken, err := resolver.ResolveToGitHubToken(req.Context(), clientTok)
					if err != nil {
						if logger != nil {
							logger.Warn("passthrough token resolution failed", "error", err)
						}
						req.Header.Del("Authorization")
						return
					}
					req.Header.Set("Authorization", rewriteAuth(realToken))
				}
			}
		},
	}

	if transport != nil {
		proxy.Transport = transport
	}

	return proxy
}

// ScopeEnforcer resolves a client token string to the full ProxyToken record
// so that repository and permission scopes can be checked.
type ScopeEnforcer interface {
	Resolve(ctx context.Context, clientToken string) (*database.ProxyToken, error)
}

// NewScopedPassthroughHandler wraps a passthrough reverse proxy with git smart
// HTTP scope enforcement. For requests carrying a client token (ghx_/gha_) that
// match a git smart HTTP path, the token's repository and permission scopes are
// verified before the request is forwarded. Non-git paths and non-client tokens
// pass through unchanged.
func NewScopedPassthroughHandler(inner http.Handler, enforcer ScopeEnforcer, resolver TokenResolver, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientTok, rewriteAuth := extractClientToken(r)
		if clientTok == "" {
			inner.ServeHTTP(w, r)
			return
		}

		repo, permission, level := GitSmartHTTPScope(r.Method, r.URL.Path, r.URL.RawQuery)
		if permission == "" {
			// Not a git smart HTTP path — pass through with token resolution only.
			inner.ServeHTTP(w, r)
			return
		}

		// Resolve the full proxy token for scope checking.
		pt, err := enforcer.Resolve(r.Context(), clientTok)
		if err != nil {
			if logger != nil {
				logger.Warn("git scope enforcement: token resolution failed", "error", err)
			}
			writeError(w, http.StatusUnauthorized, "Invalid token")
			return
		}
		if pt == nil {
			writeError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		// Enforce repository scope.
		if !repositoryAllowed(repo, pt.Repositories) {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token is not scoped to %s", repo))
			return
		}

		// Enforce permission scope.
		scopes, err := database.ParseScopes(pt.Scopes)
		if err != nil {
			if logger != nil {
				logger.Error("git scope enforcement: failed to parse scopes", "error", err)
			}
			writeError(w, http.StatusInternalServerError, "Internal error")
			return
		}
		if !scopes.HasPermission(permission, level) {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token does not have permission for %s:%s on %s", permission, level, repo))
			return
		}

		// Scope checks passed — forward with resolved token.
		realToken, err := resolver.ResolveToGitHubToken(r.Context(), clientTok)
		if err != nil {
			if logger != nil {
				logger.Warn("git scope enforcement: GitHub token resolution failed", "error", err)
			}
			writeError(w, http.StatusUnauthorized, "Token resolution failed")
			return
		}
		r.Header.Set("Authorization", rewriteAuth(realToken))
		inner.ServeHTTP(w, r)
	})
}

// NewCopilotPassthroughHandler creates a transparent reverse proxy for
// *.githubcopilot.com traffic. The original Host header is preserved so the
// correct subdomain reaches the real Copilot service. No token interception
// is performed.
// The upstream parameter sets the network destination (scheme + host:port).
// The transport parameter allows callers to supply a custom RoundTripper;
// pass nil to use http.DefaultTransport.
func NewCopilotPassthroughHandler(upstream string, enterpriseSlug string, logger *slog.Logger, transport http.RoundTripper) http.Handler {
	target, _ := url.Parse(upstream)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = originalHost

			if enterpriseSlug != "" {
				req.Header.Set("sec-GitHub-allowed-enterprise", enterpriseSlug)
			}
		},
	}

	if transport != nil {
		proxy.Transport = transport
	}

	return proxy
}

// extractClientToken checks for a client token (ghx_/gha_) in the Authorization header.
// Supports "Bearer ghx_xxx", "token ghx_xxx", and Basic auth with
// username "x-access-token" and a client token password (as used by git credential helpers).
//
// Returns the plaintext client token and a rewrite function that builds a new
// Authorization header value preserving the original scheme.
func extractClientToken(r *http.Request) (string, func(realToken string) string) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", nil
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return "", nil
	}
	scheme := strings.ToLower(parts[0])
	originalScheme := parts[0] // preserve original casing
	credential := parts[1]
	if scheme == "token" || scheme == "bearer" {
		if _, ok := token.TokenTypeFromPrefix(credential); ok {
			return credential, func(realToken string) string {
				return originalScheme + " " + realToken
			}
		}
	}
	if scheme == "basic" {
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return "", nil
		}
		user, pass, ok := strings.Cut(string(decoded), ":")
		if ok && strings.EqualFold(user, "x-access-token") {
			if _, ok := token.TokenTypeFromPrefix(pass); ok {
				return pass, func(realToken string) string {
					return originalScheme + " " + base64.StdEncoding.EncodeToString([]byte(user+":"+realToken))
				}
			}
		}
	}
	return "", nil
}

// repositoryAllowed returns true if the given repo is in the JSON array of repositories.
func repositoryAllowed(repo string, reposJSON json.RawMessage) bool {
	var repos []string
	if err := json.Unmarshal(reposJSON, &repos); err != nil {
		return false
	}
	for _, r := range repos {
		if strings.EqualFold(r, repo) {
			return true
		}
	}
	return false
}
