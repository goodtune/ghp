package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// TokenResolver resolves a ghp_ token to a real GitHub access token.
type TokenResolver interface {
	ResolveToGitHubToken(ctx context.Context, ghpToken string) (string, error)
}

// NewPassthroughHandler creates a transparent reverse proxy to the given
// upstream URL. If a ghp_ token is found in the Authorization header, it
// is resolved and replaced with the real GitHub credential.
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
				if ghpTok := extractGhpToken(req); ghpTok != "" {
					realToken, err := resolver.ResolveToGitHubToken(req.Context(), ghpTok)
					if err != nil {
						if logger != nil {
							logger.Warn("passthrough token resolution failed", "error", err)
						}
						req.Header.Del("Authorization")
						return
					}
					req.Header.Set("Authorization", "Bearer "+realToken)
				}
			}
		},
	}

	if transport != nil {
		proxy.Transport = transport
	}

	return proxy
}

// ScopeEnforcer resolves a ghp_ token string to the full ProxyToken record
// so that repository and permission scopes can be checked.
type ScopeEnforcer interface {
	Resolve(ctx context.Context, ghpToken string) (*database.ProxyToken, error)
}

// NewScopedPassthroughHandler wraps a passthrough reverse proxy with git smart
// HTTP scope enforcement. For requests carrying a ghp_ token that match a git
// smart HTTP path, the token's repository and permission scopes are verified
// before the request is forwarded. Non-git paths and non-ghp_ tokens pass
// through unchanged.
func NewScopedPassthroughHandler(inner http.Handler, enforcer ScopeEnforcer, resolver TokenResolver, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghpTok := extractGhpToken(r)
		if ghpTok == "" {
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
		pt, err := enforcer.Resolve(r.Context(), ghpTok)
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
		if !strings.EqualFold(repo, pt.Repository) {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token is scoped to %s, not %s", pt.Repository, repo))
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
				fmt.Sprintf("Token does not have permission for %s:%s on %s", permission, level, pt.Repository))
			return
		}

		// Scope checks passed — forward with resolved token.
		realToken, err := resolver.ResolveToGitHubToken(r.Context(), ghpTok)
		if err != nil {
			if logger != nil {
				logger.Warn("git scope enforcement: GitHub token resolution failed", "error", err)
			}
			writeError(w, http.StatusUnauthorized, "Token resolution failed")
			return
		}
		r.Header.Set("Authorization", "Bearer "+realToken)
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

// extractGhpToken checks for a ghp_ prefixed token in the Authorization header.
// Supports "Bearer ghp_xxx", "token ghp_xxx", and Basic auth with
// username "x-access-token" and a ghp_ password (as used by git credential helpers).
func extractGhpToken(r *http.Request) string {
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
	if (scheme == "token" || scheme == "bearer") && strings.HasPrefix(credential, token.Prefix) {
		return credential
	}
	if scheme == "basic" {
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return ""
		}
		user, pass, ok := strings.Cut(string(decoded), ":")
		if ok && strings.EqualFold(user, "x-access-token") && strings.HasPrefix(pass, token.Prefix) {
			return pass
		}
	}
	return ""
}
