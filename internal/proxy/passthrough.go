package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

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

// extractGhpToken checks for a ghp_ prefixed token in the Authorization header.
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
	tok := parts[1]
	if (scheme == "token" || scheme == "bearer") && strings.HasPrefix(tok, token.Prefix) {
		return tok
	}
	return ""
}
