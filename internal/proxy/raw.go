package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/token"
)

// rawPathRe matches raw.githubusercontent.com content paths and captures the
// owner and repository. The remainder is deliberately left unparsed: refs may
// contain slashes, and both /{owner}/{repo}/{ref}/{path} and the newer
// /{owner}/{repo}/refs/heads/{branch}/{path} form must yield the same
// owner/repo. Only the first two segments participate in enforcement.
var rawPathRe = regexp.MustCompile(`^/+([^/]+)/([^/]+)/(.+)$`)

// upstreamRaw is the canonical upstream URL used as the passthrough target.
var upstreamRaw = mustParseRawURL("https://raw.githubusercontent.com")

func mustParseRawURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// parseRawPath extracts the owner and repository from a raw content path.
// Owner and repo are lowercased: GitHub treats them case-insensitively, so
// leaving the client's casing intact would split Prometheus time series.
func parseRawPath(p string) (owner, repo string, ok bool) {
	m := rawPathRe.FindStringSubmatch(p)
	if m == nil {
		return "", "", false
	}
	return strings.ToLower(m[1]), strings.ToLower(m[2]), true
}

// newRawPassthrough builds a transparent reverse proxy to upstream
// raw.githubusercontent.com, preserving the client's Host header so tests and
// access logs see the value that was sent.
func newRawPassthrough(transport http.RoundTripper) http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host
			req.URL.Scheme = upstreamRaw.Scheme
			req.URL.Host = upstreamRaw.Host
			req.Host = originalHost
		},
	}
	if transport != nil {
		rp.Transport = transport
	}
	return rp
}

// NewRawHandler returns an http.Handler for raw.githubusercontent.com requests.
//
// Requests are classified into three paths, evaluated in order:
//
//   - A GHP-issued token (ghx_/gha_) in the Authorization header: the token is
//     resolved, contents:read is enforced against the repository allowlist, any
//     GitHub-issued ?token= is stripped, and the request is forwarded with the
//     real credential. This is the only enforced path.
//   - A GitHub-issued ?token= with no GHP token: forwarded unmodified when
//     raw.allow_query_token is true (the default), rejected with 403 otherwise.
//     GHP cannot attribute, scope-check, or revoke such tokens.
//   - Neither: forwarded anonymously. Anonymous requests cannot reach private
//     content — GitHub returns 404 without a credential — so blocking them buys
//     no confidentiality and breaks ordinary public-content tooling.
//
// This asymmetry is deliberate: GHP is an enforcement point for tokens it
// issued and a telemetry point for everything else.
//
// cfg is read on every request so SIGUSR1 hot-reload of raw.allow_query_token
// takes effect without a server restart. transport is optional; when nil the
// default RoundTripper is used.
func NewRawHandler(cfg *config.Config, enforcer ScopeEnforcer, resolver TokenResolver, ur *UsernameResolver, logger *slog.Logger, transport http.RoundTripper) http.Handler {
	passthrough := newRawPassthrough(transport)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner, repo, ok := parseRawPath(r.URL.Path)
		if !ok {
			// Not a content path. Forward and leave it to upstream; not
			// counted, so label cardinality stays bounded by real requests.
			passthrough.ServeHTTP(w, r)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_method").Inc()
			writeError(w, http.StatusForbidden, "Only GET and HEAD are permitted for raw content")
			return
		}

		clientTok, _, _ := extractClientToken(r)
		if clientTok != "" {
			serveRawAuthenticated(w, r, passthrough, enforcer, resolver, ur, logger, owner, repo, clientTok)
			return
		}

		if r.URL.Query().Get("token") != "" {
			if !cfg.RawAllowQueryToken() {
				metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_policy").Inc()
				writeError(w, http.StatusForbidden,
					"GitHub-issued query tokens are not permitted (raw.allow_query_token is disabled)")
				return
			}
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "query_token").Inc()
			SetRawAuth(r, "query_token")
			passthrough.ServeHTTP(w, r)
			return
		}

		metrics.RawRequestTotal.WithLabelValues(owner, repo, "anonymous").Inc()
		SetRawAuth(r, "anonymous")
		passthrough.ServeHTTP(w, r)
	})
}

// serveRawAuthenticated handles requests bearing a GHP-issued token. The
// token's repository allowlist and contents:read permission are enforced
// before the request is forwarded with the resolved GitHub credential.
//
// Any GitHub-issued ?token= is stripped before forwarding: carrying both a
// GHP-resolved credential and an independent GitHub capability would let the
// latter satisfy a request the former was denied.
func serveRawAuthenticated(w http.ResponseWriter, r *http.Request, passthrough http.Handler, enforcer ScopeEnforcer, resolver TokenResolver, ur *UsernameResolver, logger *slog.Logger, owner, repo, clientTok string) {
	decisionStart := time.Now()
	repoFull := owner + "/" + repo

	resolveTokenType := ""
	if tt, ok := token.TokenTypeFromPrefix(clientTok); ok {
		resolveTokenType = string(tt)
	}

	resolveStart := time.Now()
	pt, err := enforcer.Resolve(r.Context(), clientTok)
	metrics.ObserveDecision(metrics.StageTokenResolution, resolveTokenType, time.Since(resolveStart))
	if err != nil || pt == nil {
		if err != nil && logger != nil {
			logger.Warn("raw scope enforcement: token resolution failed", "error", err)
		}
		metrics.ObserveDecision(metrics.StageTotal, resolveTokenType, time.Since(decisionStart))
		writeError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	tokenType := pt.TokenType
	if pt.UserID != nil {
		SetUserID(r, *pt.UserID)
	}

	scopeParseStart := time.Now()
	si, err := parseScopeInfo(pt)
	metrics.ObserveDecision(metrics.StageScopeParsing, tokenType, time.Since(scopeParseStart))
	if err != nil {
		if logger != nil {
			logger.Error("raw scope enforcement: failed to parse token scope", "error", err)
		}
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if !si.isOpenScoped() {
		scopeEnforceStart := time.Now()
		if len(si.Repos) > 0 && !si.repoAllowed(repoFull) {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_scope").Inc()
			writeError(w, http.StatusForbidden, fmt.Sprintf("Token is not scoped to %s", repoFull))
			return
		}
		if len(si.Scopes) > 0 && !si.Scopes.HasPermission("contents", "read") {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_scope").Inc()
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token does not have permission for contents:read on %s", repoFull))
			return
		}
		metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
	}

	ghTokenStart := time.Now()
	realToken, err := resolver.ResolveToGitHubToken(r.Context(), clientTok)
	metrics.ObserveDecision(metrics.StageGitHubTokenResolution, tokenType, time.Since(ghTokenStart))
	if err != nil {
		if logger != nil {
			logger.Warn("raw scope enforcement: GitHub token resolution failed", "error", err)
		}
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
		writeError(w, http.StatusUnauthorized, "Token resolution failed")
		return
	}

	usernameStart := time.Now()
	if ur != nil {
		if u := ur.ResolveFromGitHubToken(r.Context(), realToken); u != "" {
			SetUsername(r, u)
		}
	}
	metrics.ObserveDecision(metrics.StageUsernameResolution, tokenType, time.Since(usernameStart))

	// Strip the GitHub-issued capability before forwarding our own credential.
	if q := r.URL.Query(); q.Get("token") != "" {
		q.Del("token")
		r.URL.RawQuery = q.Encode()
	}

	_, _, rewriteAuth := extractClientToken(r)
	if rewriteAuth != nil {
		r.Header.Set("Authorization", rewriteAuth(realToken))
	}

	metrics.RawRequestTotal.WithLabelValues(owner, repo, "authenticated").Inc()
	SetRawAuth(r, "proxy_token")
	metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))

	upstreamStart := time.Now()
	passthrough.ServeHTTP(w, r)
	metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, tokenType, time.Since(upstreamStart))
}
