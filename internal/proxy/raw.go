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

// rawQuerySegments splits a raw query string into its parameter segments,
// treating both "&" and ";" as separators.
//
// url.ParseQuery cannot be used for any security decision about this query:
// it silently discards any &-segment containing a ";", so "?x=1;token=SECRET"
// parses to an empty url.Values. Classifying or stripping on the parsed map
// would let a token smuggled behind a semicolon slip past both the
// raw.allow_query_token policy check and the strip on the authenticated path.
// Splitting the raw string ourselves sees every segment a permissive upstream
// parser might.
func rawQuerySegments(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	return strings.FieldsFunc(rawQuery, func(r rune) bool {
		return r == '&' || r == ';'
	})
}

// isRawTokenSegment reports whether a query segment names the "token"
// parameter. The comparison is case-insensitive because GitHub treats the
// parameter name that way; an exact-case check would let "?TOKEN=x" through.
func isRawTokenSegment(seg string) bool {
	key, _, _ := strings.Cut(seg, "=")
	// An unescape failure means the key is not a well-formed encoding of
	// "token", but compare the raw bytes anyway rather than skipping the
	// segment — deciding "not a token" from a parse error is how the
	// ParseQuery bypass happened in the first place.
	if unescaped, err := url.QueryUnescape(key); err == nil {
		key = unescaped
	}
	return strings.EqualFold(key, "token")
}

// rawQueryHasToken reports whether the raw query carries a "token" parameter.
func rawQueryHasToken(rawQuery string) bool {
	for _, seg := range rawQuerySegments(rawQuery) {
		if isRawTokenSegment(seg) {
			return true
		}
	}
	return false
}

// stripRawQueryToken removes every "token" parameter from a raw query,
// returning the remaining segments joined by "&".
//
// Segments are preserved verbatim rather than re-encoded, so unrelated
// parameters survive a query that url.ParseQuery cannot read. Semicolon
// separators are normalised to "&": that keeps what we forward unambiguous to
// upstream, which would otherwise be free to split the query differently than
// we did.
func stripRawQueryToken(rawQuery string) string {
	segs := rawQuerySegments(rawQuery)
	kept := make([]string, 0, len(segs))
	for _, seg := range segs {
		if !isRawTokenSegment(seg) {
			kept = append(kept, seg)
		}
	}
	return strings.Join(kept, "&")
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
		decisionStart := time.Now()

		owner, repo, ok := parseRawPath(r.URL.Path)
		if !ok {
			// Not a content path. Forward and leave it to upstream; not
			// counted, so label cardinality stays bounded by real requests.
			metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
			upstreamStart := time.Now()
			passthrough.ServeHTTP(w, r)
			metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, "unknown", time.Since(upstreamStart))
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_method").Inc()
			SetRawAuth(r, "denied_method")
			metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
			writeError(w, http.StatusForbidden, "Only GET and HEAD are permitted for raw content")
			return
		}

		extractStart := time.Now()
		clientTok, rawCredential, _ := extractClientToken(r)
		extractTokenType := ""
		if tt, ok := token.TokenTypeFromPrefix(clientTok); ok {
			extractTokenType = string(tt)
		}
		metrics.ObserveDecision(metrics.StageTokenExtraction, extractTokenType, time.Since(extractStart))
		if clientTok != "" {
			serveRawAuthenticated(w, r, passthrough, enforcer, resolver, ur, logger, owner, repo, clientTok, decisionStart)
			return
		}

		// The credential is not one GHP issued. Apply the token type border
		// policy before anything else forwards it: raw is exempt from GitHub's
		// sec-GitHub-allowed-enterprise restriction, so a blocked token type
		// reaches raw unless GHP stops it here.
		borderStart := time.Now()
		if cfg.IsTokenBlocked(rawCredential) {
			metrics.ObserveDecision(metrics.StageBorderPolicyCheck, "", time.Since(borderStart))
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_border").Inc()
			SetRawAuth(r, "denied_border")
			metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
			writeError(w, http.StatusForbidden, "Token type is not permitted by the border policy")
			return
		}
		metrics.ObserveDecision(metrics.StageBorderPolicyCheck, "", time.Since(borderStart))

		if rawQueryHasToken(r.URL.RawQuery) {
			if !cfg.RawAllowQueryToken() {
				metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_policy").Inc()
				SetRawAuth(r, "denied_policy")
				metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
				writeError(w, http.StatusForbidden,
					"GitHub-issued query tokens are not permitted (raw.allow_query_token is disabled)")
				return
			}
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "query_token").Inc()
			SetRawAuth(r, "query_token")
			metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
			upstreamStart := time.Now()
			passthrough.ServeHTTP(w, r)
			metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, "unknown", time.Since(upstreamStart))
			return
		}

		// A credential GHP cannot resolve — a classic PAT or installation token
		// — is forwarded intact, but it is a different event from a request
		// that carried nothing at all, and operators need the two apart.
		rawResult := "anonymous"
		if rawCredential != "" {
			rawResult = "foreign_credential"
		}
		metrics.RawRequestTotal.WithLabelValues(owner, repo, rawResult).Inc()
		SetRawAuth(r, rawResult)
		metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
		upstreamStart := time.Now()
		passthrough.ServeHTTP(w, r)
		metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, "unknown", time.Since(upstreamStart))
	})
}

// serveRawAuthenticated handles requests bearing a GHP-issued token. The
// token's repository allowlist and contents:read permission are enforced
// before the request is forwarded with the resolved GitHub credential.
//
// Any GitHub-issued ?token= is stripped before forwarding: carrying both a
// GHP-resolved credential and an independent GitHub capability would let the
// latter satisfy a request the former was denied.
//
// decisionStart is the caller's request-arrival timestamp, not a local one, so
// that the total stage covers the full pre-forward overhead — path parsing, the
// method check, and token extraction included — rather than only the work done
// here.
func serveRawAuthenticated(w http.ResponseWriter, r *http.Request, passthrough http.Handler, enforcer ScopeEnforcer, resolver TokenResolver, ur *UsernameResolver, logger *slog.Logger, owner, repo, clientTok string, decisionStart time.Time) {
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
		metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_token").Inc()
		SetRawAuth(r, "denied_token")
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
		metrics.RawRequestTotal.WithLabelValues(owner, repo, "error").Inc()
		SetRawAuth(r, "error")
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
			SetRawAuth(r, "denied_scope")
			writeError(w, http.StatusForbidden, fmt.Sprintf("Token is not scoped to %s", repoFull))
			return
		}
		if len(si.Scopes) > 0 && !si.Scopes.HasPermission("contents", "read") {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_scope").Inc()
			SetRawAuth(r, "denied_scope")
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
		metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_token").Inc()
		SetRawAuth(r, "denied_token")
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
	// stripRawQueryToken works on the raw string, so it also catches a token
	// smuggled behind a ";" and one spelled in a different case — neither of
	// which url.Values would remove.
	r.URL.RawQuery = stripRawQueryToken(r.URL.RawQuery)

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
