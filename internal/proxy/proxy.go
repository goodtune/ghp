// Package proxy implements the core reverse proxy that sits between coding
// agents and GitHub. It is responsible for:
//
//   - Extracting ghx_/gha_ tokens from the Authorization header
//   - Resolving tokens to their database records and checking expiry/revocation
//   - Enforcing repository and permission scopes against the requested API path
//   - Swapping the ghp token for the real GitHub credential (decrypted or
//     obtained from the GitHub App installation token provider)
//   - Forwarding the request to the real GitHub API and streaming the response
//   - Emitting structured JSON audit log entries for API proxy requests and Prometheus metrics for all requests
//
// The proxy handles three distinct traffic patterns through separate handlers:
//
//   - Handler: the API proxy for api.github.com traffic (REST and GraphQL)
//   - ScopedPassthroughHandler: the github.com passthrough for git operations
//   - CopilotPassthroughHandler: transparent forwarding for *.githubcopilot.com
//
// Each stage of the request pipeline is individually timed and recorded in the
// ghp_proxy_decision_duration_seconds histogram, enabling operators to identify
// exactly where overhead is introduced.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/backend"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	ghub "github.com/goodtune/ghp/internal/github"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/token"
)

// maxGraphQLBodyBytes caps the size of GraphQL request bodies the proxy
// will read into memory for static analysis. GitHub itself accepts up to
// roughly a megabyte; rejecting anything larger keeps memory use bounded
// for adversarial clients.
const maxGraphQLBodyBytes = 1 << 20 // 1 MiB

const (
	githubAPIBase    = "https://api.github.com"
	githubTokenURL   = "https://github.com/login/oauth/access_token"
	tokenRefreshSkew = 5 * time.Minute
)

// AuditLogWriter is the interface used by the proxy handler to write
// structured JSON audit log entries.
type AuditLogWriter interface {
	WriteAuditEntry(entry AuditLogEntry)
}

// AuditLogEntry holds the fields for a structured JSON audit event.
type AuditLogEntry struct {
	Action     string
	UserID     string
	Username   string
	TokenID    string
	TokenType  string
	SessionID  string
	Method     string
	Path       string
	Repository string
	StatusCode int
	DurationMS int
}

// Handler is the reverse proxy HTTP handler.
type Handler struct {
	cfg              *config.Config
	tokenService     *token.Service
	store            database.Store
	encryptor        *crypto.Encryptor
	appTokenProvider AppTokenProvider // may be nil
	usernameResolver *UsernameResolver
	logger           *slog.Logger
	client           *http.Client
	auditLog         AuditLogWriter // may be nil
}

// SetAuditLogWriter sets the audit log writer for the handler.
func (h *Handler) SetAuditLogWriter(w AuditLogWriter) {
	h.auditLog = w
}

// NewHandler creates a new reverse proxy handler.
func NewHandler(cfg *config.Config, ts *token.Service, store database.Store, enc *crypto.Encryptor, atp AppTokenProvider, ur *UsernameResolver, logger *slog.Logger) *Handler {
	return &Handler{
		cfg:              cfg,
		tokenService:     ts,
		store:            store,
		encryptor:        enc,
		appTokenProvider: atp,
		usernameResolver: ur,
		logger:           logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// Do not follow redirects. GitHub endpoints (e.g. Actions
			// job logs) return 302 redirects to external blob storage.
			// Following these at the proxy level causes 502 errors when
			// the redirect target is unreachable from the proxy's
			// network. Instead, pass the redirect through so the client
			// can follow it directly.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ServeHTTP handles proxied requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Determine the actual API path.
	// Requests come in as /api/v3/... or /api/graphql (GHE-style),
	// or directly as /... or /graphql (when proxied as api.github.com virtualhost).
	apiPath := r.URL.Path
	if strings.HasPrefix(apiPath, "/api/v3") {
		apiPath = strings.TrimPrefix(apiPath, "/api/v3")
	}
	// Normalize GraphQL path before routing — both GHE-style /api/graphql
	// and direct /graphql resolve to /graphql for upstream GitHub.
	if apiPath == "/api/graphql" {
		apiPath = "/graphql"
	}
	if apiPath == "" {
		apiPath = "/"
	}

	// Extract the client token from the Authorization header.
	// If the token is not a client token (ghx_/gha_), check the border
	// policy and then forward the request transparently to GitHub.
	extractStart := time.Now()
	clientToken, rawCredential, rewriteAuth := extractClientToken(r)
	extractTokenType := ""
	if tt, ok := token.TokenTypeFromPrefix(clientToken); ok {
		extractTokenType = string(tt)
	}
	metrics.ObserveDecision(metrics.StageTokenExtraction, extractTokenType, time.Since(extractStart))
	if clientToken == "" {
		// Check the token type border policy before forwarding.
		borderStart := time.Now()
		// Anonymous git blocking: short-circuit requests that carry a Git-Protocol
		// header but no Authorization header before they egress to GitHub.
		if h.cfg.Block.AnonymousGit && rawCredential == "" && r.Header.Get("Git-Protocol") != "" {
			metrics.BlockAnonymousGitTotal.Inc()
			metrics.ObserveDecision(metrics.StageBorderPolicyCheck, "", time.Since(borderStart))
			metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(start))
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			writeError(w, http.StatusUnauthorized, "Anonymous git access is not permitted")
			return
		}
		if h.cfg.IsTokenBlocked(rawCredential) {
			metrics.ObserveDecision(metrics.StageBorderPolicyCheck, "", time.Since(borderStart))
			metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(start))
			writeError(w, http.StatusForbidden, "Token type is not permitted by the border policy")
			return
		}
		metrics.ObserveDecision(metrics.StageBorderPolicyCheck, "", time.Since(borderStart))
		metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(start))
		upstreamStart := time.Now()
		h.forwardPassthrough(w, r, apiPath, start)
		metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, "unknown", time.Since(upstreamStart))
		return
	}

	// Derive token type from prefix for pre-resolution metrics.
	resolveTokenType := ""
	if tt, ok := token.TokenTypeFromPrefix(clientToken); ok {
		resolveTokenType = string(tt)
	}

	// Resolve the client token.
	resolveStart := time.Now()
	pt, err := h.tokenService.Resolve(r.Context(), clientToken)
	metrics.ObserveDecision(metrics.StageTokenResolution, resolveTokenType, time.Since(resolveStart))
	if err != nil {
		h.logger.Warn("token resolution failed", "error", err)
		metrics.ObserveDecision(metrics.StageTotal, resolveTokenType, time.Since(start))
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if pt == nil {
		metrics.ObserveDecision(metrics.StageTotal, resolveTokenType, time.Since(start))
		writeError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	tokenType := pt.TokenType

	// Inject the token creator's user ID into the request context for auditing.
	// Username resolution happens later, after the real GitHub token is obtained,
	// by querying the GraphQL viewer endpoint — this gives the actual identity
	// behind the credential (bot account for gha_ tokens, human for ghx_ tokens).
	if pt.UserID != nil {
		SetUserID(r, *pt.UserID)
	}

	// Parse the token's scope restrictions once; fail-closed on corrupt JSON.
	// Must happen before GraphQL routing so that corrupt JSON is never treated
	// as open-scoped, even on the GraphQL path.
	scopeParseStart := time.Now()
	si, err := parseScopeInfo(pt)
	metrics.ObserveDecision(metrics.StageScopeParsing, tokenType, time.Since(scopeParseStart))
	if err != nil {
		h.logger.Error("failed to parse token scope", "error", err)
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// GraphQL handled separately.
	if apiPath == "/graphql" {
		h.handleGraphQL(w, r, pt, si, rewriteAuth, start)
		return
	}

	// Open-scoped tokens (no repos AND no scopes) skip all filtering — forward directly to GitHub.
	if si.isOpenScoped() {
		ghTokenStart := time.Now()
		githubToken, err := h.getGitHubToken(r, pt, &si)
		metrics.ObserveDecision(metrics.StageGitHubTokenResolution, tokenType, time.Since(ghTokenStart))
		if err != nil {
			h.logger.Error("failed to get GitHub token", "error", err)
			status, msg := installationTokenErrorResponse(err)
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
			writeError(w, status, msg)
			return
		}
		usernameStart := time.Now()
		h.resolveTokenUsername(r, githubToken)
		metrics.ObserveDecision(metrics.StageUsernameResolution, tokenType, time.Since(usernameStart))
		repo := ExtractRepoFromPath(apiPath)
		authHeader := rewriteAuth(githubToken)
		// Record total decision time (everything before forwarding to GitHub).
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		upstreamStart := time.Now()
		status := h.forwardRequest(w, r, apiPath, authHeader)
		metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, tokenType, time.Since(upstreamStart))
		// Re-check the cache after the roundtrip; the async lookup triggered
		// by resolveTokenUsername may have completed during the upstream wait.
		h.checkCacheAfterRoundtrip(r, githubToken, pt)
		h.logRequest(pt, r, apiPath, repo, status, time.Since(start), "proxy_request")
		return
	}

	// Extract repository from path (if this is a /repos/ path).
	repo := ExtractRepoFromPath(apiPath)

	// Enforce repository scope only when the token has repo restrictions.
	// A token with repos=null carries no repo restriction (applies to any repo).
	scopeEnforceStart := time.Now()
	if repo != "" && len(si.Repos) > 0 && !si.repoAllowed(repo) {
		metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("Token is not scoped to %s", repo))
		h.logRequest(pt, r, apiPath, repo, http.StatusForbidden, time.Since(start), "proxy_scope_denied")
		return
	}

	// Enforce permission scope only when the token has scope restrictions.
	// Unrecognized endpoints are forwarded — GitHub's token handles access.
	// A token with scopes=null carries no permission restriction (any endpoint allowed).
	permission, level := EndpointScope(r.Method, apiPath)
	if permission != "" && permission != "metadata" && len(si.Scopes) > 0 {
		if !si.Scopes.HasPermission(permission, level) {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token does not have permission for %s:%s on %s", permission, level, repo))
			h.logRequest(pt, r, apiPath, repo, http.StatusForbidden, time.Since(start), "proxy_scope_denied")
			return
		}
	}
	metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))

	// Get the real GitHub access token.
	ghTokenStart := time.Now()
	githubToken, err := h.getGitHubToken(r, pt, &si)
	metrics.ObserveDecision(metrics.StageGitHubTokenResolution, tokenType, time.Since(ghTokenStart))
	if err != nil {
		h.logger.Error("failed to get GitHub token", "error", err)
		status, msg := installationTokenErrorResponse(err)
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		writeError(w, status, msg)
		return
	}

	usernameStart := time.Now()
	h.resolveTokenUsername(r, githubToken)
	metrics.ObserveDecision(metrics.StageUsernameResolution, tokenType, time.Since(usernameStart))

	// For the root endpoint, synthesize X-OAuth-Scopes from the token's
	// permission scopes so that tools like "gh auth status" see the token's
	// actual capabilities rather than the underlying credential's OAuth scopes.
	// (GitHub App installation tokens don't carry X-OAuth-Scopes at all.)
	var scopeOverride map[string]string
	if apiPath == "/" && len(si.Scopes) > 0 {
		scopeOverride = map[string]string{
			"X-OAuth-Scopes": syntheticOAuthScopes(si.Scopes),
		}
	}

	// Prepare the Authorization header for the upstream request.
	authHeader := rewriteAuth(githubToken)

	// Record total decision time (everything before forwarding to GitHub).
	metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))

	// Forward the request to GitHub.
	upstreamStart := time.Now()
	status := h.forwardRequest(w, r, apiPath, authHeader, scopeOverride)
	metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, tokenType, time.Since(upstreamStart))

	// Re-check the cache after the roundtrip; the async lookup triggered
	// by resolveTokenUsername may have completed during the upstream wait.
	h.checkCacheAfterRoundtrip(r, githubToken, pt)

	h.logRequest(pt, r, apiPath, repo, status, time.Since(start), "proxy_request")
}

func (h *Handler) handleGraphQL(w http.ResponseWriter, r *http.Request, pt *database.ProxyToken, si tokenScopeInfo, rewriteAuth func(string) string, start time.Time) {
	tokenType := pt.TokenType

	// Open-scoped tokens skip GraphQL static analysis entirely and forward
	// to GitHub unchanged. The underlying credential's own permissions act
	// as the only enforcement layer. Emit zero-duration GraphQL-analysis
	// and scope-enforcement decisions so the per-request stage timeline
	// is uniform across paths.
	if si.isOpenScoped() {
		metrics.ObserveDecision(metrics.StageGraphQLAnalysis, tokenType, 0)
		metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, 0)
		h.forwardGraphQL(w, r, pt, &si, rewriteAuth, start, nil)
		return
	}

	// Buffer the request body so we can both analyse the query and replay
	// it to GitHub. MaxBytesReader caps the read so unbounded uploads are
	// rejected before any allocation. Close the original body once it is
	// drained so the underlying network connection can be returned to the
	// pool while we run static analysis.
	originalBody := r.Body
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxGraphQLBodyBytes))
	_ = originalBody.Close()
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
			writeError(w, http.StatusRequestEntityTooLarge,
				"GraphQL request body exceeds proxy size limit")
			h.logRequest(pt, r, "/graphql", "", http.StatusRequestEntityTooLarge, time.Since(start), "proxy_scope_denied")
			return
		}
		h.logger.Warn("graphql: failed to read request body", "error", err)
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		writeError(w, http.StatusBadRequest, "Failed to read GraphQL request body")
		h.logRequest(pt, r, "/graphql", "", http.StatusBadRequest, time.Since(start), "proxy_scope_denied")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	// Static analysis: parse the query and extract required scopes,
	// referenced repositories, and any unknown fields encountered.
	analysisStart := time.Now()
	analysis, err := analyzeGraphQLRequest(body)
	metrics.ObserveDecision(metrics.StageGraphQLAnalysis, tokenType, time.Since(analysisStart))
	if err != nil {
		// Fail closed: a query we cannot parse is a query we cannot scope.
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid GraphQL request: %s", err.Error()))
		h.logRequest(pt, r, "/graphql", "", http.StatusBadRequest, time.Since(start), "proxy_scope_denied")
		return
	}

	scopeEnforceStart := time.Now()

	// Subscriptions are never permitted: GitHub's GraphQL endpoint does not
	// support them over HTTP, and even if it did the proxy has no way to
	// stream-scope per-event payloads.
	if analysis.hasSubscription {
		metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		writeError(w, http.StatusForbidden, "GraphQL subscriptions are not supported")
		h.logRequest(pt, r, "/graphql", "", http.StatusForbidden, time.Since(start), "proxy_scope_denied")
		return
	}

	// Deny-by-default: any unknown field rejects the request when the token
	// has any restriction. Open-scoped tokens were forwarded earlier.
	if len(analysis.unknownFields) > 0 {
		metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("GraphQL request references unmapped fields: %s", strings.Join(analysis.unknownFields, ", ")))
		h.logRequest(pt, r, "/graphql", "", http.StatusForbidden, time.Since(start), "proxy_scope_denied")
		return
	}

	// Repository-scope enforcement.
	if len(si.Repos) > 0 {
		// Cross-repo fields cannot be statically constrained to a repo
		// allowlist (e.g. `search`, `node(id:)`, `viewer.repositories`).
		// Reject these requests rather than risk leaking data outside the
		// allowlist.
		if len(analysis.crossRepoFields) > 0 {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token is repository-restricted; GraphQL request uses cross-repository fields: %s",
					strings.Join(analysis.crossRepoFields, ", ")))
			h.logRequest(pt, r, "/graphql", "", http.StatusForbidden, time.Since(start), "proxy_scope_denied")
			return
		}
		// Repository-restricted queries must include at least one literal
		// repository(owner, name) reference, and every referenced
		// repository must be in the allowlist. Selections that are not
		// pinned to a repository are bounded by the cross-repository
		// field check above, which rejects fields that could return
		// out-of-allowlist data.
		if len(analysis.referencedRepos) == 0 {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
			writeError(w, http.StatusForbidden,
				"Token is repository-restricted; GraphQL request must reference repository(owner, name) with literal arguments")
			h.logRequest(pt, r, "/graphql", "", http.StatusForbidden, time.Since(start), "proxy_scope_denied")
			return
		}
		for _, repo := range analysis.referencedRepos {
			if !si.repoAllowed(repo) {
				metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
				metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
				writeError(w, http.StatusForbidden,
					fmt.Sprintf("Token is not scoped to %s", repo))
				h.logRequest(pt, r, "/graphql", repo, http.StatusForbidden, time.Since(start), "proxy_scope_denied")
				return
			}
		}
	}

	// Permission-scope enforcement.
	if len(si.Scopes) > 0 {
		// Mutations require at least one mapped write scope; if the
		// analyzer didn't map any required scope from a mutation, reject
		// (the deny-by-default unknown-fields check above usually catches
		// this first, but we verify here too).
		if analysis.hasMutation && len(analysis.requiredScopes) == 0 {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
			writeError(w, http.StatusForbidden,
				"GraphQL mutation could not be statically scoped; rejected by deny-by-default policy")
			h.logRequest(pt, r, "/graphql", "", http.StatusForbidden, time.Since(start), "proxy_scope_denied")
			return
		}
		if missing := analysis.missingScopes(si.Scopes); len(missing) > 0 {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token does not grant required GraphQL scopes: %s", strings.Join(missing, ", ")))
			h.logRequest(pt, r, "/graphql", "", http.StatusForbidden, time.Since(start), "proxy_scope_denied")
			return
		}
	}

	metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))

	// All static checks passed — forward to GitHub.
	repoForLog := ""
	if len(analysis.referencedRepos) == 1 {
		repoForLog = analysis.referencedRepos[0]
	}
	h.forwardGraphQL(w, r, pt, &si, rewriteAuth, start, &repoForLog)
}

// forwardGraphQL completes the GitHub-token resolution + upstream roundtrip
// portion of a GraphQL request. It is shared by the open-scoped fast path
// and the post-analysis path so that the metrics stages and audit log
// emission stay consistent across both.
func (h *Handler) forwardGraphQL(w http.ResponseWriter, r *http.Request, pt *database.ProxyToken, si *tokenScopeInfo, rewriteAuth func(string) string, start time.Time, repoForLog *string) {
	tokenType := pt.TokenType

	ghTokenStart := time.Now()
	githubToken, err := h.getGitHubToken(r, pt, si)
	metrics.ObserveDecision(metrics.StageGitHubTokenResolution, tokenType, time.Since(ghTokenStart))
	if err != nil {
		h.logger.Error("failed to get GitHub token for GraphQL", "error", err)
		status, msg := installationTokenErrorResponse(err)
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))
		writeError(w, status, msg)
		return
	}

	usernameStart := time.Now()
	h.resolveTokenUsername(r, githubToken)
	metrics.ObserveDecision(metrics.StageUsernameResolution, tokenType, time.Since(usernameStart))

	authHeader := rewriteAuth(githubToken)

	metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(start))

	upstreamStart := time.Now()
	status := h.forwardRequest(w, r, "/graphql", authHeader)
	metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, tokenType, time.Since(upstreamStart))

	h.checkCacheAfterRoundtrip(r, githubToken, pt)

	repo := ""
	if repoForLog != nil {
		repo = *repoForLog
	}
	h.logRequest(pt, r, "/graphql", repo, status, time.Since(start), "proxy_request")
}

// resolveTokenUsername resolves the identity behind a GitHub token by querying
// the GraphQL viewer endpoint and sets it as the username on the request
// context. The resolved login is cached by token hash so subsequent requests
// with the same credential are served from memory.
func (h *Handler) resolveTokenUsername(r *http.Request, githubToken string) {
	if h.usernameResolver != nil {
		if username := h.usernameResolver.ResolveFromGitHubToken(r.Context(), githubToken); username != "" {
			SetUsername(r, username)
		}
	}
}

// checkCacheAfterRoundtrip re-checks the username LRU cache after an upstream
// roundtrip and sets the username on the request if it was resolved during the
// wait. The async lookup triggered by resolveTokenUsername often completes
// while the upstream network I/O is in-flight, so this eliminates
// misattribution on most cold-cache first requests without adding latency.
//
// If the cache still yields no result and pt is a ghx_ proxy token with a
// known creator (pt.UserID), the method falls back to a database lookup for
// the creator's username. This keeps access logs and metrics populated during
// GitHub GraphQL outages or rate-limit bursts. The fallback is intentionally
// skipped for gha_ agent tokens to avoid misattributing the bot request to
// the human who created the token.
func (h *Handler) checkCacheAfterRoundtrip(r *http.Request, githubToken string, pt *database.ProxyToken) {
	resolveUsernameAfterRoundtrip(r, githubToken, GetUsername(r), h.usernameResolver, pt)
}

func (h *Handler) getGitHubToken(r *http.Request, pt *database.ProxyToken, si *tokenScopeInfo) (string, error) {
	switch token.TokenType(pt.TokenType) {
	case token.TokenTypeAgent:
		return h.getAgentGitHubToken(r.Context(), pt, si)
	default:
		return h.getProxyGitHubToken(r, pt)
	}
}

func (h *Handler) getAgentGitHubToken(ctx context.Context, pt *database.ProxyToken, si *tokenScopeInfo) (string, error) {
	if h.appTokenProvider == nil {
		return "", fmt.Errorf("agent tokens require GitHub App configuration")
	}
	if pt.InstallationID == nil {
		return "", fmt.Errorf("agent token missing installation_id")
	}

	// If the provider supports multi-app dispatch and the token has an app_id, use it.
	if multi, ok := h.appTokenProvider.(MultiAppTokenProvider); ok && pt.AppID != nil {
		return multi.GetInstallationTokenForApp(ctx, *pt.AppID, *pt.InstallationID, si.Repos, si.Scopes)
	}

	return h.appTokenProvider.GetInstallationToken(ctx, *pt.InstallationID, si.Repos, si.Scopes)
}

func (h *Handler) getProxyGitHubToken(r *http.Request, pt *database.ProxyToken) (string, error) {
	if pt.GitHubTokenID == nil {
		return "", fmt.Errorf("token has no linked GitHub credential")
	}
	gt, err := h.store.GetGitHubTokenByID(r.Context(), *pt.GitHubTokenID)
	if err != nil {
		return "", fmt.Errorf("loading github token: %w", err)
	}
	if gt == nil {
		return "", fmt.Errorf("github token not found")
	}

	// If the access token expires soon, attempt a refresh.
	if time.Until(gt.AccessTokenExpiresAt) < tokenRefreshSkew {
		newToken, err := h.refreshGitHubToken(r.Context(), gt)
		if err != nil {
			h.logger.Warn("github token refresh failed, using existing token",
				"token_id", gt.ID, "error", err)
			metrics.GitHubTokenRefreshTotal.WithLabelValues(gt.UserID, "failure").Inc()
		} else {
			metrics.GitHubTokenRefreshTotal.WithLabelValues(gt.UserID, "success").Inc()
			return newToken, nil
		}
	}

	// Decrypt the access token.
	plaintext, err := h.encryptor.Decrypt(gt.AccessToken)
	if err != nil {
		return "", fmt.Errorf("decrypting github token: %w", err)
	}

	return plaintext, nil
}

// tokenRefreshResponse represents the JSON response from GitHub's OAuth token endpoint.
type tokenRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// refreshGitHubToken exchanges a refresh token for a new access token via
// GitHub's OAuth token endpoint. On success it persists the new encrypted
// tokens and returns the new plaintext access token.
func (h *Handler) refreshGitHubToken(ctx context.Context, gt *database.GitHubToken) (string, error) {
	refreshPlaintext, err := h.encryptor.Decrypt(gt.RefreshToken)
	if err != nil {
		return "", fmt.Errorf("decrypting refresh token: %w", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {h.cfg.GitHub.ClientID},
		"client_secret": {h.cfg.GitHub.ClientSecret},
		"refresh_token": {refreshPlaintext},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("refresh endpoint returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp tokenRefreshResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing refresh response: %w", err)
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("refresh error: %s: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	// Encrypt and persist the new tokens.
	encAccess, err := h.encryptor.Encrypt(tokenResp.AccessToken)
	if err != nil {
		return "", fmt.Errorf("encrypting new access token: %w", err)
	}

	encRefresh, err := h.encryptor.Encrypt(tokenResp.RefreshToken)
	if err != nil {
		return "", fmt.Errorf("encrypting new refresh token: %w", err)
	}

	now := time.Now()
	gt.AccessToken = encAccess
	gt.RefreshToken = encRefresh
	gt.AccessTokenExpiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	// GitHub refresh tokens are valid for 6 months; update to 6 months from now.
	gt.RefreshTokenExpiresAt = now.Add(6 * 30 * 24 * time.Hour)

	if err := h.store.UpsertGitHubToken(ctx, gt); err != nil {
		return "", fmt.Errorf("persisting refreshed token: %w", err)
	}

	h.logger.Info("github token refreshed",
		"token_id", gt.ID,
		"expires_at", gt.AccessTokenExpiresAt.Format(time.RFC3339))

	return tokenResp.AccessToken, nil
}

// forwardPassthrough forwards a request to GitHub transparently, preserving
// the original Authorization header. Used for non-ghp_ tokens (e.g. gho_*,
// ghp_* from other systems, or personal access tokens) so they reach GitHub
// without interference.
func (h *Handler) forwardPassthrough(w http.ResponseWriter, r *http.Request, path string, start time.Time) {
	// Grab the raw GitHub token before forwarding so we can resolve the
	// username for metrics/access-log purposes without storing the token.
	rawToken := extractRawGitHubToken(r)

	// Trigger async username lookup early so it can run concurrently with
	// the upstream roundtrip. On a cache hit this returns immediately; on a
	// cache miss a background goroutine is spawned. Capture any cached
	// username so error-path metrics can attribute the request.
	if rawToken != "" && h.usernameResolver != nil {
		if username := h.usernameResolver.ResolveFromGitHubToken(r.Context(), rawToken); username != "" {
			SetUsername(r, username)
		}
	}

	apiType := "rest"
	if path == "/graphql" {
		apiType = "graphql"
	}

	targetURL := githubAPIBase + path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		metrics.ObservePassthroughRequest(backend.API, r.Method, http.StatusInternalServerError, time.Since(start), apiType, passthroughTokenType(rawToken), GetUsername(r))
		writeError(w, http.StatusInternalServerError, "Failed to create upstream request")
		return
	}

	// Copy all request headers, skipping hop-by-hop headers so the
	// passthrough is truly transparent for non-ghp_ credentials.
	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailer":             true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}
	for key, vals := range r.Header {
		if hopByHop[http.CanonicalHeaderKey(key)] {
			continue
		}
		for _, v := range vals {
			proxyReq.Header.Add(key, v)
		}
	}

	// Inject enterprise access restriction header if configured.
	if h.cfg.GitHub.EnterpriseSlug != "" {
		proxyReq.Header.Set("sec-GitHub-allowed-enterprise", h.cfg.GitHub.EnterpriseSlug)
	}

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		h.logger.Error("upstream passthrough request failed", "error", err)
		metrics.ObservePassthroughRequest(backend.API, r.Method, http.StatusBadGateway, time.Since(start), apiType, passthroughTokenType(rawToken), GetUsername(r))
		writeError(w, http.StatusBadGateway, "Upstream request failed")
		return
	}
	defer resp.Body.Close()

	// Copy response headers, filtering out hop-by-hop headers.
	for key, vals := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(key)] {
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}

	// Check the username cache after the roundtrip; the async lookup
	// triggered before the upstream request may have completed by now.
	if rawToken != "" && h.usernameResolver != nil && GetUsername(r) == "" {
		if username := h.usernameResolver.CheckCache(rawToken); username != "" {
			SetUsername(r, username)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	// Emit proxy-level metrics for passthrough traffic (token type may be "unknown").
	metrics.ObservePassthroughRequest(backend.API, r.Method, resp.StatusCode, time.Since(start), apiType, passthroughTokenType(rawToken), GetUsername(r))
}

// forwardRequest forwards a proxied request to GitHub, substituting authHeader
// as the Authorization value. The optional overrideHeaders map is applied after
// copying upstream response headers, allowing callers to inject or replace
// specific response headers (e.g. X-OAuth-Scopes) before the response is sent.
func (h *Handler) forwardRequest(w http.ResponseWriter, r *http.Request, path, authHeader string, overrideHeaders ...map[string]string) int {
	targetURL := githubAPIBase + path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create upstream request")
		return http.StatusInternalServerError
	}

	// Copy relevant headers.
	for _, key := range []string{"Content-Type", "Accept", "User-Agent"} {
		if v := r.Header.Get(key); v != "" {
			proxyReq.Header.Set(key, v)
		}
	}

	// Set the resolved Authorization header (scheme preserved from original request).
	proxyReq.Header.Set("Authorization", authHeader)

	// Inject enterprise access restriction header if configured.
	if h.cfg.GitHub.EnterpriseSlug != "" {
		proxyReq.Header.Set("sec-GitHub-allowed-enterprise", h.cfg.GitHub.EnterpriseSlug)
	}

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err)
		writeError(w, http.StatusBadGateway, "Upstream request failed")
		return http.StatusBadGateway
	}
	defer resp.Body.Close()

	// Copy rate limit headers for observability and update Prometheus metrics.
	for _, key := range []string{
		"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Used",
	} {
		if v := resp.Header.Get(key); v != "" {
			w.Header().Set(key, v)
		}
	}

	// Record rate limit metrics from response headers, labeled by GitHub username.
	username := GetUsername(r)
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		if n, err := strconv.Atoi(remaining); err == nil {
			h.logger.Debug("github rate limit", "remaining", n, "limit", resp.Header.Get("X-RateLimit-Limit"))
			metrics.GitHubRateLimitRemaining.WithLabelValues(username).Set(float64(n))
		}
	}
	if limit := resp.Header.Get("X-RateLimit-Limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil {
			metrics.GitHubRateLimitLimit.WithLabelValues(username).Set(float64(n))
		}
	}

	// Copy other response headers. X-OAuth-Scopes is included here so that
	// open-scoped tokens pass through GitHub's real scope information; for
	// scoped tokens the override applied below replaces this value. Location
	// is included so that upstream redirects (e.g. Actions job log downloads)
	// are passed through to the client.
	for key, vals := range resp.Header {
		canonicalKey := http.CanonicalHeaderKey(key)
		if strings.HasPrefix(canonicalKey, "X-Github") || canonicalKey == "Link" || canonicalKey == "Content-Type" || canonicalKey == "X-Oauth-Scopes" || canonicalKey == "Location" {
			for _, v := range vals {
				w.Header().Add(canonicalKey, v)
			}
		}
	}

	// Apply caller-supplied header overrides last so they take precedence over
	// whatever the upstream returned.
	if len(overrideHeaders) > 0 {
		for k, v := range overrideHeaders[0] {
			w.Header().Set(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	return resp.StatusCode
}

// syntheticOAuthScopes formats a Scopes map into a comma-separated string
// suitable for the X-OAuth-Scopes response header. Entries are sorted
// alphabetically for deterministic output.
func syntheticOAuthScopes(scopes database.Scopes) string {
	if len(scopes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(scopes))
	for perm, level := range scopes {
		parts = append(parts, perm+":"+level)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func (h *Handler) logRequest(pt *database.ProxyToken, r *http.Request, path, repo string, status int, dur time.Duration, action string) {
	userID := ""
	if pt.UserID != nil {
		userID = *pt.UserID
	}

	// Use the GitHub username for logging and metrics when available.
	username := GetUsername(r)

	h.logger.Info(action,
		"token_id", pt.ID,
		"user_id", userID,
		"github_username", username,
		"session", pt.SessionID,
		"repo", repo,
		"method", r.Method,
		"path", path,
		"status", status,
		"duration_ms", dur.Milliseconds(),
	)

	// Record Prometheus proxy-level metrics.
	apiType := "rest"
	if path == "/graphql" {
		apiType = "graphql"
	}
	metrics.ObserveProxyRequest(backend.API, pt, r.Method, status, dur, apiType, username)

	if h.auditLog != nil {
		h.auditLog.WriteAuditEntry(AuditLogEntry{
			Action:     action,
			UserID:     userID,
			Username:   username,
			TokenID:    pt.ID,
			TokenType:  pt.TokenType,
			SessionID:  pt.SessionID,
			Method:     r.Method,
			Path:       path,
			Repository: repo,
			StatusCode: status,
			DurationMS: int(dur.Milliseconds()),
		})
	}
}

// installationTokenErrorResponse inspects err for an *InstallationTokenError
// and returns the upstream status code with a descriptive message listing
// missing permissions. For all other errors it returns 500 with a generic message.
func installationTokenErrorResponse(err error) (int, string) {
	var ite *ghub.InstallationTokenError
	if !errors.As(err, &ite) {
		return http.StatusInternalServerError, "Failed to retrieve GitHub credentials"
	}

	missing := ite.MissingPermissions()
	if ite.GrantedPermissions == nil || len(missing) == 0 {
		return ite.StatusCode, ite.Message
	}

	parts := make([]string, 0, len(missing))
	for perm, level := range missing {
		parts = append(parts, perm+":"+level)
	}
	sort.Strings(parts)
	return ite.StatusCode, fmt.Sprintf("Installation is missing permissions: %s", strings.Join(parts, ", "))
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"message":           message,
		"documentation_url": "https://docs.github.com/rest",
	})
}
