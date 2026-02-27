package proxy

import (
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

const (
	githubAPIBase    = "https://api.github.com"
	githubTokenURL   = "https://github.com/login/oauth/access_token"
	tokenRefreshSkew = 5 * time.Minute
)

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
	// If the token is not a client token (ghx_/gha_), forward the request
	// transparently to GitHub with the original credentials intact.
	clientToken, rewriteAuth := extractClientToken(r)
	if clientToken == "" {
		h.forwardPassthrough(w, r, apiPath)
		return
	}

	// Resolve the client token.
	pt, err := h.tokenService.Resolve(r.Context(), clientToken)
	if err != nil {
		h.logger.Warn("token resolution failed", "error", err)
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if pt == nil {
		writeError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	// Resolve the GitHub username from the token's user ID and inject it
	// into the request context so the access-log middleware can read it.
	if h.usernameResolver != nil && pt.UserID != nil {
		if username := h.usernameResolver.ResolveFromUserID(r.Context(), *pt.UserID); username != "" {
			SetUsername(r, username)
		}
	}

	// Parse the token's scope restrictions once; fail-closed on corrupt JSON.
	// Must happen before GraphQL routing so that corrupt JSON is never treated
	// as open-scoped, even on the GraphQL path.
	si, err := parseScopeInfo(pt)
	if err != nil {
		h.logger.Error("failed to parse token scope", "error", err)
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
		githubToken, err := h.getGitHubToken(r, pt)
		if err != nil {
			h.logger.Error("failed to get GitHub token", "error", err)
			status, msg := installationTokenErrorResponse(err)
			writeError(w, status, msg)
			return
		}
		repo := ExtractRepoFromPath(apiPath)
		status := h.forwardRequest(w, r, apiPath, rewriteAuth(githubToken))
		if err := h.tokenService.RecordUsage(r.Context(), pt.ID); err != nil {
			h.logger.Error("failed to record token usage", "error", err)
		}
		h.logRequest(r.Context(), pt, r, apiPath, repo, status, time.Since(start), "proxy_request")
		return
	}

	// Extract repository from path (if this is a /repos/ path).
	repo := ExtractRepoFromPath(apiPath)

	// Enforce repository scope only when the token has repo restrictions.
	// A token with repos=null carries no repo restriction (applies to any repo).
	if repo != "" && len(si.Repos) > 0 && !si.repoAllowed(repo) {
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("Token is not scoped to %s", repo))
		h.logRequest(r.Context(), pt, r, apiPath, repo, http.StatusForbidden, time.Since(start), "proxy_scope_denied")
		return
	}

	// Enforce permission scope only when the token has scope restrictions.
	// Unrecognized endpoints are forwarded — GitHub's token handles access.
	// A token with scopes=null carries no permission restriction (any endpoint allowed).
	permission, level := EndpointScope(r.Method, apiPath)
	if permission != "" && permission != "metadata" && len(si.Scopes) > 0 {
		if !si.Scopes.HasPermission(permission, level) {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token does not have permission for %s:%s on %s", permission, level, repo))
			h.logRequest(r.Context(), pt, r, apiPath, repo, http.StatusForbidden, time.Since(start), "proxy_scope_denied")
			return
		}
	}

	// Get the real GitHub access token.
	githubToken, err := h.getGitHubToken(r, pt)
	if err != nil {
		h.logger.Error("failed to get GitHub token", "error", err)
		status, msg := installationTokenErrorResponse(err)
		writeError(w, status, msg)
		return
	}

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

	// Forward the request to GitHub.
	status := h.forwardRequest(w, r, apiPath, rewriteAuth(githubToken), scopeOverride)

	// Record usage.
	if err := h.tokenService.RecordUsage(r.Context(), pt.ID); err != nil {
		h.logger.Error("failed to record token usage", "error", err)
	}

	h.logRequest(r.Context(), pt, r, apiPath, repo, status, time.Since(start), "proxy_request")
}

func (h *Handler) handleGraphQL(w http.ResponseWriter, r *http.Request, pt *database.ProxyToken, si tokenScopeInfo, rewriteAuth func(string) string, start time.Time) {
	// Repository-restricted tokens cannot have their repo restrictions enforced
	// on GraphQL requests because GraphQL queries can span arbitrary repositories
	// without a parseable path structure. Block GraphQL to prevent bypassing
	// repository scope restrictions.
	if len(si.Repos) > 0 {
		writeError(w, http.StatusForbidden,
			"Token is repository-restricted; GraphQL is not supported for repository-scoped tokens")
		h.logRequest(r.Context(), pt, r, "/graphql", "", http.StatusForbidden, time.Since(start), "proxy_scope_denied")
		return
	}

	// For permission-scoped tokens (scopes set, no repo restrictions), we forward
	// to GitHub. Full GraphQL query parsing to enforce per-operation permission
	// checks is not implemented; the underlying GitHub token enforces actual access.
	githubToken, err := h.getGitHubToken(r, pt)
	if err != nil {
		h.logger.Error("failed to get GitHub token for GraphQL", "error", err)
		status, msg := installationTokenErrorResponse(err)
		writeError(w, status, msg)
		return
	}

	status := h.forwardRequest(w, r, "/graphql", rewriteAuth(githubToken))

	if err := h.tokenService.RecordUsage(r.Context(), pt.ID); err != nil {
		h.logger.Error("failed to record token usage", "error", err)
	}

	h.logRequest(r.Context(), pt, r, "/graphql", "", status, time.Since(start), "proxy_request")
}

func (h *Handler) getGitHubToken(r *http.Request, pt *database.ProxyToken) (string, error) {
	switch token.TokenType(pt.TokenType) {
	case token.TokenTypeAgent:
		return h.getAgentGitHubToken(r.Context(), pt)
	default:
		return h.getProxyGitHubToken(r, pt)
	}
}

func (h *Handler) getAgentGitHubToken(ctx context.Context, pt *database.ProxyToken) (string, error) {
	if h.appTokenProvider == nil {
		return "", fmt.Errorf("agent tokens require GitHub App configuration")
	}
	if pt.InstallationID == nil {
		return "", fmt.Errorf("agent token missing installation_id")
	}

	si, err := parseScopeInfo(pt)
	if err != nil {
		return "", fmt.Errorf("parsing agent token scope: %w", err)
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
func (h *Handler) forwardPassthrough(w http.ResponseWriter, r *http.Request, path string) {
	// Grab the raw GitHub token before forwarding so we can resolve the
	// username for metrics/access-log purposes without storing the token.
	rawToken := extractRawGitHubToken(r)

	targetURL := githubAPIBase + path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
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

	// Resolve the GitHub username from the raw token and inject it into the
	// request context before writing the response so the access-log
	// middleware can capture it.
	if rawToken != "" && h.usernameResolver != nil {
		if username := h.usernameResolver.ResolveFromGitHubToken(r.Context(), rawToken); username != "" {
			SetUsername(r, username)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
	// scoped tokens the override applied below replaces this value.
	for key, vals := range resp.Header {
		if strings.HasPrefix(key, "X-GitHub") || key == "Link" || key == "Content-Type" || key == "X-Oauth-Scopes" {
			for _, v := range vals {
				w.Header().Add(key, v)
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

func (h *Handler) logRequest(ctx context.Context, pt *database.ProxyToken, r *http.Request, path, repo string, status int, dur time.Duration, action string) {
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

	entry := &database.AuditEntry{
		UserID:     userID,
		Action:     action,
		Method:     r.Method,
		Path:       path,
		Repository: repo,
		StatusCode: status,
		DurationMS: int(dur.Milliseconds()),
		SessionID:  pt.SessionID,
	}
	tokenID := pt.ID
	entry.ProxyTokenID = &tokenID

	if err := h.store.CreateAuditEntry(ctx, entry); err != nil {
		h.logger.Error("failed to create audit entry", "error", err)
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
