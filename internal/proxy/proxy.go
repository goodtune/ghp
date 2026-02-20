package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/backend"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
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
	logger           *slog.Logger
	client           *http.Client
}

// NewHandler creates a new reverse proxy handler.
func NewHandler(cfg *config.Config, ts *token.Service, store database.Store, enc *crypto.Encryptor, atp AppTokenProvider, logger *slog.Logger) *Handler {
	return &Handler{
		cfg:              cfg,
		tokenService:     ts,
		store:            store,
		encryptor:        enc,
		appTokenProvider: atp,
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

	// GraphQL handled separately.
	if apiPath == "/graphql" {
		h.handleGraphQL(w, r, pt, rewriteAuth, start)
		return
	}

	// Extract repository from path (if this is a /repos/ path).
	repo := ExtractRepoFromPath(apiPath)

	// If a repo is identified, enforce the token's repository scope.
	if repo != "" && !repositoryAllowed(repo, pt.Repositories) {
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("Token is not scoped to %s", repo))
		h.logRequest(r.Context(), pt, r.Method, apiPath, repo, http.StatusForbidden, time.Since(start), "proxy_scope_denied")
		return
	}

	// Check endpoint permission scope for known endpoints.
	// Unrecognized endpoints are forwarded — GitHub's token handles access.
	permission, level := EndpointScope(r.Method, apiPath)
	if permission != "" && permission != "metadata" {
		scopes, err := database.ParseScopes(pt.Scopes)
		if err != nil {
			h.logger.Error("failed to parse token scopes", "error", err)
			writeError(w, http.StatusInternalServerError, "Internal error")
			return
		}

		if !scopes.HasPermission(permission, level) {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token does not have permission for %s:%s on %s", permission, level, repo))
			h.logRequest(r.Context(), pt, r.Method, apiPath, repo, http.StatusForbidden, time.Since(start), "proxy_scope_denied")
			return
		}
	}

	// Get the real GitHub access token.
	githubToken, err := h.getGitHubToken(r, pt)
	if err != nil {
		h.logger.Error("failed to get GitHub token", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve GitHub credentials")
		return
	}

	// Forward the request to GitHub.
	status := h.forwardRequest(w, r, apiPath, rewriteAuth(githubToken))

	// Record usage.
	if err := h.tokenService.RecordUsage(r.Context(), pt.ID); err != nil {
		h.logger.Error("failed to record token usage", "error", err)
	}

	h.logRequest(r.Context(), pt, r.Method, apiPath, repo, status, time.Since(start), "proxy_request")
}

func (h *Handler) handleGraphQL(w http.ResponseWriter, r *http.Request, pt *database.ProxyToken, rewriteAuth func(string) string, start time.Time) {
	// For GraphQL, we forward the request and check the token's scopes in a simplified manner.
	// Full GraphQL query parsing is complex; for now, we require that the token has at least one scope.
	githubToken, err := h.getGitHubToken(r, pt)
	if err != nil {
		h.logger.Error("failed to get GitHub token for GraphQL", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve GitHub credentials")
		return
	}

	status := h.forwardRequest(w, r, "/graphql", rewriteAuth(githubToken))

	if err := h.tokenService.RecordUsage(r.Context(), pt.ID); err != nil {
		h.logger.Error("failed to record token usage", "error", err)
	}

	h.logRequest(r.Context(), pt, r.Method, "/graphql", "", status, time.Since(start), "proxy_request")
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

	var repos []string
	if err := json.Unmarshal(pt.Repositories, &repos); err != nil {
		return "", fmt.Errorf("parsing repositories: %w", err)
	}

	scopes, err := database.ParseScopes(pt.Scopes)
	if err != nil {
		return "", fmt.Errorf("parsing scopes: %w", err)
	}

	return h.appTokenProvider.GetInstallationToken(ctx, *pt.InstallationID, repos, scopes)
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
		} else {
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

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *Handler) forwardRequest(w http.ResponseWriter, r *http.Request, path, authHeader string) int {
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

	// Copy rate limit headers for observability.
	for _, key := range []string{
		"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Used",
	} {
		if v := resp.Header.Get(key); v != "" {
			w.Header().Set(key, v)
		}
	}

	// Log rate limit info.
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		if n, err := strconv.Atoi(remaining); err == nil {
			h.logger.Debug("github rate limit", "remaining", n, "limit", resp.Header.Get("X-RateLimit-Limit"))
		}
	}

	// Copy other response headers.
	for key, vals := range resp.Header {
		if strings.HasPrefix(key, "X-GitHub") || key == "Link" || key == "Content-Type" {
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	return resp.StatusCode
}

func (h *Handler) logRequest(ctx context.Context, pt *database.ProxyToken, method, path, repo string, status int, dur time.Duration, action string) {
	userID := ""
	if pt.UserID != nil {
		userID = *pt.UserID
	}
	h.logger.Info(action,
		"token_id", pt.ID,
		"user_id", userID,
		"session", pt.SessionID,
		"repo", repo,
		"method", method,
		"path", path,
		"status", status,
		"duration_ms", dur.Milliseconds(),
	)

	// Record Prometheus proxy-level metrics.
	metrics.ObserveProxyRequest(backend.API, pt, method, status, dur)

	entry := &database.AuditEntry{
		UserID:     userID,
		Action:     action,
		Method:     method,
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


func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"message":           message,
		"documentation_url": "https://docs.github.com/rest",
	})
}
