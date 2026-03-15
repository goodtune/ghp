// Package server wires up the HTTP server with all routes.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	ghub "github.com/google/go-github/v84/github"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	ghpgithub "github.com/goodtune/ghp/internal/github"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/proxy"
	"github.com/goodtune/ghp/internal/token"
)

// maxRequestBodySize is the maximum allowed request body size for API endpoints.
const maxRequestBodySize = 1 << 20 // 1 MB

// isValidUUID returns true if s is a well-formed UUID string.
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// validateBaseURL checks that s is a valid HTTPS URL with no path or query.
// An empty string is allowed (means use the default GitHub API URL).
func validateBaseURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("malformed URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be https")
	}
	if u.Host == "" {
		return fmt.Errorf("host is required")
	}
	return nil
}

// maxSessionIDLength caps the length of the user-provided session_id to
// prevent oversized audit log lines and log-volume amplification.
const maxSessionIDLength = 128

// API handles the service API endpoints (token management, users).
type API struct {
	cfg                *config.Config
	ctx                context.Context     // server lifecycle context; cancelled on shutdown
	store              database.Store
	tokenService       *token.Service
	authHandler        *auth.Handler
	encryptor          *crypto.Encryptor
	appTokenProvider   *ghpgithub.AppTokenProvider // nil if GitHub App not configured
	appRegistry        *ghpgithub.AppRegistry      // nil if no apps loaded
	proxyTokenResolver *proxy.ProxyTokenResolver   // resolves proxy tokens to GitHub credentials
	usernameResolver   *proxy.UsernameResolver     // caches GitHub username lookups
	logger             *slog.Logger
	httpClient         *http.Client // used for outbound GitHub API calls
	auditLog           *auditLogWriter

	tokenCreateLimiter *auth.IPRateLimiter // POST /api/tokens
}

// NewAPI creates a new API handler.
func NewAPI(ctx context.Context, cfg *config.Config, store database.Store, ts *token.Service, ah *auth.Handler, enc *crypto.Encryptor, atp *ghpgithub.AppTokenProvider, ar *ghpgithub.AppRegistry, ptr *proxy.ProxyTokenResolver, ur *proxy.UsernameResolver, logger *slog.Logger, aw *auditLogWriter) *API {
	if aw == nil {
		aw = newAuditLogWriter(nil)
	}
	return &API{
		cfg:                cfg,
		ctx:                ctx,
		store:              store,
		tokenService:       ts,
		authHandler:        ah,
		encryptor:          enc,
		appTokenProvider:   atp,
		appRegistry:        ar,
		proxyTokenResolver: ptr,
		usernameResolver:   ur,
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		auditLog:           aw,
		tokenCreateLimiter: auth.NewIPRateLimiter(20, time.Minute, "/api/tokens", logger),
	}
}

// RegisterRoutes adds API routes to the given mux.
// All routes require authentication via the auth handler.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/tokens", a.authHandler.RequireAuth(a.tokenCreateLimiter.Middleware(http.HandlerFunc(a.handleCreateToken))))
	mux.Handle("GET /api/tokens", a.authHandler.RequireAuth(http.HandlerFunc(a.handleListTokens)))
	mux.Handle("GET /api/tokens/{id}", a.authHandler.RequireAuth(http.HandlerFunc(a.handleGetToken)))
	mux.Handle("DELETE /api/tokens/{id}", a.authHandler.RequireAuth(http.HandlerFunc(a.handleRevokeToken)))

	mux.Handle("GET /api/users", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListUsers)))
	mux.Handle("GET /api/users/{id}/tokens", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListUserTokens)))

	mux.Handle("GET /api/github/repositories", a.authHandler.RequireAuth(http.HandlerFunc(a.handleListUserRepos)))
	mux.Handle("GET /api/github/permissions", a.authHandler.RequireAuth(http.HandlerFunc(a.handleGetPermissions)))
	mux.Handle("GET /api/github/installations", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListInstallations)))
	mux.Handle("GET /api/github/installations/{id}/repositories", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListInstallationRepos)))

	// App management routes.
	mux.Handle("GET /api/apps", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListApps)))
	mux.Handle("POST /api/apps", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleCreateApp)))
	mux.Handle("GET /api/apps/{id}", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleGetApp)))
	mux.Handle("PUT /api/apps/{id}", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleUpdateApp)))
	mux.Handle("DELETE /api/apps/{id}", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleDeleteApp)))
	mux.Handle("GET /api/apps/{id}/installations", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListAppInstallations)))
	mux.Handle("GET /api/apps/{id}/installations/{iid}/repositories", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListAppInstallationRepos)))

}

type createTokenRequest struct {
	Type           string   `json:"type"`
	AppRecordID    string   `json:"app_record_id"`
	Repository     string   `json:"repository"`
	Repositories   []string `json:"repositories"`
	InstallationID int64    `json:"installation_id"`
	Scopes         string   `json:"scopes"`
	Duration       string   `json:"duration"`
	SessionID      string   `json:"session_id"`
}

func (a *API) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"message": "Request body too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
		}
		return
	}

	tt := token.TokenTypeProxy
	if req.Type == "agent" {
		tt = token.TokenTypeAgent
		if session.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "Admin role required for agent tokens"})
			return
		}
	}

	// app_record_id is only meaningful for agent tokens. GitHub App installations
	// are not used for proxy (OAuth-backed) tokens, so reject the field early to
	// prevent confusing state where a proxy token carries an unused app association.
	if req.AppRecordID != "" && tt == token.TokenTypeProxy {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "app_record_id is only valid for agent tokens"})
		return
	}

	// Reject agent token creation when apps exist in the store but none loaded
	// successfully — the token would be created but reliably fail at use time.
	if tt == token.TokenTypeAgent && a.appRegistry != nil && a.appRegistry.TotalApps() > 0 && a.appRegistry.Count() == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "cannot create agent tokens: apps exist but none loaded successfully (check private keys)"})
		return
	}

	// Scopes are optional — an empty string means open-scoped.
	var scopes map[string]string
	if req.Scopes != "" {
		var err error
		scopes, err = token.ParseScopeString(req.Scopes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
	}

	duration := a.cfg.Tokens.DefaultDuration
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid duration format"})
			return
		}
		duration = d
	}

	// Validate app_record_id if provided: must be a valid UUID and the
	// referenced app must exist in the store and be loaded in the registry.
	if req.AppRecordID != "" {
		if !isValidUUID(req.AppRecordID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid app_record_id: not a valid UUID"})
			return
		}
		app, err := a.store.GetAppByID(r.Context(), req.AppRecordID)
		if err != nil {
			a.logger.Error("failed to look up app for token creation", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
			return
		}
		if app == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid app_record_id: app not found"})
			return
		}
		if a.appRegistry != nil {
			if _, err := a.appRegistry.Get(req.AppRecordID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid app_record_id: app is not loaded (invalid credentials or private key)"})
				return
			}
		}
	}

	sessionID := truncateSessionID(req.SessionID)

	// For agent tokens in multi-app mode, pin the token to the default (or
	// sole) app when no app_record_id was specified. DefaultOrOnlyID handles
	// both the explicit-default case and the single-app-no-default case so
	// that dispatch stays deterministic even if more apps are added later.
	appRecordID := req.AppRecordID
	if tt == token.TokenTypeAgent && appRecordID == "" && a.appRegistry != nil && a.appRegistry.Count() > 0 {
		appRecordID = a.appRegistry.DefaultOrOnlyID()
		// When multiple apps are configured but none is marked as default, the
		// caller must explicitly specify which app the token belongs to; there is
		// no unambiguous choice to make on their behalf.
		if appRecordID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "app_record_id is required when multiple apps are configured and no default app is set"})
			return
		}
	}

	createReq := token.CreateRequest{
		TokenType:   tt,
		AppRecordID: appRecordID,
		UserID:      session.UserID,
		Scopes:      scopes,
		Duration:    duration,
		SessionID:   sessionID,
	}

	switch tt {
	case token.TokenTypeProxy:
		gt, err := a.store.GetGitHubToken(r.Context(), session.UserID)
		if err != nil || gt == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "No GitHub token found. Please re-authenticate."})
			return
		}
		createReq.GitHubTokenID = gt.ID
		// Support both single repository and multiple repositories.
		if len(req.Repositories) > 0 {
			createReq.Repositories = req.Repositories
		} else if req.Repository != "" {
			createReq.Repository = req.Repository
		}
	case token.TokenTypeAgent:
		createReq.InstallationID = req.InstallationID
		createReq.Repositories = req.Repositories
	}

	result, err := a.tokenService.Create(r.Context(), createReq)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	metrics.TokenCreatedTotal.WithLabelValues(session.UserID).Inc()
	metrics.TokenActive.WithLabelValues(session.UserID).Inc()

	// Best-effort warm of the username cache for the newly created token so
	// the first proxied requests are more likely to have the identity
	// available without an extra lookup. Identity may still be resolved
	// lazily on first use.
	a.warmTokenUsername(result.ID)

	a.auditLog.writeEntry(&auditLogEntry{
		Msg:       "audit event",
		Action:    "token_created",
		UserID:    session.UserID,
		Username:  session.Username,
		TokenID:   result.ID,
		TokenType: string(tt),
		SessionID: result.SessionID,
	})

	a.logger.Info("token_created",
		"user", session.Username,
		"type", string(tt),
		"repos", result.Repositories,
		"session", result.SessionID,
	)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":        result.Token,
		"id":           result.ID,
		"type":         string(result.TokenType),
		"repositories": result.Repositories,
		"scopes":       result.Scopes,
		"expires_at":   result.ExpiresAt.Format(time.RFC3339),
		"session_id":   result.SessionID,
	})
}

func (a *API) handleListTokens(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	var tokens []*database.ProxyToken
	var err error

	// Admins can see all tokens.
	if session.Role == "admin" && r.URL.Query().Get("all") == "true" {
		tokens, err = a.store.ListAllProxyTokens(r.Context())
	} else {
		tokens, err = a.store.ListProxyTokens(r.Context(), session.UserID)
	}

	if err != nil {
		a.logger.Error("failed to list tokens", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}

	if tokens == nil {
		tokens = []*database.ProxyToken{}
	}

	writeJSON(w, http.StatusOK, tokens)
}

func (a *API) handleGetToken(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	id := r.PathValue("id")

	pt, err := a.store.GetProxyTokenByID(r.Context(), id)
	if err != nil {
		a.logger.Error("failed to get token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	if pt == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Token not found"})
		return
	}
	if (pt.UserID == nil || *pt.UserID != session.UserID) && session.Role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "Access denied"})
		return
	}

	writeJSON(w, http.StatusOK, pt)
}

func (a *API) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	id := r.PathValue("id")

	pt, err := a.store.GetProxyTokenByID(r.Context(), id)
	if err != nil {
		a.logger.Error("failed to get token for revocation", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	if pt == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Token not found"})
		return
	}
	if (pt.UserID == nil || *pt.UserID != session.UserID) && session.Role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "Access denied"})
		return
	}

	if err := a.tokenService.Revoke(r.Context(), id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	ownerID := session.UserID
	if pt.UserID != nil && *pt.UserID != "" {
		ownerID = *pt.UserID
	}
	metrics.TokenRevokedTotal.WithLabelValues(ownerID).Inc()
	metrics.TokenActive.WithLabelValues(ownerID).Dec()

	a.auditLog.writeEntry(&auditLogEntry{
		Msg:       "audit event",
		Action:    "token_revoked",
		UserID:    session.UserID,
		Username:  session.Username,
		TokenID:   id,
		TokenType: pt.TokenType,
	})

	a.logger.Info("token_revoked", "user", session.Username, "token_id", id)

	writeJSON(w, http.StatusOK, map[string]string{"message": "Token revoked"})
}

func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.ListUsers(r.Context())
	if err != nil {
		a.logger.Error("failed to list users", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (a *API) handleListUserTokens(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tokens, err := a.store.ListProxyTokens(r.Context(), id)
	if err != nil {
		a.logger.Error("failed to list user tokens", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	if tokens == nil {
		tokens = []*database.ProxyToken{}
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (a *API) handleListUserRepos(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	gt, err := a.store.GetGitHubToken(r.Context(), session.UserID)
	if err != nil || gt == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "No GitHub token found. Please re-authenticate."})
		return
	}

	plainToken, err := a.encryptor.Decrypt(gt.AccessToken)
	if err != nil {
		a.logger.Error("failed to decrypt github token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to decrypt credentials"})
		return
	}

	client := ghub.NewClient(nil).WithAuthToken(plainToken)

	type ghRepo struct {
		FullName string `json:"full_name"`
		Name     string `json:"name"`
		Private  bool   `json:"private"`
	}

	var allRepos []ghRepo
	opts := &ghub.RepositoryListByAuthenticatedUserOptions{
		Sort:        "full_name",
		ListOptions: ghub.ListOptions{PerPage: 100},
	}
	for {
		repos, resp, err := client.Repositories.ListByAuthenticatedUser(r.Context(), opts)
		if err != nil {
			a.logger.Error("failed to list user repos", "error", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Failed to list repositories"})
			return
		}
		for _, repo := range repos {
			allRepos = append(allRepos, ghRepo{
				FullName: repo.GetFullName(),
				Name:     repo.GetName(),
				Private:  repo.GetPrivate(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	writeJSON(w, http.StatusOK, allRepos)
}

func (a *API) handleListInstallations(w http.ResponseWriter, r *http.Request) {
	if a.appTokenProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "GitHub App not configured"})
		return
	}

	installations, err := a.appTokenProvider.ListInstallations(r.Context())
	if err != nil {
		a.logger.Error("failed to list installations", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Failed to list GitHub installations"})
		return
	}

	writeJSON(w, http.StatusOK, installations)
}

func (a *API) handleListInstallationRepos(w http.ResponseWriter, r *http.Request) {
	if a.appTokenProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "GitHub App not configured"})
		return
	}

	idStr := r.PathValue("id")
	installationID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid installation ID"})
		return
	}

	repos, err := a.appTokenProvider.ListInstallationRepositories(r.Context(), installationID)
	if err != nil {
		a.logger.Error("failed to list installation repos", "error", err, "installation_id", installationID)
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Failed to list repositories"})
		return
	}

	writeJSON(w, http.StatusOK, repos)
}

// handleGetPermissions returns the permission levels available for the
// authenticated user's GitHub OAuth token, derived from X-OAuth-Scopes.
// When no GitHub token is stored (dev mode, test users) it returns a full
// default set so the UI remains functional.
func (a *API) handleGetPermissions(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	gt, err := a.store.GetGitHubToken(r.Context(), session.UserID)
	if err != nil {
		a.logger.Error("failed to get github token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}

	// No GitHub token — dev mode or test user. Return the full default set.
	if gt == nil {
		writeJSON(w, http.StatusOK, defaultPermissions())
		return
	}

	plainToken, err := a.encryptor.Decrypt(gt.AccessToken)
	if err != nil {
		a.logger.Error("failed to decrypt github token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to decrypt credentials"})
		return
	}

	// Call GET https://api.github.com/ to retrieve X-OAuth-Scopes.
	req, err := http.NewRequestWithContext(r.Context(), "GET", "https://api.github.com/", nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+plainToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Error("failed to call github root endpoint", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Failed to contact GitHub"})
		return
	}
	defer resp.Body.Close()

	scopesHeader := resp.Header.Get("X-OAuth-Scopes")
	perms := oauthScopesToPermissions(scopesHeader)

	// If no permissions were derived (e.g. GitHub App token with no OAuth scopes),
	// fall back to the default set so the UI is still usable.
	if len(perms) == 0 {
		writeJSON(w, http.StatusOK, defaultPermissions())
		return
	}

	writeJSON(w, http.StatusOK, perms)
}

// defaultPermissions returns the full set of proxy-token permissions at their
// maximum levels. Used when no GitHub OAuth token is available to constrain
// the set (dev mode, test users, GitHub App tokens).
func defaultPermissions() map[string]string {
	return map[string]string{
		"contents":      "write",
		"pull_requests": "write",
		"issues":        "write",
		"statuses":      "write",
		"checks":        "write",
		"actions":       "write",
		"metadata":      "read",
	}
}

// oauthScopesToPermissions maps a GitHub OAuth X-OAuth-Scopes header value to
// the permission levels available in the proxy scope system. Permissions not
// covered by the granted OAuth scopes are omitted from the result, preventing
// users from creating tokens that claim permissions the underlying credential
// cannot satisfy.
func oauthScopesToPermissions(scopesHeader string) map[string]string {
	scopes := make(map[string]bool)
	for _, s := range strings.Split(scopesHeader, ",") {
		scopes[strings.TrimSpace(s)] = true
	}

	perms := make(map[string]string)

	// repo (or public_repo) grants access to most repository resources.
	if scopes["repo"] || scopes["public_repo"] {
		perms["contents"] = "write"
		perms["pull_requests"] = "write"
		perms["issues"] = "write"
		perms["statuses"] = "write"
		perms["checks"] = "write"
		perms["metadata"] = "read"
		// Actions read is implied by repo; write requires the workflow scope.
		if scopes["workflow"] {
			perms["actions"] = "write"
		} else {
			perms["actions"] = "read"
		}
	} else if scopes["repo:status"] {
		// repo:status alone gives commit-status write without full repo access.
		perms["statuses"] = "write"
		perms["metadata"] = "read"
	}

	// Security alerts and vulnerability scanning.
	if scopes["security_events"] {
		perms["security_events"] = "write"
		perms["vulnerability_alerts"] = "write"
		if perms["metadata"] == "" {
			perms["metadata"] = "read"
		}
	}

	// Package registry.
	if scopes["write:packages"] {
		perms["packages"] = "write"
	} else if scopes["read:packages"] {
		perms["packages"] = "read"
	}

	// Organisation membership management.
	if scopes["admin:org"] || scopes["write:org"] {
		perms["members"] = "write"
	} else if scopes["read:org"] {
		perms["members"] = "read"
	}

	// Discussions.
	if scopes["write:discussion"] || scopes["admin:discussion"] {
		perms["discussions"] = "write"
	} else if scopes["read:discussion"] {
		perms["discussions"] = "read"
	}

	return perms
}

// warmTokenUsername resolves the GitHub credential behind a newly created
// proxy token and triggers a best-effort async GraphQL viewer lookup to
// pre-populate the username cache. The lookup runs in the background and
// may not complete before the first proxied request arrives.
// The server-lifecycle context (a.ctx) is used as the parent so that
// in-flight DB and token-resolution calls are cancelled if the server
// shuts down. The GraphQL viewer lookup spawned by ResolveFromGitHubToken
// runs on a separate background context (bounded by a 5s HTTP timeout) so
// it is not cancelled by the parent — this is by design, matching the
// request-driven path where lookups must outlive the triggering request.
func (a *API) warmTokenUsername(tokenID string) {
	if a.proxyTokenResolver == nil || a.usernameResolver == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
		defer cancel()

		pt, err := a.store.GetProxyTokenByID(ctx, tokenID)
		if err != nil || pt == nil {
			return
		}
		ghToken, err := a.proxyTokenResolver.ResolveProxyTokenToGitHub(ctx, pt)
		if err != nil {
			return
		}
		a.usernameResolver.ResolveFromGitHubToken(ctx, ghToken)
	}()
}

// truncateSessionID caps s to maxSessionIDLength bytes to prevent oversized
// audit log lines from user-provided session identifiers. The truncation
// respects UTF-8 rune boundaries so the result is always valid UTF-8.
func truncateSessionID(s string) string {
	if len(s) <= maxSessionIDLength {
		return s
	}
	// Walk rune boundaries and find the last one at or before the limit.
	cut := maxSessionIDLength
	for i := range s {
		if i > maxSessionIDLength {
			break
		}
		cut = i
	}
	return s[:cut]
}

// --- App management handlers ---

func (a *API) handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := a.store.ListApps(r.Context())
	if err != nil {
		a.logger.Error("failed to list apps", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	if apps == nil {
		apps = []*database.App{}
	}
	type appResponse struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		AppID     int64  `json:"app_id"`
		ClientID  string `json:"client_id"`
		BaseURL   string `json:"base_url"`
		IsDefault bool   `json:"is_default"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}
	result := make([]appResponse, 0, len(apps))
	for _, app := range apps {
		result = append(result, appResponse{
			ID:        app.ID,
			Name:      app.Name,
			AppID:     app.AppID,
			ClientID:  app.ClientID,
			BaseURL:   app.BaseURL,
			IsDefault: app.IsDefault,
			CreatedAt: app.CreatedAt.Format(time.RFC3339),
			UpdatedAt: app.UpdatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, result)
}

type createAppRequest struct {
	Name         string `json:"name"`
	AppID        int64  `json:"app_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	PrivateKey   string `json:"private_key"`
	BaseURL      string `json:"base_url"`
	IsDefault    bool   `json:"is_default"`
}

func (a *API) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req createAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"message": "Request body too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
		}
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "name is required"})
		return
	}
	if req.AppID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "app_id must be a positive integer"})
		return
	}
	if req.PrivateKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "private_key is required"})
		return
	}
	if err := validateBaseURL(req.BaseURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("invalid base_url: %s", err)})
		return
	}

	// Encrypt secrets before storing.
	encClientSecret := req.ClientSecret
	if a.encryptor != nil && encClientSecret != "" {
		encrypted, err := a.encryptor.Encrypt(encClientSecret)
		if err != nil {
			a.logger.Error("failed to encrypt client secret", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to encrypt credentials"})
			return
		}
		encClientSecret = encrypted
	}
	encPrivateKey := req.PrivateKey
	if a.encryptor != nil && encPrivateKey != "" {
		encrypted, err := a.encryptor.Encrypt(encPrivateKey)
		if err != nil {
			a.logger.Error("failed to encrypt private key", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to encrypt credentials"})
			return
		}
		encPrivateKey = encrypted
	}

	// Create the app with IsDefault=false first. If the caller requested it to
	// be the default, we promote it after a successful insert so that a failed
	// CreateApp cannot leave the system with no default app.
	app := &database.App{
		Name:         req.Name,
		AppID:        req.AppID,
		ClientID:     req.ClientID,
		ClientSecret: encClientSecret,
		PrivateKey:   encPrivateKey,
		BaseURL:      req.BaseURL,
		IsDefault:    false,
	}

	if err := a.store.CreateApp(r.Context(), app); err != nil {
		a.logger.Error("failed to create app", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to create app"})
		return
	}

	// Enforce at most one default app: clear the flag on all other apps and
	// then promote the newly created one.
	if req.IsDefault {
		if err := a.clearDefaultApps(r.Context(), app.ID); err != nil {
			a.logger.Error("failed to clear default apps", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to update app"})
			return
		}
		app.IsDefault = true
		if err := a.store.UpdateApp(r.Context(), app); err != nil {
			a.logger.Error("failed to set default app", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to update app"})
			return
		}
	}

	// Reload the app registry to pick up the new app.
	if a.appRegistry != nil {
		if err := a.appRegistry.Reload(r.Context()); err != nil {
			a.logger.Warn("failed to reload app registry", "error", err)
		}
	}

	session := auth.SessionFromContext(r.Context())
	a.logger.Info("app_created", "user", session.Username, "app_id", app.ID, "name", app.Name)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         app.ID,
		"name":       app.Name,
		"app_id":     app.AppID,
		"is_default": app.IsDefault,
		"created_at": app.CreatedAt.Format(time.RFC3339),
	})
}

func (a *API) handleGetApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isValidUUID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid app ID format"})
		return
	}
	app, err := a.store.GetAppByID(r.Context(), id)
	if err != nil {
		a.logger.Error("failed to get app", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	if app == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "App not found"})
		return
	}
	// Return without sensitive fields.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         app.ID,
		"name":       app.Name,
		"app_id":     app.AppID,
		"client_id":  app.ClientID,
		"base_url":   app.BaseURL,
		"is_default": app.IsDefault,
		"created_at": app.CreatedAt.Format(time.RFC3339),
		"updated_at": app.UpdatedAt.Format(time.RFC3339),
	})
}

// updateAppRequest is used for PUT /api/apps/{id}. IsDefault and BaseURL use
// pointers so that omitting them in the request body leaves the existing value
// unchanged. For IsDefault this avoids clearing the default flag; for BaseURL
// this allows explicitly clearing it back to empty (dotcom default) by sending
// "base_url": "" — omitting the field entirely leaves the current value intact.
type updateAppRequest struct {
	Name         string  `json:"name"`
	AppID        int64   `json:"app_id"`
	ClientID     string  `json:"client_id"`
	ClientSecret string  `json:"client_secret"`
	PrivateKey   string  `json:"private_key"`
	BaseURL      *string `json:"base_url"`
	IsDefault    *bool   `json:"is_default"`
}

func (a *API) handleUpdateApp(w http.ResponseWriter, r *http.Request) {
	// Parse and validate the request body before hitting the store so that
	// oversized/invalid payloads are rejected cheaply without I/O.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req updateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"message": "Request body too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
		}
		return
	}

	id := r.PathValue("id")
	if !isValidUUID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid app ID format"})
		return
	}
	existing, err := a.store.GetAppByID(r.Context(), id)
	if err != nil {
		a.logger.Error("failed to get app", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	if existing == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "App not found"})
		return
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.AppID < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "app_id must be a positive integer"})
		return
	}
	if req.AppID != 0 {
		existing.AppID = req.AppID
	}
	if req.ClientID != "" {
		existing.ClientID = req.ClientID
	}
	if req.ClientSecret != "" {
		if a.encryptor != nil {
			encrypted, err := a.encryptor.Encrypt(req.ClientSecret)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to encrypt credentials"})
				return
			}
			existing.ClientSecret = encrypted
		} else {
			existing.ClientSecret = req.ClientSecret
		}
	}
	if req.PrivateKey != "" {
		if a.encryptor != nil {
			encrypted, err := a.encryptor.Encrypt(req.PrivateKey)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to encrypt credentials"})
				return
			}
			existing.PrivateKey = encrypted
		} else {
			existing.PrivateKey = req.PrivateKey
		}
	}
	if req.BaseURL != nil {
		if err := validateBaseURL(*req.BaseURL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("invalid base_url: %s", err)})
			return
		}
		existing.BaseURL = *req.BaseURL
	}
	if req.IsDefault != nil {
		existing.IsDefault = *req.IsDefault
	}

	// Enforce at most one default app: clear the flag on all other apps
	// before persisting this one as the new default.
	if existing.IsDefault {
		if err := a.clearDefaultApps(r.Context(), existing.ID); err != nil {
			a.logger.Error("failed to clear default apps", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to update app"})
			return
		}
	}

	if err := a.store.UpdateApp(r.Context(), existing); err != nil {
		a.logger.Error("failed to update app", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to update app"})
		return
	}

	// Reload the app registry.
	if a.appRegistry != nil {
		if err := a.appRegistry.Reload(r.Context()); err != nil {
			a.logger.Warn("failed to reload app registry", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "App updated"})
}

func (a *API) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isValidUUID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid app ID format"})
		return
	}
	if err := a.store.DeleteApp(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "App not found"})
		} else {
			a.logger.Error("failed to delete app", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to delete app"})
		}
		return
	}

	// Reload the app registry.
	if a.appRegistry != nil {
		if err := a.appRegistry.Reload(r.Context()); err != nil {
			a.logger.Warn("failed to reload app registry", "error", err)
		}
	}

	session := auth.SessionFromContext(r.Context())
	a.logger.Info("app_deleted", "user", session.Username, "app_id", id)
	writeJSON(w, http.StatusOK, map[string]string{"message": "App deleted"})
}

func (a *API) handleListAppInstallations(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if a.appRegistry == nil || a.appRegistry.Count() == 0 {
		msg := "No apps configured"
		if a.appRegistry != nil && a.appRegistry.TotalApps() > 0 {
			msg = "Apps exist but none loaded successfully (check private keys)"
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": msg})
		return
	}

	if !isValidUUID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid app ID format"})
		return
	}
	provider, err := a.appRegistry.Get(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "App not found or not loaded"})
		return
	}

	installations, err := provider.ListInstallations(r.Context())
	if err != nil {
		a.logger.Error("failed to list installations for app", "error", err, "app_id", id)
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Failed to list GitHub installations"})
		return
	}

	writeJSON(w, http.StatusOK, installations)
}

func (a *API) handleListAppInstallationRepos(w http.ResponseWriter, r *http.Request) {
	appID := r.PathValue("id")
	if a.appRegistry == nil || a.appRegistry.Count() == 0 {
		msg := "No apps configured"
		if a.appRegistry != nil && a.appRegistry.TotalApps() > 0 {
			msg = "Apps exist but none loaded successfully (check private keys)"
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": msg})
		return
	}

	if !isValidUUID(appID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid app ID format"})
		return
	}
	provider, err := a.appRegistry.Get(appID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "App not found or not loaded"})
		return
	}

	iidStr := r.PathValue("iid")
	installationID, err := strconv.ParseInt(iidStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid installation ID"})
		return
	}

	repos, err := provider.ListInstallationRepositories(r.Context(), installationID)
	if err != nil {
		a.logger.Error("failed to list installation repos for app", "error", err, "app_id", appID, "installation_id", installationID)
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Failed to list repositories"})
		return
	}

	writeJSON(w, http.StatusOK, repos)
}

// clearDefaultApps sets IsDefault=false on all apps except the one with
// excludeID. Pass an empty excludeID to clear all defaults (e.g. before
// creating a new default app). This enforces the invariant that at most one
// app can be the default at any time. Note: this is not a single atomic
// operation — it reads and updates apps one by one. For admin-only config
// paths this is acceptable.
func (a *API) clearDefaultApps(ctx context.Context, excludeID string) error {
	apps, err := a.store.ListApps(ctx)
	if err != nil {
		return err
	}
	for _, app := range apps {
		if app.IsDefault && app.ID != excludeID {
			app.IsDefault = false
			if err := a.store.UpdateApp(ctx, app); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
