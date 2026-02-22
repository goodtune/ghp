// Package server wires up the HTTP server with all routes.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	ghub "github.com/google/go-github/v68/github"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	ghpgithub "github.com/goodtune/ghp/internal/github"
	"github.com/goodtune/ghp/internal/token"
)

// API handles the service API endpoints (token management, users, audit).
type API struct {
	cfg              *config.Config
	store            database.Store
	tokenService     *token.Service
	authHandler      *auth.Handler
	encryptor        *crypto.Encryptor
	appTokenProvider *ghpgithub.AppTokenProvider // nil if GitHub App not configured
	logger           *slog.Logger
}

// NewAPI creates a new API handler.
func NewAPI(cfg *config.Config, store database.Store, ts *token.Service, ah *auth.Handler, enc *crypto.Encryptor, atp *ghpgithub.AppTokenProvider, logger *slog.Logger) *API {
	return &API{
		cfg:              cfg,
		store:            store,
		tokenService:     ts,
		authHandler:      ah,
		encryptor:        enc,
		appTokenProvider: atp,
		logger:           logger,
	}
}

// RegisterRoutes adds API routes to the given mux.
// All routes require authentication via the auth handler.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/tokens", a.authHandler.RequireAuth(http.HandlerFunc(a.handleCreateToken)))
	mux.Handle("GET /api/tokens", a.authHandler.RequireAuth(http.HandlerFunc(a.handleListTokens)))
	mux.Handle("GET /api/tokens/{id}", a.authHandler.RequireAuth(http.HandlerFunc(a.handleGetToken)))
	mux.Handle("DELETE /api/tokens/{id}", a.authHandler.RequireAuth(http.HandlerFunc(a.handleRevokeToken)))

	mux.Handle("GET /api/users", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListUsers)))
	mux.Handle("GET /api/users/{id}/tokens", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListUserTokens)))

	mux.Handle("GET /api/github/repositories", a.authHandler.RequireAuth(http.HandlerFunc(a.handleListUserRepos)))
	mux.Handle("GET /api/github/installations", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListInstallations)))
	mux.Handle("GET /api/github/installations/{id}/repositories", a.authHandler.RequireAdmin(http.HandlerFunc(a.handleListInstallationRepos)))

	mux.Handle("GET /api/audit", a.authHandler.RequireAuth(http.HandlerFunc(a.handleListAudit)))
}

type createTokenRequest struct {
	Type           string   `json:"type"`
	Repository     string   `json:"repository"`
	Repositories   []string `json:"repositories"`
	InstallationID int64    `json:"installation_id"`
	Scopes         string   `json:"scopes"`
	Duration       string   `json:"duration"`
	SessionID      string   `json:"session_id"`
}

func (a *API) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
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

	scopes, err := token.ParseScopeString(req.Scopes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
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

	createReq := token.CreateRequest{
		TokenType: tt,
		UserID:    session.UserID,
		Scopes:    scopes,
		Duration:  duration,
		SessionID: req.SessionID,
	}

	switch tt {
	case token.TokenTypeProxy:
		gt, err := a.store.GetGitHubToken(r.Context(), session.UserID)
		if err != nil || gt == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "No GitHub token found. Please re-authenticate."})
			return
		}
		createReq.GitHubTokenID = gt.ID
		createReq.Repository = req.Repository
	case token.TokenTypeAgent:
		createReq.InstallationID = req.InstallationID
		createReq.Repositories = req.Repositories
	}

	result, err := a.tokenService.Create(r.Context(), createReq)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	// Audit log.
	a.store.CreateAuditEntry(r.Context(), &database.AuditEntry{
		UserID:    session.UserID,
		Action:    "token_created",
		SessionID: req.SessionID,
	})

	a.logger.Info("token_created",
		"user", session.Username,
		"type", string(tt),
		"repos", result.Repositories,
		"session", req.SessionID,
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

	// Audit log.
	a.store.CreateAuditEntry(r.Context(), &database.AuditEntry{
		UserID: session.UserID,
		Action: "token_revoked",
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

func (a *API) handleListAudit(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	filter := database.AuditFilter{
		Repository: r.URL.Query().Get("repository"),
		TokenID:    r.URL.Query().Get("token_id"),
		Action:     r.URL.Query().Get("action"),
		Limit:      100,
	}

	// Non-admins can only see their own audit entries.
	if session.Role != "admin" {
		filter.UserID = session.UserID
	} else if uid := r.URL.Query().Get("user_id"); uid != "" {
		filter.UserID = uid
	}

	entries, err := a.store.ListAuditEntries(r.Context(), filter)
	if err != nil {
		a.logger.Error("failed to list audit entries", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	if entries == nil {
		entries = []*database.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
