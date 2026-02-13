// Package server wires up the HTTP server with all routes.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// API handles the service API endpoints (token management, users, audit).
type API struct {
	cfg          *config.Config
	store        database.Store
	tokenService *token.Service
	authHandler  *auth.Handler
	logger       *slog.Logger
}

// NewAPI creates a new API handler.
func NewAPI(cfg *config.Config, store database.Store, ts *token.Service, ah *auth.Handler, logger *slog.Logger) *API {
	return &API{
		cfg:          cfg,
		store:        store,
		tokenService: ts,
		authHandler:  ah,
		logger:       logger,
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

	mux.Handle("GET /api/audit", a.authHandler.RequireAuth(http.HandlerFunc(a.handleListAudit)))
}

type createTokenRequest struct {
	Repository string `json:"repository"`
	Scopes     string `json:"scopes"`
	Duration   string `json:"duration"`
	SessionID  string `json:"session_id"`
}

func (a *API) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
		return
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

	// Get the user's GitHub token.
	gt, err := a.store.GetGitHubToken(r.Context(), session.UserID)
	if err != nil || gt == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "No GitHub token found. Please re-authenticate."})
		return
	}

	result, err := a.tokenService.Create(r.Context(), token.CreateRequest{
		UserID:        session.UserID,
		GitHubTokenID: gt.ID,
		Repository:    req.Repository,
		Scopes:        scopes,
		Duration:      duration,
		SessionID:     req.SessionID,
	})
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
		"repo", req.Repository,
		"session", req.SessionID,
	)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":      result.Token,
		"id":         result.ID,
		"repository": result.Repository,
		"scopes":     result.Scopes,
		"expires_at": result.ExpiresAt.Format(time.RFC3339),
		"session_id": result.SessionID,
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
	if pt.UserID != session.UserID && session.Role != "admin" {
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
	if pt.UserID != session.UserID && session.Role != "admin" {
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
