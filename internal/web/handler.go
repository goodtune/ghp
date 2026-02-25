// Package web provides the embedded web UI for ghp.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// tokenNotifier broadcasts token change events to admin SSE connections.
// Uses the close-and-replace channel pattern for fan-out notification.
type tokenNotifier struct {
	mu sync.Mutex
	ch chan struct{}
}

func newTokenNotifier() *tokenNotifier {
	return &tokenNotifier{ch: make(chan struct{})}
}

// Wait returns a channel that will be closed on the next Notify call.
func (n *tokenNotifier) Wait() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ch
}

// Notify wakes all goroutines waiting on the current channel.
func (n *tokenNotifier) Notify() {
	n.mu.Lock()
	defer n.mu.Unlock()
	close(n.ch)
	n.ch = make(chan struct{})
}

// Handler serves the web UI.
type Handler struct {
	auth            *auth.Handler
	store           database.Store
	tokenService    *token.Service
	defaultDuration time.Duration
	devMode         bool
	logger          *slog.Logger
	templates       *template.Template
	tokenNotify     *tokenNotifier
}

// TokenView is a server-side view model for a proxy token.
type TokenView struct {
	ID         string
	Prefix     string
	Type       string // "proxy" or "agent"
	Repos      string
	Scopes     []string
	SessionID  string
	Status     string // "active", "expired", "revoked"
	ExpiryText string // "Expires in 6h", "Expired 2d ago", "Revoked"
	RawID      string // for revoke action
}

// UserView is a server-side view model for a user.
type UserView struct {
	ID       string
	Username string
	Role     string
	Created  string
}

// NewHandler creates a new web UI handler.
func NewHandler(ah *auth.Handler, store database.Store, ts *token.Service, defaultDuration time.Duration, devMode bool, logger *slog.Logger) *Handler {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/*.html"))
	return &Handler{
		auth:            ah,
		store:           store,
		tokenService:    ts,
		defaultDuration: defaultDuration,
		devMode:         devMode,
		logger:          logger,
		templates:       tmpl,
		tokenNotify:     newTokenNotifier(),
	}
}

// RegisterRoutes adds web UI routes to the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Page routes (full HTML).
	mux.HandleFunc("GET /{$}", h.handleIndex)
	mux.HandleFunc("GET /login", h.handleLogin)
	mux.HandleFunc("GET /admin", h.handleAdmin)
	mux.Handle("GET /static/", http.FileServerFS(staticFS))

	// SSE routes (Datastar fragments).
	mux.Handle("GET /ui/dashboard/stream", h.auth.RequireAuth(http.HandlerFunc(h.handleDashboardStreamSSE)))
	mux.Handle("GET /ui/stepper/{step}", h.auth.RequireAuth(http.HandlerFunc(h.handleStepperSSE)))
	mux.Handle("POST /ui/stepper/{step}", h.auth.RequireAuth(http.HandlerFunc(h.handleStepperSSE)))
	mux.Handle("DELETE /ui/tokens/{id}", h.auth.RequireAuth(http.HandlerFunc(h.handleRevokeTokenSSE)))
	mux.Handle("POST /ui/tokens", h.auth.RequireAuth(http.HandlerFunc(h.handleCreateTokenSSE)))
	mux.Handle("POST /ui/agent-tokens", h.auth.RequireAdmin(http.HandlerFunc(h.handleCreateAgentTokenSSE)))
	mux.Handle("POST /ui/logout", h.auth.RequireAuth(http.HandlerFunc(h.handleLogoutSSE)))
	mux.Handle("GET /ui/admin/stream", h.auth.RequireAdmin(http.HandlerFunc(h.handleAdminStreamSSE)))
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	session := h.auth.GetSession(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tokens, err := h.store.ListProxyTokens(r.Context(), session.UserID)
	if err != nil {
		h.logger.Error("failed to list tokens", "error", err)
		tokens = nil
	}

	data := map[string]interface{}{
		"Username": session.Username,
		"Role":     session.Role,
		"Page":     "dashboard",
		"Tokens":   buildTokenViews(tokens),
		"DevMode":  h.devMode,
	}

	if err := h.templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleAdmin(w http.ResponseWriter, r *http.Request) {
	session := h.auth.GetSession(r)
	if session == nil {
		if h.devMode {
			if err := h.templates.ExecuteTemplate(w, "admin-login.html", nil); err != nil {
				h.logger.Error("template execution failed", "error", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
			}
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if session.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	data := map[string]interface{}{
		"Username": session.Username,
		"Role":     session.Role,
		"Page":     "admin",
	}

	if err := h.templates.ExecuteTemplate(w, "admin.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	session := h.auth.GetSession(r)
	if session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := h.templates.ExecuteTemplate(w, "login.html", nil); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

// buildTokenViews converts database tokens into template-friendly view models.
func buildTokenViews(tokens []*database.ProxyToken) []TokenView {
	views := make([]TokenView, 0, len(tokens))
	now := time.Now()

	for _, t := range tokens {
		var status, expiryText string
		if t.RevokedAt != nil {
			status = "revoked"
			expiryText = "Revoked"
		} else if t.ExpiresAt.Before(now) {
			status = "expired"
			expiryText = "Expired " + formatRelative(now.Sub(t.ExpiresAt)) + " ago"
		} else {
			status = "active"
			expiryText = "Expires in " + formatRelative(t.ExpiresAt.Sub(now))
		}

		// Parse repos from JSON.
		var repos []string
		_ = json.Unmarshal(t.Repositories, &repos)
		repoStr := ""
		for i, r := range repos {
			if i > 0 {
				repoStr += ", "
			}
			repoStr += r
		}

		// Parse scopes from JSON.
		var scopeMap map[string]string
		_ = json.Unmarshal(t.Scopes, &scopeMap)
		scopes := make([]string, 0, len(scopeMap))
		for k, v := range scopeMap {
			scopes = append(scopes, k+":"+v)
		}
		sort.Strings(scopes)

		tokenType := t.TokenType
		if tokenType == "" {
			tokenType = "proxy"
		}

		views = append(views, TokenView{
			ID:         t.ID,
			Prefix:     t.TokenPrefix,
			Type:       tokenType,
			Repos:      repoStr,
			Scopes:     scopes,
			SessionID:  t.SessionID,
			Status:     status,
			ExpiryText: expiryText,
			RawID:      t.ID,
		})
	}

	return views
}

// buildUserViews converts database users into template-friendly view models.
func buildUserViews(users []*database.User) []UserView {
	views := make([]UserView, 0, len(users))
	for _, u := range users {
		views = append(views, UserView{
			ID:       u.ID,
			Username: u.GitHubUsername,
			Role:     u.Role,
			Created:  u.CreatedAt.Format("2 Jan 2006"),
		})
	}
	return views
}

// formatRelative produces a human-readable relative duration like "6h", "3d", "5m".
func formatRelative(d time.Duration) string {
	days := int(math.Floor(d.Hours() / 24))
	hours := int(math.Floor(d.Hours()))
	minutes := int(math.Floor(d.Minutes()))

	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return "<1m"
}
