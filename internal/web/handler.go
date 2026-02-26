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
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/database"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Handler serves the web UI.
type Handler struct {
	auth          *auth.Handler
	store         database.Store
	devMode       bool
	logger        *slog.Logger
	pageTemplates map[string]*template.Template
}

// NewHandler creates a new web UI handler.
func NewHandler(ah *auth.Handler, store database.Store, devMode bool, logger *slog.Logger) *Handler {
	h := &Handler{
		auth:    ah,
		store:   store,
		devMode: devMode,
		logger:  logger,
	}
	h.initTemplates()
	return h
}

func (h *Handler) initTemplates() {
	base := template.Must(template.ParseFS(templateFS,
		"templates/base.html",
		"templates/header.html",
		"templates/token_card.html",
		"templates/empty_state.html",
	))
	pages := []string{"login.html", "dashboard.html", "admin.html", "admin-login.html"}
	h.pageTemplates = make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		t := template.Must(template.Must(base.Clone()).ParseFS(templateFS, "templates/"+page))
		h.pageTemplates[page] = t
	}
}

func (h *Handler) renderPage(w http.ResponseWriter, page string, data interface{}) error {
	t, ok := h.pageTemplates[page]
	if !ok {
		return fmt.Errorf("unknown page template: %s", page)
	}
	return t.ExecuteTemplate(w, "base", data)
}

// StaticFS returns the embedded static file system for use by the server.
func StaticFS() embed.FS {
	return staticFS
}

// RegisterRoutes adds web UI routes to the given chi router.
func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
	})
	r.Get("/dashboard/", h.handleIndex)
	r.Get("/login/", h.handleLogin)
	r.Get("/admin/", h.handleAdmin)
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	session := h.auth.GetSession(r)
	if session == nil {
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
		return
	}

	tokens, err := h.store.ListProxyTokens(r.Context(), session.UserID)
	if err != nil {
		h.logger.Error("failed to list tokens", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"ShowHeader": true,
		"DevMode":    h.devMode,
		"Username":   session.Username,
		"Role":       session.Role,
		"ActiveNav":  "dashboard",
		"Tokens":     prepareTokenCards(tokens),
	}

	if err := h.renderPage(w, "dashboard.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleAdmin(w http.ResponseWriter, r *http.Request) {
	session := h.auth.GetSession(r)
	if session == nil {
		if h.devMode {
			if err := h.renderPage(w, "admin-login.html", nil); err != nil {
				h.logger.Error("template execution failed", "error", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
			}
			return
		}
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
		return
	}
	if session.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	data := map[string]interface{}{
		"ShowHeader": true,
		"DevMode":    h.devMode,
		"Username":   session.Username,
		"Role":       session.Role,
		"ActiveNav":  "admin",
	}

	if err := h.renderPage(w, "admin.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	session := h.auth.GetSession(r)
	if session != nil {
		http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"ShowHeader": false,
		"DevMode":    h.devMode,
	}
	if err := h.renderPage(w, "login.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

// TokenCardData is the template data for a single token card.
type TokenCardData struct {
	ID          string
	RepoDisplay string
	TokenPrefix string
	TokenType   string
	SessionID   string
	IsActive    bool
	ExpiresIn   string
	ScopeList   []string
}

func prepareTokenCards(tokens []*database.ProxyToken) []TokenCardData {
	var cards []TokenCardData
	now := time.Now()
	for _, t := range tokens {
		card := TokenCardData{
			ID:          t.ID,
			TokenPrefix: t.TokenPrefix,
			TokenType:   t.TokenType,
			SessionID:   t.SessionID,
			IsActive:    t.RevokedAt == nil && t.ExpiresAt.After(now),
		}

		// Repository display
		var repos []string
		json.Unmarshal(t.Repositories, &repos)
		if len(repos) > 0 {
			card.RepoDisplay = repos[0]
			if len(repos) > 1 {
				card.RepoDisplay = fmt.Sprintf("%s (+%d)", repos[0], len(repos)-1)
			}
		}

		// Expires in
		if card.IsActive {
			hours := int(math.Ceil(time.Until(t.ExpiresAt).Hours()))
			if hours <= 1 {
				mins := int(math.Ceil(time.Until(t.ExpiresAt).Minutes()))
				card.ExpiresIn = fmt.Sprintf("%dm", mins)
			} else {
				card.ExpiresIn = fmt.Sprintf("%dh", hours)
			}
		}

		// Scopes
		var scopes map[string]string
		json.Unmarshal(t.Scopes, &scopes)
		for k, v := range scopes {
			card.ScopeList = append(card.ScopeList, k+":"+v)
		}
		sort.Strings(card.ScopeList)

		cards = append(cards, card)
	}
	return cards
}
