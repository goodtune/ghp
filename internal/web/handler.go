// Package web provides the management web UI and HTTP middleware for ghp.
// It serves the dashboard (token management, admin panel, audit logs) and
// applies cross-cutting concerns: security headers (CSP, X-Frame-Options),
// the Server response header identifying the ghp version, and session
// username injection for access log attribution.
package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/database"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Handler serves the web UI.
type Handler struct {
	auth      *auth.Handler
	store     database.Store
	devMode   bool
	version   string
	logger    *slog.Logger
	templates *template.Template
}

// NewHandler creates a new web UI handler. version is the build version string
// surfaced in the UI (e.g. beneath the login form) so operators can identify
// which image a deployment is running.
func NewHandler(ah *auth.Handler, store database.Store, devMode bool, version string, logger *slog.Logger) *Handler {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/*.html"))
	return &Handler{
		auth:      ah,
		store:     store,
		devMode:   devMode,
		version:   version,
		logger:    logger,
		templates: tmpl,
	}
}

// appSummary is a safe-for-template representation of an app (no secrets).
type appSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IsDefault bool   `json:"is_default"`
}

// getAppSummaries returns a list of app summaries for template rendering.
func (h *Handler) getAppSummaries(r *http.Request) []appSummary {
	apps, err := h.store.ListApps(r.Context())
	if err != nil {
		h.logger.Error("failed to list apps for UI", "error", err)
		return nil
	}
	summaries := make([]appSummary, 0, len(apps))
	for _, a := range apps {
		summaries = append(summaries, appSummary{
			ID:        a.ID,
			Name:      a.Name,
			IsDefault: a.IsDefault,
		})
	}
	return summaries
}

// RegisterRoutes adds web UI routes to the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.handleIndex)
	mux.HandleFunc("GET /login", h.handleLogin)
	mux.HandleFunc("GET /admin", h.handleAdmin)
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	session := h.auth.GetSession(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	apps := h.getAppSummaries(r)
	appsJSON, _ := json.Marshal(apps)
	data := map[string]interface{}{
		"Username": session.Username,
		"Role":     session.Role,
		"HasApps":  len(apps) > 0,
		"AppsJSON": template.JS(appsJSON),
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

	apps := h.getAppSummaries(r)
	data := map[string]interface{}{
		"Username": session.Username,
		"Role":     session.Role,
		"HasApps":  len(apps) > 0,
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

	data := map[string]interface{}{
		"Version": h.version,
	}
	if err := h.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}
