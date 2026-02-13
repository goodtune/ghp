// Package web provides the embedded web UI for ghp.
package web

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/goodtune/ghp/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Handler serves the web UI.
type Handler struct {
	auth      *auth.Handler
	devMode   bool
	logger    *slog.Logger
	templates *template.Template
}

// NewHandler creates a new web UI handler.
func NewHandler(ah *auth.Handler, devMode bool, logger *slog.Logger) *Handler {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/*.html"))
	return &Handler{
		auth:      ah,
		devMode:   devMode,
		logger:    logger,
		templates: tmpl,
	}
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

	data := map[string]interface{}{
		"Username": session.Username,
		"Role":     session.Role,
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
