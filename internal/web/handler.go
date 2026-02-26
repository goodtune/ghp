// Package web provides the embedded web UI for ghp.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/goodtune/ghp/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Handler serves the web UI.
type Handler struct {
	auth          *auth.Handler
	devMode       bool
	logger        *slog.Logger
	pageTemplates map[string]*template.Template
}

// NewHandler creates a new web UI handler.
func NewHandler(ah *auth.Handler, devMode bool, logger *slog.Logger) *Handler {
	h := &Handler{
		auth:    ah,
		devMode: devMode,
		logger:  logger,
	}
	h.initTemplates()
	return h
}

func (h *Handler) initTemplates() {
	base := template.Must(template.ParseFS(templateFS, "templates/base.html", "templates/header.html"))
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

	data := map[string]interface{}{
		"ShowHeader": true,
		"DevMode":    h.devMode,
		"Username":   session.Username,
		"Role":       session.Role,
		"ActiveNav":  "dashboard",
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
