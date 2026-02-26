// Package web provides the embedded web UI for ghp.
package web

import (
	"bytes"
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
	"github.com/starfederation/datastar-go/datastar"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Handler serves the web UI.
type Handler struct {
	auth          *auth.Handler
	store         database.Store
	encryptor     *crypto.Encryptor
	tokenService  *token.Service
	devMode       bool
	logger        *slog.Logger
	pageTemplates map[string]*template.Template
	fragTemplates *template.Template // for fragment templates (wizard steps, modals)
}

// NewHandler creates a new web UI handler.
func NewHandler(ah *auth.Handler, store database.Store, enc *crypto.Encryptor, ts *token.Service, devMode bool, logger *slog.Logger) *Handler {
	h := &Handler{
		auth:         ah,
		store:        store,
		encryptor:    enc,
		tokenService: ts,
		devMode:      devMode,
		logger:       logger,
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

	// Fragment templates (for SSE partial updates — wizard steps, confirm dialogs)
	h.fragTemplates = template.Must(template.ParseFS(templateFS,
		"templates/token_wizard_step1.html",
		"templates/token_wizard_step2.html",
		"templates/token_wizard_step3.html",
		"templates/token_wizard_step4.html",
		"templates/token_created.html",
	))
}

func (h *Handler) renderPage(w http.ResponseWriter, page string, data interface{}) error {
	t, ok := h.pageTemplates[page]
	if !ok {
		return fmt.Errorf("unknown page template: %s", page)
	}
	return t.ExecuteTemplate(w, "base", data)
}

func (h *Handler) renderFragment(name string, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := h.fragTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// StaticFS returns the embedded static file system for use by the server.
func StaticFS() embed.FS {
	return staticFS
}

// requireAuthWeb is middleware that redirects unauthenticated users to the login page.
func (h *Handler) requireAuthWeb(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := h.auth.GetSession(r)
		if session == nil {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		ctx := auth.ContextWithSession(r.Context(), session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RegisterRoutes adds web UI routes to the given chi router.
func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
	})
	r.Get("/login/", h.handleLogin)
	r.Get("/admin/", h.handleAdmin)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(h.requireAuthWeb)
		r.Get("/dashboard/", h.handleDashboard)
		r.Get("/dashboard/token/add/", h.handleWizardGet)
		r.Post("/dashboard/token/add/", h.handleWizardPost)
	})
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

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

// --- Token Wizard Handlers ---

func (h *Handler) handleWizardGet(w http.ResponseWriter, r *http.Request) {
	// Returns step 1 via SSE + opens modal
	sse := datastar.NewSSE(w, r)

	data := map[string]interface{}{
		"Repository": "",
	}
	html, err := h.renderFragment("wizard_step1", data)
	if err != nil {
		h.logger.Error("render wizard step1 failed", "error", err)
		return
	}

	sse.PatchSignals([]byte(`{"modalOpen":true}`))
	sse.PatchElements(html, datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
}

func (h *Handler) handleWizardPost(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	r.ParseForm()
	state, _ := getWizardCookie(r, h.encryptor)

	isBack := r.FormValue("back") == "true"
	stepStr := r.FormValue("step")

	if isBack {
		// Go back one step
		switch stepStr {
		case "2":
			state.Step = 1
		case "3":
			state.Step = 2
		case "4":
			state.Step = 3
		}
	} else {
		// Process current step and advance
		switch state.Step {
		case 0, 1:
			state.Repository = r.FormValue("repository")
			state.Step = 2
		case 2:
			state.Permissions = h.collectPermissions(r)
			state.Step = 3
		case 3:
			state.Duration = r.FormValue("duration")
			if state.Duration == "" {
				state.Duration = "24h"
			}
			state.SessionID = r.FormValue("session_id")
			state.Step = 4
		case 4:
			// Final submission — create the token
			h.createTokenFromWizard(w, r, session, state)
			return
		}
	}

	setWizardCookie(w, h.encryptor, state)

	sse := datastar.NewSSE(w, r)
	data := h.wizardStepData(state)
	tmplName := fmt.Sprintf("wizard_step%d", state.Step)
	html, err := h.renderFragment(tmplName, data)
	if err != nil {
		h.logger.Error("render wizard step failed", "error", err, "step", state.Step)
		return
	}
	sse.PatchElements(html, datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
}

func (h *Handler) collectPermissions(r *http.Request) map[string]string {
	perms := make(map[string]string)
	for _, p := range token.CommonPermissions() {
		val := r.FormValue("perm_" + p.Key)
		if val != "" {
			perms[p.Key] = val
		}
	}
	// Also check all permissions fields
	for _, p := range token.AllPermissions() {
		val := r.FormValue("perm_" + p.Key)
		if val != "" {
			perms[p.Key] = val
		}
	}
	return perms
}

// PermissionDisplay is used by the wizard step 2 template.
type PermissionDisplay struct {
	Key          string
	DisplayName  string
	Description  string
	ReadOnly     bool   // true for metadata
	CurrentValue string // "read", "write", or "" (no access)
}

func (h *Handler) wizardStepData(state *WizardState) map[string]interface{} {
	data := map[string]interface{}{
		"Repository": state.Repository,
		"Duration":   state.Duration,
		"SessionID":  state.SessionID,
	}

	// Permissions for step 2
	var perms []PermissionDisplay
	for _, p := range token.CommonPermissions() {
		pd := PermissionDisplay{
			Key:         p.Key,
			DisplayName: p.DisplayName,
			Description: p.Description,
			ReadOnly:    len(p.Levels) == 1 && p.Levels[0] == "read",
		}
		if state.Permissions != nil {
			pd.CurrentValue = state.Permissions[p.Key]
		}
		// Default metadata to "read"
		if p.Key == "metadata" && pd.CurrentValue == "" {
			pd.CurrentValue = "read"
		}
		perms = append(perms, pd)
	}
	data["Permissions"] = perms

	// Scope list for step 4 summary
	var scopeList []string
	for k, v := range state.Permissions {
		scopeList = append(scopeList, k+":"+v)
	}
	sort.Strings(scopeList)
	data["ScopeList"] = scopeList

	return data
}

func (h *Handler) createTokenFromWizard(w http.ResponseWriter, r *http.Request, session *auth.Session, state *WizardState) {
	dur, err := time.ParseDuration(state.Duration)
	if err != nil {
		dur = 24 * time.Hour
	}

	// Look up the user's GitHub token for proxy token creation
	ghToken, err := h.store.GetGitHubToken(r.Context(), session.UserID)
	if err != nil {
		h.logger.Error("failed to get github token", "error", err)
		sse := datastar.NewSSE(w, r)
		sse.PatchElements(`<div class="wizard-error">Failed to create token: no GitHub token found. Please re-authenticate.</div>`,
			datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
		return
	}

	req := token.CreateRequest{
		TokenType:     token.TokenTypeProxy,
		UserID:        session.UserID,
		GitHubTokenID: ghToken.ID,
		Repository:    state.Repository,
		Scopes:        state.Permissions,
		Duration:      dur,
		SessionID:     state.SessionID,
	}

	result, err := h.tokenService.Create(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to create token", "error", err)
		sse := datastar.NewSSE(w, r)
		sse.PatchElements(fmt.Sprintf(`<div class="wizard-error">Failed to create token: %s</div>`, template.HTMLEscapeString(err.Error())),
			datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
		return
	}

	clearWizardCookie(w)

	sse := datastar.NewSSE(w, r)
	html, err := h.renderFragment("token_created", map[string]interface{}{
		"Token": result.Token,
	})
	if err != nil {
		h.logger.Error("render token_created failed", "error", err)
		return
	}
	sse.PatchElements(html, datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
}

// --- Token Card Helpers ---

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
