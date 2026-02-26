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
	"strings"
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
		"templates/admin_layout.html",
	))
	pages := []string{"login.html", "dashboard.html", "admin_users.html", "admin_user_detail.html", "admin_tokens.html", "logout.html"}
	h.pageTemplates = make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		t := template.Must(template.Must(base.Clone()).ParseFS(templateFS, "templates/"+page))
		h.pageTemplates[page] = t
	}

	// Fragment templates (for SSE partial updates — wizard steps, confirm dialogs)
	h.fragTemplates = template.Must(template.ParseFS(templateFS,
		"templates/token_card.html",
		"templates/token_wizard_step1.html",
		"templates/token_wizard_step2.html",
		"templates/token_wizard_step3.html",
		"templates/token_wizard_step4.html",
		"templates/token_created.html",
		"templates/revoke_confirm.html",
		"templates/admin_tokens.html",
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

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(h.requireAuthWeb)
		r.Get("/dashboard/", h.handleDashboard)
		r.Get("/dashboard/token/add/", h.handleWizardGet)
		r.Post("/dashboard/token/add/", h.handleWizardPost)
		r.Get("/dashboard/token/{id}/revoke/", h.handleRevokeConfirm)
		r.Post("/dashboard/token/{id}/revoke/", h.handleRevoke)
		r.Get("/logout/", h.handleLogoutConfirm)
		r.Post("/logout/", h.handleLogoutExecute)
	})

	// Admin routes
	r.Group(func(r chi.Router) {
		r.Use(h.requireAuthWeb)
		r.Use(h.requireAdminWeb)

		r.Get("/admin/", h.handleAdminUsers)
		r.Get("/admin/tokens/", h.handleAdminTokens)
		r.Get("/admin/tokens/add/", h.handleAdminWizardGet)
		r.Post("/admin/tokens/add/", h.handleAdminWizardPost)
		r.Get("/admin/tokens/{id}/revoke/", h.handleAdminTokenRevokeConfirm)
		r.Post("/admin/tokens/{id}/revoke/", h.handleAdminTokenRevoke)
		r.Get("/admin/{username}/", h.handleAdminUserDetail)
		r.Get("/admin/{username}/{id}/revoke/", h.handleAdminUserTokenRevokeConfirm)
		r.Post("/admin/{username}/{id}/revoke/", h.handleAdminUserTokenRevoke)
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

// --- Admin Data Types ---

// AdminTokenData extends TokenCardData with username for the admin tokens table.
type AdminTokenData struct {
	TokenCardData
	Username string
}

// UserDisplay is template data for the admin users table.
type UserDisplay struct {
	GitHubUsername     string
	Role               string
	CreatedAtFormatted string
}

// requireAdminWeb is middleware that restricts access to admin users.
func (h *Handler) requireAdminWeb(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil || session.Role != "admin" {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		h.logger.Error("failed to list users", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	var userDisplays []UserDisplay
	for _, u := range users {
		userDisplays = append(userDisplays, UserDisplay{
			GitHubUsername:     u.GitHubUsername,
			Role:               u.Role,
			CreatedAtFormatted: u.CreatedAt.Format("2 Jan 2006"),
		})
	}

	data := map[string]interface{}{
		"ShowHeader": true,
		"DevMode":    h.devMode,
		"Username":   session.Username,
		"Role":       session.Role,
		"ActiveNav":  "admin",
		"ActiveTab":  "users",
		"Users":      userDisplays,
	}
	if err := h.renderPage(w, "admin_users.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	username := chi.URLParam(r, "username")

	// Find user by username
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		h.logger.Error("failed to list users", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	var targetUser *database.User
	for _, u := range users {
		if u.GitHubUsername == username {
			targetUser = u
			break
		}
	}
	if targetUser == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	tokens, err := h.store.ListProxyTokens(r.Context(), targetUser.ID)
	if err != nil {
		h.logger.Error("failed to list tokens", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	cards := prepareTokenCards(tokens)

	data := map[string]interface{}{
		"ShowHeader":   true,
		"DevMode":      h.devMode,
		"Username":     session.Username,
		"Role":         session.Role,
		"ActiveNav":    "admin",
		"ActiveTab":    "users",
		"ViewUsername": username,
		"Tokens":       cards,
	}
	if err := h.renderPage(w, "admin_user_detail.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleAdminTokens(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	// Read filter params
	filterStatus := r.URL.Query().Get("status")
	if filterStatus == "" && !r.URL.Query().Has("status") {
		filterStatus = "active" // default to active
	}
	filterUser := r.URL.Query().Get("user")
	filterRepo := r.URL.Query().Get("repo")
	filterScope := r.URL.Query().Get("scope")

	allTokens, err := h.store.ListAllProxyTokens(r.Context())
	if err != nil {
		h.logger.Error("failed to list all tokens", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Get users for username lookup
	users, _ := h.store.ListUsers(r.Context())
	userMap := make(map[string]string) // userID -> username
	for _, u := range users {
		userMap[u.ID] = u.GitHubUsername
	}

	now := time.Now()
	var filtered []*database.ProxyToken
	for _, t := range allTokens {
		// Status filter
		isActive := t.RevokedAt == nil && t.ExpiresAt.After(now)
		if filterStatus == "active" && !isActive {
			continue
		}
		if filterStatus == "revoked" && isActive {
			continue
		}

		// Username filter
		if filterUser != "" {
			uid := ""
			if t.UserID != nil {
				uid = *t.UserID
			}
			uname, ok := userMap[uid]
			if !ok || !strings.Contains(strings.ToLower(uname), strings.ToLower(filterUser)) {
				continue
			}
		}

		// Repo filter
		if filterRepo != "" {
			var repos []string
			json.Unmarshal(t.Repositories, &repos)
			found := false
			for _, repo := range repos {
				if strings.Contains(strings.ToLower(repo), strings.ToLower(filterRepo)) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Scope filter
		if filterScope != "" {
			var scopes map[string]string
			json.Unmarshal(t.Scopes, &scopes)
			found := false
			for k, v := range scopes {
				if strings.Contains(k+":"+v, filterScope) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		filtered = append(filtered, t)
	}

	cards := prepareTokenCards(filtered)
	var adminTokens []AdminTokenData
	for i, card := range cards {
		username := ""
		if filtered[i].UserID != nil {
			username = userMap[*filtered[i].UserID]
		}
		adminTokens = append(adminTokens, AdminTokenData{
			TokenCardData: card,
			Username:      username,
		})
	}

	data := map[string]interface{}{
		"ShowHeader":   true,
		"DevMode":      h.devMode,
		"Username":     session.Username,
		"Role":         session.Role,
		"ActiveNav":    "admin",
		"ActiveTab":    "tokens",
		"Tokens":       adminTokens,
		"FilterStatus": filterStatus,
		"FilterUser":   filterUser,
		"FilterRepo":   filterRepo,
		"FilterScope":  filterScope,
	}

	// Check if this is a Datastar SSE request (has Accept: text/event-stream)
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		sse := datastar.NewSSE(w, r)
		html, err := h.renderFragment("admin_tokens_table", data)
		if err != nil {
			h.logger.Error("render admin tokens table failed", "error", err)
			return
		}
		sse.PatchElements(html, datastar.WithSelectorID("admin-tokens-table"), datastar.WithModeInner())
		return
	}

	if err := h.renderPage(w, "admin_tokens.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

// --- Admin Revoke Handlers ---

func (h *Handler) handleAdminTokenRevokeConfirm(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "id")
	tok, err := h.store.GetProxyTokenByID(r.Context(), tokenID)
	if err != nil {
		h.logger.Error("failed to get token", "error", err)
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	cards := prepareTokenCards([]*database.ProxyToken{tok})
	data := map[string]interface{}{
		"ID":          tok.ID,
		"RepoDisplay": cards[0].RepoDisplay,
		"TokenPrefix": tok.TokenPrefix,
		"RevokeURL":   "/admin/tokens/" + tok.ID + "/revoke/",
	}

	sse := datastar.NewSSE(w, r)
	html, err := h.renderFragment("revoke_confirm", data)
	if err != nil {
		h.logger.Error("render revoke_confirm failed", "error", err)
		return
	}
	sse.PatchSignals([]byte(`{"modalOpen":true}`))
	sse.PatchElements(html, datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
}

func (h *Handler) handleAdminTokenRevoke(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "id")
	if err := h.store.RevokeProxyToken(r.Context(), tokenID); err != nil {
		h.logger.Error("failed to revoke token", "error", err)
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	sse := datastar.NewSSE(w, r)
	sse.PatchSignals([]byte(`{"modalOpen":false}`))
	sse.PatchElements(`<script>window.location.reload()</script>`, datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
}

// handleAdminUserTokenRevokeConfirm handles revoke confirm from the user detail page.
func (h *Handler) handleAdminUserTokenRevokeConfirm(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "id")
	username := chi.URLParam(r, "username")
	tok, err := h.store.GetProxyTokenByID(r.Context(), tokenID)
	if err != nil {
		h.logger.Error("failed to get token", "error", err)
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	cards := prepareTokenCards([]*database.ProxyToken{tok})
	data := map[string]interface{}{
		"ID":          tok.ID,
		"RepoDisplay": cards[0].RepoDisplay,
		"TokenPrefix": tok.TokenPrefix,
		"RevokeURL":   "/admin/" + username + "/" + tok.ID + "/revoke/",
	}

	sse := datastar.NewSSE(w, r)
	html, err := h.renderFragment("revoke_confirm", data)
	if err != nil {
		h.logger.Error("render revoke_confirm failed", "error", err)
		return
	}
	sse.PatchSignals([]byte(`{"modalOpen":true}`))
	sse.PatchElements(html, datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
}

// handleAdminUserTokenRevoke handles revoke execution from the user detail page.
func (h *Handler) handleAdminUserTokenRevoke(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "id")
	if err := h.store.RevokeProxyToken(r.Context(), tokenID); err != nil {
		h.logger.Error("failed to revoke token", "error", err)
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	sse := datastar.NewSSE(w, r)
	sse.PatchSignals([]byte(`{"modalOpen":false}`))
	sse.PatchElements(`<script>window.location.reload()</script>`, datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
}

// handleAdminWizardGet reuses the user wizard for admin token creation.
func (h *Handler) handleAdminWizardGet(w http.ResponseWriter, r *http.Request) {
	h.handleWizardGet(w, r)
}

// handleAdminWizardPost reuses the user wizard for admin token creation.
func (h *Handler) handleAdminWizardPost(w http.ResponseWriter, r *http.Request) {
	h.handleWizardPost(w, r)
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

// --- Revoke Handlers ---

func (h *Handler) handleRevokeConfirm(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "id")
	tok, err := h.store.GetProxyTokenByID(r.Context(), tokenID)
	if err != nil {
		h.logger.Error("failed to get token", "error", err)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Verify ownership
	session := auth.SessionFromContext(r.Context())
	if tok.UserID == nil || *tok.UserID != session.UserID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	cards := prepareTokenCards([]*database.ProxyToken{tok})
	data := map[string]interface{}{
		"ID":          tok.ID,
		"RepoDisplay": cards[0].RepoDisplay,
		"TokenPrefix": tok.TokenPrefix,
		"RevokeURL":   "/dashboard/token/" + tok.ID + "/revoke/",
	}

	sse := datastar.NewSSE(w, r)
	html, err := h.renderFragment("revoke_confirm", data)
	if err != nil {
		h.logger.Error("render revoke_confirm failed", "error", err)
		return
	}
	sse.PatchSignals([]byte(`{"modalOpen":true}`))
	sse.PatchElements(html, datastar.WithSelectorID("modal-content"), datastar.WithModeInner())
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "id")
	tok, err := h.store.GetProxyTokenByID(r.Context(), tokenID)
	if err != nil {
		h.logger.Error("failed to get token", "error", err)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Verify ownership
	session := auth.SessionFromContext(r.Context())
	if tok.UserID == nil || *tok.UserID != session.UserID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := h.store.RevokeProxyToken(r.Context(), tokenID); err != nil {
		h.logger.Error("failed to revoke token", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Re-fetch to get updated state
	tok, err = h.store.GetProxyTokenByID(r.Context(), tokenID)
	if err != nil {
		h.logger.Error("failed to re-fetch token", "error", err)
		return
	}

	cards := prepareTokenCards([]*database.ProxyToken{tok})

	sse := datastar.NewSSE(w, r)
	sse.PatchSignals([]byte(`{"modalOpen":false}`))

	if len(cards) > 0 {
		html, err := h.renderFragment("token_card", cards[0])
		if err != nil {
			h.logger.Error("render token_card failed", "error", err)
			return
		}
		sse.PatchElements(html, datastar.WithSelectorID("token-"+tokenID))
	}
}

// --- Logout Handlers ---

func (h *Handler) handleLogoutConfirm(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	data := map[string]interface{}{
		"ShowHeader": true,
		"DevMode":    h.devMode,
		"Username":   session.Username,
		"Role":       session.Role,
		"ActiveNav":  "",
	}
	if err := h.renderPage(w, "logout.html", data); err != nil {
		h.logger.Error("template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleLogoutExecute(w http.ResponseWriter, r *http.Request) {
	h.auth.Logout(w, r)
	http.Redirect(w, r, "/login/", http.StatusSeeOther)
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
