package web

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/starfederation/datastar-go/datastar"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// defaultProxyPermissions are the standard proxy token permissions used in dev mode.
var defaultProxyPermissions = map[string]string{
	"contents": "write", "pulls": "write", "issues": "write",
	"statuses": "write", "checks": "write", "actions": "write", "metadata": "read",
}

// ── Fragment templates rendered by SSE handlers ──────────────────────

var fragmentTemplates = template.Must(template.New("fragments").Parse(`
{{- define "token-card" -}}
<article class="token-card" id="token-{{ .RawID }}">
    <div class="token-card-header">
        <div>
            <h3 class="token-card-repo">{{ .Repos }}</h3>
            <span class="token-card-prefix">{{ .Prefix }}...</span>
        </div>
        <span class="status status-{{ .Status }}">
            <span class="status-dot"></span>
            {{ .ExpiryText }}
        </span>
    </div>
    <ul class="token-card-scopes">
        {{ range .Scopes }}
        <li class="scope-chip">{{ . }}</li>
        {{ end }}
    </ul>
    {{ if .SessionID }}
    <p class="token-card-session">{{ .SessionID }}</p>
    {{ end }}
    <footer class="token-card-footer">
        <span class="token-card-meta">{{ .Type }}</span>
    </footer>
</article>
{{- end -}}

{{- define "token-row" -}}
<tr id="token-row-{{ .RawID }}">
    <td class="text-mono">{{ .Prefix }}...</td>
    <td><span class="badge badge-{{ .Type }}">{{ .Type }}</span></td>
    <td>{{ .Repos }}</td>
    <td>{{ range .Scopes }}<span class="scope-chip">{{ . }}</span> {{ end }}</td>
    <td>{{ if .SessionID }}{{ .SessionID }}{{ else }}-{{ end }}</td>
    <td><span class="badge badge-{{ .Status }}">{{ .Status }}</span></td>
    <td>{{ .ExpiryText }}</td>
    <td></td>
</tr>
{{- end -}}

{{- define "token-created" -}}
<div id="step-confirm">
    <div class="token-display" onclick="navigator.clipboard.writeText(this.textContent.trim());this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),2000)">{{ .Token }}</div>
    <p class="token-warning">This token will only be shown once. Click to copy.</p>
</div>
{{- end -}}

{{- define "stepper-dots" -}}
<div class="stepper-dots">
    <span class="stepper-dot{{ if eq .Step 0 }} active{{ end }}{{ if gt .Step 0 }} completed{{ end }}"></span>
    <span class="stepper-dot{{ if eq .Step 1 }} active{{ end }}{{ if gt .Step 1 }} completed{{ end }}"></span>
    <span class="stepper-dot{{ if eq .Step 2 }} active{{ end }}{{ if gt .Step 2 }} completed{{ end }}"></span>
    <span class="stepper-dot{{ if eq .Step 3 }} active{{ end }}"></span>
</div>
{{- end -}}

{{- define "stepper-0" -}}
<div id="stepper-content">
    {{ template "stepper-dots" . }}
    <h3 class="stepper-title">Select Repository</h3>
    <div class="form-group">
        <label>Repository</label>
        {{ if .DevMode }}
        <input type="text" id="repo-input" placeholder="owner/repo" data-bind:repo>
        {{ else }}
        <ghp-repo-select id="repo-select" mode="single" placeholder="Loading repositories..."></ghp-repo-select>
        <input type="hidden" id="repo-signal" data-bind:repo>
        {{ end }}
    </div>
    {{ if .Error }}<p class="form-error">{{ .Error }}</p>{{ end }}
    <div class="stepper-actions">
        <span></span>
        {{ if .DevMode }}
        <button class="btn btn-primary" data-on:click="@post('/ui/stepper/1')">Next</button>
        {{ else }}
        <button class="btn btn-primary" onclick="if(!window.syncRepo())event.stopImmediatePropagation()" data-on:click="@post('/ui/stepper/1')">Next</button>
        {{ end }}
    </div>
</div>
{{- end -}}

{{- define "stepper-1" -}}
<div id="stepper-content">
    {{ template "stepper-dots" . }}
    <h3 class="stepper-title">Set Permissions</h3>
    <div class="form-group">
        <label>Permissions</label>
        <ghp-permission-select id="perm-select"></ghp-permission-select>
        <input type="hidden" id="perms-signal" data-bind:perms>
    </div>
    {{ if .Error }}<p class="form-error">{{ .Error }}</p>{{ end }}
    <div class="stepper-actions">
        <button class="btn btn-ghost" data-on:click="@get('/ui/stepper/0')">Back</button>
        {{ if .DevMode }}
        <button class="btn btn-primary" onclick="window.syncPerms()" data-on:click="@post('/ui/stepper/2')">Next</button>
        {{ else }}
        <button class="btn btn-primary" onclick="if(!window.syncPerms())event.stopImmediatePropagation()" data-on:click="@post('/ui/stepper/2')">Next</button>
        {{ end }}
    </div>
</div>
{{- end -}}

{{- define "stepper-2" -}}
<div id="stepper-content">
    {{ template "stepper-dots" . }}
    <h3 class="stepper-title">Details</h3>
    <div class="form-group">
        <label for="duration">Duration</label>
        <select id="duration" data-bind:duration>
            <option value="8h">8 hours</option>
            <option value="24h">24 hours</option>
            <option value="48h">48 hours</option>
            <option value="168h">7 days</option>
        </select>
    </div>
    <div class="form-group">
        <label for="session">Session identifier (optional)</label>
        <input type="text" id="session" data-bind:session placeholder="claude-code-feature-123">
    </div>
    <div class="stepper-actions">
        <button class="btn btn-ghost" data-on:click="@get('/ui/stepper/1')">Back</button>
        <button class="btn btn-primary" data-on:click="@post('/ui/stepper/3')">Next</button>
    </div>
</div>
{{- end -}}

{{- define "stepper-3" -}}
<div id="stepper-content">
    {{ template "stepper-dots" . }}
    <div id="step-confirm">
        <h3 class="stepper-title">Confirm &amp; Create</h3>
        <dl class="confirm-summary">
            <dt>Repository</dt><dd>{{ .Repo }}</dd>
            <dt>Permissions</dt><dd>{{ range .Scopes }}<span class="scope-chip">{{ . }}</span> {{ end }}</dd>
            <dt>Duration</dt><dd>{{ .Duration }}</dd>
            {{ if .Session }}<dt>Session</dt><dd>{{ .Session }}</dd>{{ end }}
        </dl>
        <div class="stepper-actions">
            <button class="btn btn-ghost" data-on:click="@get('/ui/stepper/2')">Back</button>
            <button class="btn btn-primary" data-on:click="@post('/ui/tokens')">Create Token</button>
        </div>
    </div>
</div>
{{- end -}}

{{- define "admin-users-panel" -}}
<section id="admin-users-panel">
    {{ if .Users }}
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Users }}
                <tr>
                    <td>{{ .Username }}</td>
                    <td><span class="badge badge-{{ .Role }}">{{ .Role }}</span></td>
                    <td>{{ .Created }}</td>
                </tr>
                {{ end }}
            </tbody>
        </table>
    </div>
    {{ else }}
    <div class="empty-state">
        <p>No users found.</p>
    </div>
    {{ end }}
</section>
{{- end -}}

{{- define "dashboard-tokens" -}}
<div id="dashboard-tokens">
    <div class="section-header">
        <h2>Your Tokens</h2>
        {{ if .Tokens }}
        <button class="btn btn-primary" data-on:click="$stepperOpen = true; $repo = ''; $perms = '{}'; $duration = '24h'; $session = ''; @get('/ui/stepper/0')">New Token</button>
        {{ end }}
    </div>
    {{ if .Tokens }}
    <section class="token-grid" id="token-grid">
        {{ range .Tokens }}
        <article class="token-card" id="token-{{ .RawID }}">
            <div class="token-card-header">
                <div>
                    <h3 class="token-card-repo">{{ .Repos }}</h3>
                    <span class="token-card-prefix">{{ .Prefix }}...</span>
                </div>
                <span class="status status-{{ .Status }}">
                    <span class="status-dot"></span>
                    {{ .ExpiryText }}
                </span>
            </div>
            <ul class="token-card-scopes">
                {{ range .Scopes }}
                <li class="scope-chip">{{ . }}</li>
                {{ end }}
            </ul>
            {{ if .SessionID }}
            <p class="token-card-session">{{ .SessionID }}</p>
            {{ end }}
            <footer class="token-card-footer">
                <span class="token-card-meta">{{ .Type }}</span>
                {{ if eq .Status "active" }}
                <button class="btn btn-danger" onclick="if(!confirm('Revoke this token?'))event.stopImmediatePropagation()" data-on:click="@delete('/ui/tokens/{{ .RawID }}')">Revoke</button>
                {{ end }}
            </footer>
        </article>
        {{ end }}
    </section>
    {{ else }}
    <section class="empty-state">
        <img src="/static/octobear.png" alt="">
        <p>No tokens yet. Create one to get started.</p>
        <button class="btn btn-primary" data-on:click="$stepperOpen = true; $repo = ''; $perms = '{}'; $duration = '24h'; $session = ''; @get('/ui/stepper/0')">New Token</button>
    </section>
    {{ end }}
</div>
{{- end -}}

{{- define "admin-tokens-panel" -}}
<section id="admin-tokens-panel">
    <div class="section-header">
        <h2>All Tokens</h2>
        <button class="btn btn-primary" data-on:click="$agentOpen = true; $agentStep = 0">New Agent Token</button>
    </div>
    {{ if .Tokens }}
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Prefix</th>
                    <th>Type</th>
                    <th>Repos</th>
                    <th>Scopes</th>
                    <th>Session</th>
                    <th>Status</th>
                    <th>Expires</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                {{ range .Tokens }}
                <tr id="token-row-{{ .RawID }}">
                    <td class="text-mono">{{ .Prefix }}...</td>
                    <td><span class="badge badge-{{ .Type }}">{{ .Type }}</span></td>
                    <td>{{ .Repos }}</td>
                    <td>{{ range .Scopes }}<span class="scope-chip">{{ . }}</span> {{ end }}</td>
                    <td>{{ if .SessionID }}{{ .SessionID }}{{ else }}-{{ end }}</td>
                    <td><span class="badge badge-{{ .Status }}">{{ .Status }}</span></td>
                    <td>{{ .ExpiryText }}</td>
                    <td>
                        {{ if eq .Status "active" }}
                        <button class="btn btn-danger" onclick="if(!confirm('Revoke this token?'))event.stopImmediatePropagation()" data-on:click="@delete('/ui/tokens/{{ .RawID }}')">Revoke</button>
                        {{ end }}
                    </td>
                </tr>
                {{ end }}
            </tbody>
        </table>
    </div>
    {{ else }}
    <div class="empty-state">
        <img src="/static/octobear.png" alt="">
        <p>No tokens found.</p>
    </div>
    {{ end }}
</section>
{{- end -}}
`))

// ── SSE: revoke token ───────────────────────────────────────────────

func (h *Handler) handleRevokeTokenSSE(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	id := r.PathValue("id")

	pt, err := h.store.GetProxyTokenByID(r.Context(), id)
	if err != nil {
		h.logger.Error("failed to get token for revocation", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if pt == nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}
	if (pt.UserID == nil || *pt.UserID != session.UserID) && session.Role != "admin" {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if err := h.tokenService.Revoke(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.logger.Info("token_revoked", "user", session.Username, "token_id", id)
	h.tokenNotify.Notify()

	// Re-fetch the token to get its revoked state.
	pt, _ = h.store.GetProxyTokenByID(r.Context(), id)
	sse := datastar.NewSSE(w, r)

	if pt != nil {
		views := buildTokenViews([]*database.ProxyToken{pt})
		if len(views) > 0 {
			view := views[0]

			// Determine which fragment to use based on Referer.
			tmplName := "token-card"
			if isAdminReferer(r) {
				tmplName = "token-row"
			}

			var buf bytes.Buffer
			if err := fragmentTemplates.ExecuteTemplate(&buf, tmplName, view); err != nil {
				h.logger.Error("fragment render failed", "error", err)
				return
			}
			sse.PatchElements(buf.String())
			return
		}
	}

	// Fallback: remove the element.
	sse.RemoveElementByID("token-" + id)
	sse.RemoveElementByID("token-row-" + id)
}

// ── SSE: create proxy token ─────────────────────────────────────────

type createTokenSignals struct {
	Repo     string `json:"repo"`
	Duration string `json:"duration"`
	Session  string `json:"session"`
	Perms    string `json:"perms"`
}

func (h *Handler) handleCreateTokenSSE(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	var signals createTokenSignals
	if err := datastar.ReadSignals(r, &signals); err != nil {
		h.logger.Error("failed to read signals", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse permissions from JSON string; use defaults in dev mode.
	var perms map[string]string
	if err := json.Unmarshal([]byte(signals.Perms), &perms); err != nil {
		http.Error(w, "Invalid permissions", http.StatusBadRequest)
		return
	}
	if h.devMode && len(perms) == 0 {
		perms = defaultProxyPermissions
	}

	duration := h.defaultDuration
	if signals.Duration != "" {
		d, err := time.ParseDuration(signals.Duration)
		if err != nil {
			http.Error(w, "Invalid duration", http.StatusBadRequest)
			return
		}
		duration = d
	}

	// Get user's GitHub token for proxy token creation.
	gt, err := h.store.GetGitHubToken(r.Context(), session.UserID)
	if err != nil || gt == nil {
		http.Error(w, "No GitHub token found. Please re-authenticate.", http.StatusBadRequest)
		return
	}

	// All validation passed — start SSE stream.
	sse := datastar.NewSSE(w, r)

	result, err := h.tokenService.Create(r.Context(), token.CreateRequest{
		TokenType:     token.TokenTypeProxy,
		UserID:        session.UserID,
		GitHubTokenID: gt.ID,
		Repository:    signals.Repo,
		Scopes:        perms,
		Duration:      duration,
		SessionID:     signals.Session,
	})
	if err != nil {
		h.logger.Error("token creation failed", "error", err)
		sse.PatchElements(`<div id="step-confirm"><p class="token-warning">` + template.HTMLEscapeString(err.Error()) + `</p></div>`)
		return
	}

	h.logger.Info("token_created",
		"user", session.Username,
		"type", "proxy",
		"repo", signals.Repo,
		"session", signals.Session,
	)
	h.tokenNotify.Notify()

	// Patch the stepper confirm step with the token display.
	var buf bytes.Buffer
	if err := fragmentTemplates.ExecuteTemplate(&buf, "token-created", map[string]string{
		"Token": result.Token,
	}); err != nil {
		h.logger.Error("fragment render failed", "error", err)
		return
	}
	sse.PatchElements(buf.String())
}

// ── SSE: create agent token (admin) ─────────────────────────────────

type createAgentTokenSignals struct {
	InstallationID string `json:"installationId"` // string from DOM select value
	Repos          string `json:"agentRepos"`     // JSON array as string
	Perms          string `json:"agentPerms"`     // JSON object as string
	Duration       string `json:"agentDuration"`
	Session        string `json:"agentSession"`
}

func (h *Handler) handleCreateAgentTokenSSE(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	if session.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	var signals createAgentTokenSignals
	if err := datastar.ReadSignals(r, &signals); err != nil {
		h.logger.Error("failed to read signals", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	installationID, err := strconv.ParseInt(signals.InstallationID, 10, 64)
	if err != nil {
		http.Error(w, "Invalid installation ID", http.StatusBadRequest)
		return
	}

	var repos []string
	if err := json.Unmarshal([]byte(signals.Repos), &repos); err != nil {
		http.Error(w, "Invalid repositories", http.StatusBadRequest)
		return
	}

	var perms map[string]string
	if err := json.Unmarshal([]byte(signals.Perms), &perms); err != nil {
		http.Error(w, "Invalid permissions", http.StatusBadRequest)
		return
	}

	duration := h.defaultDuration
	if signals.Duration != "" {
		d, err := time.ParseDuration(signals.Duration)
		if err != nil {
			http.Error(w, "Invalid duration", http.StatusBadRequest)
			return
		}
		duration = d
	}

	// All validation passed — start SSE stream.
	sse := datastar.NewSSE(w, r)

	result, err := h.tokenService.Create(r.Context(), token.CreateRequest{
		TokenType:      token.TokenTypeAgent,
		UserID:         session.UserID,
		InstallationID: installationID,
		Repositories:   repos,
		Scopes:         perms,
		Duration:       duration,
		SessionID:      signals.Session,
	})
	if err != nil {
		h.logger.Error("agent token creation failed", "error", err)
		sse.PatchElements(`<div id="agent-step-confirm"><p class="token-warning">` + template.HTMLEscapeString(err.Error()) + `</p></div>`)
		return
	}

	h.logger.Info("token_created",
		"user", session.Username,
		"type", "agent",
		"repos", result.Repositories,
		"session", signals.Session,
	)
	h.tokenNotify.Notify()

	var buf bytes.Buffer
	if err := fragmentTemplates.ExecuteTemplate(&buf, "token-created", map[string]string{
		"Token": result.Token,
	}); err != nil {
		h.logger.Error("fragment render failed", "error", err)
		return
	}
	sse.PatchElements(buf.String(), datastar.WithSelectorID("agent-step-confirm"))
}

// ── SSE: admin panel stream ──────────────────────────────────────────

func (h *Handler) handleAdminUsersPanelSSE(w http.ResponseWriter, r *http.Request) {
	sse := datastar.NewSSE(w, r)
	h.sendAdminUsersPanel(sse, r.Context())
}

func (h *Handler) handleAdminTokensPanelSSE(w http.ResponseWriter, r *http.Request) {
	sse := datastar.NewSSE(w, r)
	h.sendAdminTokensPanel(sse, r.Context())
}

func (h *Handler) handleAdminStreamSSE(w http.ResponseWriter, r *http.Request) {
	sse := datastar.NewSSE(w, r)

	// Send initial users panel only; tokens panel loads on-demand via tab click.
	h.sendAdminUsersPanel(sse, r.Context())

	// Keep connection open — push token panel updates on change.
	for {
		ch := h.tokenNotify.Wait()
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			h.sendAdminTokensPanel(sse, r.Context())
		}
	}
}

func (h *Handler) sendAdminUsersPanel(sse *datastar.ServerSentEventGenerator, ctx context.Context) {
	users, err := h.store.ListUsers(ctx)
	if err != nil {
		h.logger.Error("failed to list users", "error", err)
		users = nil
	}

	var buf bytes.Buffer
	if err := fragmentTemplates.ExecuteTemplate(&buf, "admin-users-panel", map[string]interface{}{
		"Users": buildUserViews(users),
	}); err != nil {
		h.logger.Error("admin users panel render failed", "error", err)
		return
	}
	sse.PatchElements(buf.String())
}

func (h *Handler) sendAdminTokensPanel(sse *datastar.ServerSentEventGenerator, ctx context.Context) {
	tokens, err := h.store.ListAllProxyTokens(ctx)
	if err != nil {
		h.logger.Error("failed to list all tokens", "error", err)
		tokens = nil
	}

	var buf bytes.Buffer
	if err := fragmentTemplates.ExecuteTemplate(&buf, "admin-tokens-panel", map[string]interface{}{
		"Tokens": buildTokenViews(tokens),
	}); err != nil {
		h.logger.Error("admin tokens panel render failed", "error", err)
		return
	}
	sse.PatchElements(buf.String())
}

// ── SSE: stepper navigation ──────────────────────────────────────────

type stepperSignals struct {
	Repo     string `json:"repo"`
	Duration string `json:"duration"`
	Session  string `json:"session"`
	Perms    string `json:"perms"`
}

func (h *Handler) handleStepperSSE(w http.ResponseWriter, r *http.Request) {
	stepStr := r.PathValue("step")
	step, err := strconv.Atoi(stepStr)
	if err != nil || step < 0 || step > 3 {
		http.Error(w, "Invalid step", http.StatusBadRequest)
		return
	}

	var signals stepperSignals
	if r.Method == http.MethodPost {
		if err := datastar.ReadSignals(r, &signals); err != nil {
			h.logger.Error("failed to read stepper signals", "error", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
	}

	sse := datastar.NewSSE(w, r)
	data := map[string]interface{}{
		"Step":    step,
		"DevMode": h.devMode,
	}

	// Validate on POST (forward navigation).
	if r.Method == http.MethodPost {
		switch step {
		case 1: // Validate step 0: repo required.
			if signals.Repo == "" {
				data["Step"] = 0
				data["Error"] = "Please select a repository."
				h.renderFragment(sse, "stepper-0", data)
				return
			}
		case 2: // Validate step 1: perms required.
			var perms map[string]string
			if err := json.Unmarshal([]byte(signals.Perms), &perms); err != nil || len(perms) == 0 {
				if h.devMode {
					// Dev mode: use default permissions when none synced from component.
					break
				}
				data["Step"] = 1
				data["Error"] = "Please select at least one permission."
				h.renderFragment(sse, "stepper-1", data)
				return
			}
		case 3: // Build confirm summary from signals.
			repo := signals.Repo
			duration := signals.Duration
			if duration == "" {
				duration = "24h"
			}

			var perms map[string]string
			_ = json.Unmarshal([]byte(signals.Perms), &perms)
			if h.devMode && len(perms) == 0 {
				perms = defaultProxyPermissions
			}

			data["Repo"] = repo
			data["Scopes"] = buildSortedScopes(perms)
			data["Duration"] = duration
			data["Session"] = signals.Session
		}
	}

	h.renderFragment(sse, "stepper-"+stepStr, data)
}

func (h *Handler) renderFragment(sse *datastar.ServerSentEventGenerator, name string, data interface{}) {
	var buf bytes.Buffer
	if err := fragmentTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.Error("fragment render failed", "template", name, "error", err)
		return
	}
	sse.PatchElements(buf.String())
}

func buildSortedScopes(perms map[string]string) []string {
	scopes := make([]string, 0, len(perms))
	for k, v := range perms {
		scopes = append(scopes, k+":"+v)
	}
	sort.Strings(scopes)
	return scopes
}

// ── SSE: dashboard stream ────────────────────────────────────────────

func (h *Handler) handleDashboardStreamSSE(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	sse := datastar.NewSSE(w, r)

	// Send initial dashboard tokens.
	h.sendDashboardTokens(sse, r.Context(), session.UserID)

	// Keep connection open — push updates on change.
	for {
		ch := h.tokenNotify.Wait()
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			h.sendDashboardTokens(sse, r.Context(), session.UserID)
		}
	}
}

func (h *Handler) sendDashboardTokens(sse *datastar.ServerSentEventGenerator, ctx context.Context, userID string) {
	tokens, err := h.store.ListProxyTokens(ctx, userID)
	if err != nil {
		h.logger.Error("failed to list tokens for dashboard update", "error", err)
		tokens = nil
	}

	var buf bytes.Buffer
	if err := fragmentTemplates.ExecuteTemplate(&buf, "dashboard-tokens", map[string]interface{}{
		"Tokens": buildTokenViews(tokens),
	}); err != nil {
		h.logger.Error("dashboard tokens render failed", "error", err)
		return
	}
	sse.PatchElements(buf.String())
}

// ── SSE: logout ─────────────────────────────────────────────────────

func (h *Handler) handleLogoutSSE(w http.ResponseWriter, r *http.Request) {
	h.auth.ClearSession(w, r)

	sse := datastar.NewSSE(w, r)
	sse.Redirect("/login")
}

// ── Helpers ─────────────────────────────────────────────────────────

func isAdminReferer(r *http.Request) bool {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return false
	}
	u, err := url.Parse(ref)
	if err != nil {
		return false
	}
	return u.Path == "/admin"
}
