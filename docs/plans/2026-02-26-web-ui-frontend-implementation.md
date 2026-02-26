# Web UI Frontend Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the existing web UI with a Chi + Datastar hypermedia frontend, fixing permission names to use GitHub's canonical `InstallationPermissions` JSON tags.

**Architecture:** Chi replaces `http.ServeMux` globally. Datastar handles partial DOM updates via SSE. Templates use Go `html/template` with embedded FS (filesystem override in dev mode). Wizard state stored in encrypted cookies. All URLs end with trailing slash.

**Tech Stack:** Go, Chi v5, Datastar v1.0.0 (CDN), Datastar Go SDK, vanilla CSS, `html/template`

---

### Task 1: Add Chi and Datastar Go SDK Dependencies

**Files:**
- Modify: `go.mod`

**Step 1: Add dependencies**

Run:
```bash
cd /Users/gary/Projects/ghp.web-ui-redo
go get github.com/go-chi/chi/v5
go get github.com/starfederation/datastar-go/datastar
```

**Step 2: Verify**

Run: `go mod tidy && go build ./...`
Expected: clean build, no errors

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "Add Chi router and Datastar Go SDK dependencies"
```

---

### Task 2: Fix Permission Names — Rename `pulls` to `pull_requests`

This is the scope bug fix. Every occurrence of the internal scope name `"pulls"` must become `"pull_requests"` to match `github.InstallationPermissions`'s JSON tag.

**Files:**
- Modify: `internal/github/app.go:400` — change `add("pulls", p.PullRequests)` to `add("pull_requests", p.PullRequests)`
- Modify: `internal/proxy/scope.go:48-55` — change all `"pulls"` to `"pull_requests"` in endpoint rules
- Modify: `internal/proxy/scope_test.go` — update all `"pulls"` references
- Modify: `internal/proxy/proxy_test.go` — update all `"pulls"` references
- Modify: `internal/token/token.go:259` — update docstring example
- Modify: `internal/token/token_test.go:82-85` — update test scope strings
- Modify: `internal/database/sqlite_test.go:120` — update JSON scope literal
- Modify: `internal/database/postgres_test.go:138` — update JSON scope literal
- Modify: `internal/database/models_test.go:11-45` — update all `"pulls"` references
- Modify: `cmd/ghp/token.go:126` — update `--scope` flag help text

**Step 1: Write a failing test**

Add a test in `internal/proxy/scope_test.go` that asserts `EndpointScope("GET", "/repos/org/repo/pulls")` returns `"pull_requests", "read"` (not `"pulls"`):

```go
func TestEndpointScopeCanonicalNames(t *testing.T) {
	perm, level := EndpointScope("GET", "/repos/org/repo/pulls")
	if perm != "pull_requests" || level != "read" {
		t.Errorf("GET pulls: got %s:%s, want pull_requests:read", perm, level)
	}
	perm, level = EndpointScope("POST", "/repos/org/repo/pulls")
	if perm != "pull_requests" || level != "write" {
		t.Errorf("POST pulls: got %s:%s, want pull_requests:write", perm, level)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestEndpointScopeCanonicalNames -v`
Expected: FAIL — returns `"pulls"` not `"pull_requests"`

**Step 3: Rename all occurrences**

In `internal/proxy/scope.go`, replace every `"pulls"` with `"pull_requests"` in the rules slice (lines 48-55).

In `internal/github/app.go:400`, change:
```go
add("pulls", p.PullRequests)
```
to:
```go
add("pull_requests", p.PullRequests)
```

**Step 4: Update all existing tests**

In every test file listed above, replace `"pulls"` scope references with `"pull_requests"`. This includes:
- Scope map keys: `"pulls": "write"` → `"pull_requests": "write"`
- Scope strings: `"contents:read,pulls:write"` → `"contents:read,pull_requests:write"`
- Error message assertions: `"pulls:write"` → `"pull_requests:write"`
- CLI help text: `"contents:read,pulls:write"` → `"contents:read,pull_requests:write"`

**Step 5: Run all tests**

Run: `go test ./...`
Expected: all PASS

**Step 6: Commit**

```bash
git add internal/github/app.go internal/proxy/scope.go internal/proxy/scope_test.go internal/proxy/proxy_test.go internal/token/token.go internal/token/token_test.go internal/database/sqlite_test.go internal/database/postgres_test.go internal/database/models_test.go cmd/ghp/token.go
git commit -m "Fix scope name: rename pulls to pull_requests to match GitHub API"
```

---

### Task 3: Add Database Migration for Stored Scope Rename

Existing proxy tokens in the database have `{"pulls":"write"}` in their scopes JSON column. This needs to become `{"pull_requests":"write"}`.

**Files:**
- Create: `internal/database/migrations/sqlite/002_rename_pulls_scope.up.sql`
- Create: `internal/database/migrations/sqlite/002_rename_pulls_scope.down.sql`
- Create: `internal/database/migrations/postgres/002_rename_pulls_scope.up.sql`
- Create: `internal/database/migrations/postgres/002_rename_pulls_scope.down.sql`

**Step 1: Write SQLite migration**

`002_rename_pulls_scope.up.sql`:
```sql
UPDATE proxy_tokens
SET scopes = REPLACE(scopes, '"pulls":', '"pull_requests":')
WHERE scopes LIKE '%"pulls"%';
```

`002_rename_pulls_scope.down.sql`:
```sql
UPDATE proxy_tokens
SET scopes = REPLACE(scopes, '"pull_requests":', '"pulls":')
WHERE scopes LIKE '%"pull_requests"%';
```

**Step 2: Write PostgreSQL migration**

`002_rename_pulls_scope.up.sql`:
```sql
UPDATE proxy_tokens
SET scopes = REPLACE(scopes::text, '"pulls":', '"pull_requests":')::jsonb
WHERE scopes::text LIKE '%"pulls"%';
```

`002_rename_pulls_scope.down.sql`:
```sql
UPDATE proxy_tokens
SET scopes = REPLACE(scopes::text, '"pull_requests":', '"pulls":')::jsonb
WHERE scopes::text LIKE '%"pull_requests"%';
```

**Step 3: Verify migrations apply**

Run: `go test ./internal/database/ -v`
Expected: PASS (migration runner picks up new files)

**Step 4: Commit**

```bash
git add internal/database/migrations/
git commit -m "Add migration to rename pulls scope to pull_requests in stored tokens"
```

---

### Task 4: Build Permission Registry

Create a canonical permission registry derived from `InstallationPermissions` JSON tags with display metadata for the wizard UI.

**Files:**
- Create: `internal/token/permissions.go`
- Create: `internal/token/permissions_test.go`

**Step 1: Write the failing test**

`internal/token/permissions_test.go`:
```go
package token

import "testing"

func TestPermissionRegistryContainsPullRequests(t *testing.T) {
	p, ok := PermissionByKey("pull_requests")
	if !ok {
		t.Fatal("pull_requests not found in registry")
	}
	if p.DisplayName != "Pull requests" {
		t.Errorf("display name = %q, want %q", p.DisplayName, "Pull requests")
	}
}

func TestPermissionRegistryCommonSubset(t *testing.T) {
	common := CommonPermissions()
	if len(common) == 0 {
		t.Fatal("common permissions list is empty")
	}
	// Must include the permissions coding agents commonly need.
	keys := make(map[string]bool)
	for _, p := range common {
		keys[p.Key] = true
	}
	for _, key := range []string{"actions", "checks", "contents", "issues", "metadata", "pull_requests", "statuses"} {
		if !keys[key] {
			t.Errorf("common permissions missing %q", key)
		}
	}
}

func TestAllPermissionsMatchesSDK(t *testing.T) {
	all := AllPermissions()
	if len(all) < 30 {
		t.Errorf("expected 30+ permissions from SDK, got %d", len(all))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/token/ -run TestPermission -v`
Expected: FAIL — functions don't exist yet

**Step 3: Write the implementation**

`internal/token/permissions.go`:
```go
package token

import (
	"reflect"
	"sort"
	"strings"

	ghub "github.com/google/go-github/v68/github"
)

// Permission describes a GitHub App installation permission.
type Permission struct {
	Key         string   // JSON tag from InstallationPermissions, e.g. "pull_requests"
	DisplayName string   // Human-friendly name, e.g. "Pull requests"
	Description string   // Short description for the UI
	Levels      []string // Allowed access levels, e.g. ["read", "write"]
}

var (
	allPermissions    []Permission
	permissionsByKey  map[string]Permission
	commonKeys        = map[string]bool{
		"actions": true, "checks": true, "contents": true,
		"deployments": true, "issues": true, "metadata": true,
		"packages": true, "pull_requests": true, "statuses": true,
		"workflows": true,
	}
)

func init() {
	permissionsByKey = make(map[string]Permission)

	// Use reflection on InstallationPermissions to get canonical field list.
	t := reflect.TypeOf(ghub.InstallationPermissions{})
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		key := strings.TrimSuffix(jsonTag, ",omitempty")

		p := Permission{
			Key:         key,
			DisplayName: fieldNameToDisplay(field.Name),
			Description: descriptionFor(key),
			Levels:      levelsFor(key),
		}
		allPermissions = append(allPermissions, p)
		permissionsByKey[key] = p
	}

	sort.Slice(allPermissions, func(i, j int) bool {
		return allPermissions[i].DisplayName < allPermissions[j].DisplayName
	})
}

// AllPermissions returns all permissions from the GitHub SDK.
func AllPermissions() []Permission {
	return allPermissions
}

// CommonPermissions returns the curated subset for coding agents.
func CommonPermissions() []Permission {
	var result []Permission
	for _, p := range allPermissions {
		if commonKeys[p.Key] {
			result = append(result, p)
		}
	}
	return result
}

// PermissionByKey looks up a permission by its canonical key.
func PermissionByKey(key string) (Permission, bool) {
	p, ok := permissionsByKey[key]
	return p, ok
}

// fieldNameToDisplay converts "PullRequests" to "Pull requests",
// "OrganizationAdministration" to "Organization administration", etc.
func fieldNameToDisplay(name string) string {
	var words []string
	start := 0
	for i := 1; i < len(name); i++ {
		if name[i] >= 'A' && name[i] <= 'Z' {
			words = append(words, name[start:i])
			start = i
		}
	}
	words = append(words, name[start:])

	if len(words) == 0 {
		return name
	}
	result := words[0]
	for _, w := range words[1:] {
		result += " " + strings.ToLower(w)
	}
	return result
}

// levelsFor returns allowed access levels for a permission.
func levelsFor(key string) []string {
	// Metadata is read-only.
	if key == "metadata" {
		return []string{"read"}
	}
	return []string{"read", "write"}
}

// descriptionFor returns a human-friendly description for common permissions.
func descriptionFor(key string) string {
	descriptions := map[string]string{
		"actions":              "GitHub Actions workflows, runs, and artifacts.",
		"checks":              "Check runs and check suites.",
		"contents":            "Repository contents, commits, branches, downloads, releases, and merges.",
		"deployments":         "Deployments and deployment statuses.",
		"issues":              "Issues and related comments, assignees, labels, and milestones.",
		"metadata":            "Search repositories, list collaborators, and access repository metadata.",
		"packages":            "GitHub Packages.",
		"pages":               "GitHub Pages.",
		"pull_requests":       "Pull requests and related comments, assignees, labels, milestones, and merges.",
		"statuses":            "Commit statuses.",
		"workflows":           "GitHub Actions workflows.",
		"administration":      "Repository administration.",
		"security_events":     "Code scanning and secret scanning alerts.",
		"vulnerability_alerts": "Dependabot vulnerability alerts.",
		"environments":        "Repository environments.",
		"secrets":             "Repository secrets.",
		"discussions":         "Repository discussions.",
		"members":             "Organization members.",
	}
	if d, ok := descriptions[key]; ok {
		return d
	}
	return ""
}
```

**Step 4: Run tests**

Run: `go test ./internal/token/ -run TestPermission -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add internal/token/permissions.go internal/token/permissions_test.go
git commit -m "Add permission registry derived from GitHub SDK InstallationPermissions"
```

---

### Task 5: Replace `http.ServeMux` with Chi Router

Convert the top-level mux in `internal/server/server.go` from `http.ServeMux` to `chi.Router`. Convert each package's `RegisterRoutes(mux *http.ServeMux)` to `RegisterRoutes(r chi.Router)`.

**Files:**
- Modify: `internal/server/server.go:131-156` — replace `http.NewServeMux()` with `chi.NewRouter()`
- Modify: `internal/auth/auth.go:134-160` — change `RegisterRoutes(mux *http.ServeMux)` to `RegisterRoutes(r chi.Router)`
- Modify: `internal/server/api.go:48-64` — change `RegisterRoutes(mux *http.ServeMux)` to `RegisterRoutes(r chi.Router)`
- Modify: `internal/web/handler.go:39-44` — change `RegisterRoutes(mux *http.ServeMux)` to `RegisterRoutes(r chi.Router)`

**Step 1: Write a failing test**

Add a test in `internal/server/` that verifies the router is a `chi.Router`:

```go
// In a new file internal/server/router_test.go
package server

import (
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRouterIsChi(t *testing.T) {
	// Verify chi.NewRouter returns chi.Router
	r := chi.NewRouter()
	var _ chi.Router = r
}
```

**Step 2: Run test to verify it compiles**

Run: `go test ./internal/server/ -run TestRouterIsChi -v`
Expected: PASS (this confirms chi is importable)

**Step 3: Convert server.go**

In `internal/server/server.go`, replace:
```go
mux := http.NewServeMux()
```
with:
```go
r := chi.NewRouter()
r.Use(middleware.RedirectSlashes)
```

Add imports:
```go
"github.com/go-chi/chi/v5"
"github.com/go-chi/chi/v5/middleware"
```

Change all `mux` references to `r` and update the `RegisterRoutes` calls. The host dispatch config changes `mgmtHandler: accessLogHandler(backend.Mgmt, mux, aw)` to `mgmtHandler: accessLogHandler(backend.Mgmt, r, aw)`.

Static routes:
```go
r.Handle("/static/*", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
```

Docs routes:
```go
r.Handle("/docs/*", http.StripPrefix("/docs/", docs.Handler()))
r.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
})
```

Proxy routes:
```go
r.Handle("/api/v3/*", proxyHandler)
r.Handle("/api/graphql", proxyHandler)
```

Metrics:
```go
if s.cfg.Metrics.Enabled {
    r.Handle("/metrics", promhttp.Handler())
}
```

**Step 4: Convert auth.RegisterRoutes**

In `internal/auth/auth.go`, change signature from:
```go
func (h *Handler) RegisterRoutes(mux *http.ServeMux)
```
to:
```go
func (h *Handler) RegisterRoutes(r chi.Router)
```

Convert route registrations from `mux.Handle("GET /path", handler)` to `r.Method("GET", "/path/", handler)` or `r.Get("/path/", handlerFunc)`. Remember trailing slashes.

Example conversions:
```go
r.With(h.githubLimiter.Middleware).Get("/auth/github/", h.handleGitHubLogin)
r.Get("/auth/github/callback/", h.handleGitHubCallback)
r.Post("/auth/logout/", h.handleLogout)
r.Get("/auth/status/", h.handleStatus)
```

Broker routes (conditional):
```go
r.With(h.authorizeLimiter.Middleware).Get("/auth/authorize/", h.handleBrokerAuthorize)
r.Get("/auth/callback/", h.handleBrokerCallback)
r.Get("/.well-known/jwks.json", h.handleJWKS)
```

Dev mode:
```go
r.With(h.loginLimiter.Middleware).Post("/auth/test-login/", h.handleTestLogin)
```

Note: `IPRateLimiter.Middleware` needs to match Chi's `func(http.Handler) http.Handler` signature. Check current signature — it already does since it wraps `http.Handler`.

**Step 5: Convert api.RegisterRoutes**

In `internal/server/api.go`, change signature and routes:
```go
func (a *API) RegisterRoutes(r chi.Router) {
    r.Group(func(r chi.Router) {
        r.Use(a.authHandler.RequireAuth)

        r.With(a.tokenCreateLimiter.Middleware).Post("/api/tokens/", a.handleCreateToken)
        r.Get("/api/tokens/", a.handleListTokens)
        r.Get("/api/tokens/{id}/", a.handleGetToken)
        r.Delete("/api/tokens/{id}/", a.handleRevokeToken)

        r.Get("/api/github/repositories/", a.handleListUserRepos)
        r.Get("/api/audit/", a.handleListAudit)
    })

    r.Group(func(r chi.Router) {
        r.Use(a.authHandler.RequireAdmin)

        r.Get("/api/users/", a.handleListUsers)
        r.Get("/api/users/{id}/tokens/", a.handleListUserTokens)
        r.Get("/api/github/installations/", a.handleListInstallations)
        r.Get("/api/github/installations/{id}/repositories/", a.handleListInstallationRepos)
    })
}
```

Note: API handlers that use `r.PathValue("id")` (Go 1.22 mux) need to change to `chi.URLParam(r, "id")`. Search for all `r.PathValue(` in `internal/server/api.go` and replace.

**Step 6: Convert web.RegisterRoutes**

In `internal/web/handler.go`, change to:
```go
func (h *Handler) RegisterRoutes(r chi.Router) {
    r.Get("/login/", h.handleLogin)
    r.Get("/dashboard/", h.handleIndex)
    r.Get("/admin/", h.handleAdmin)
}
```

Note: the root route `GET /{$}` becomes a redirect from `/` to `/dashboard/`.

Static file serving moves to `server.go` since it's now a top-level Chi route.

**Step 7: Run all tests**

Run: `go test ./...`
Expected: all PASS

**Step 8: Commit**

```bash
git add internal/server/server.go internal/server/api.go internal/auth/auth.go internal/web/handler.go go.mod go.sum
git commit -m "Replace http.ServeMux with Chi router globally"
```

---

### Task 6: CSS Stylesheet

Create the vanilla CSS stylesheet with the design system from the spec.

**Files:**
- Create: `internal/web/static/style.css`

**Step 1: Write the stylesheet**

Create `internal/web/static/style.css` with all CSS custom properties, layout classes, component styles matching the spec's design system. Include:

- `:root` with color palette variables
- `[data-theme="dark"]` empty block for future dark mode
- `.layout`, `.header`, `.dev-banner`, `.content` layout styles
- `.card-grid` — CSS Grid, 3 columns desktop, responsive breakpoints
- `.token-card` — white card with shadow, padding
- `.permission-tag` — monospace pill badges, light tan background
- `.status-badge` — green/grey/amber status indicators
- `.role-badge` — grey (user) / blue (admin) pills
- `.btn-primary`, `.btn-danger`, `.btn-outline` button styles
- `.modal-overlay`, `.modal-card` modal styles
- `.wizard-dots` — step indicator dots
- `.table` — data table with clean borders
- `.filter-bar` — filter controls row
- `.empty-state` — centered empty state
- `.login-card` — centered login card
- Form elements: inputs, selects, labels
- Responsive breakpoints: 1024px, 768px

Reference the screenshots for exact proportions and spacing. Key values:
- Max content width: 1100px
- Card padding: 24px
- Card gap: 20px
- Card border-radius: 8px
- Card shadow: `0 1px 3px rgba(0,0,0,0.1)`
- Button border-radius: 6px
- Permission tag: `font-family: monospace`, small font size, rounded

**Step 2: Verify file exists**

Run: `ls -la internal/web/static/style.css`
Expected: file exists

**Step 3: Commit**

```bash
git add internal/web/static/style.css
git commit -m "Add vanilla CSS stylesheet with design system"
```

---

### Task 7: Base Template and Header Partial

Create the base HTML template with Datastar CDN, stylesheet link, and the header partial.

**Files:**
- Create: `internal/web/templates/base.html`
- Create: `internal/web/templates/header.html`

**Step 1: Write base.html**

```html
{{define "base"}}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{block "title" .}}GitHub Proxy{{end}}</title>
    <link rel="stylesheet" href="/static/style.css">
    <script type="module" src="https://cdn.jsdelivr.net/gh/starfederation/datastar@v1.0.0/bundles/datastar.js"></script>
</head>
<body>
    {{if .DevMode}}
    <div class="dev-banner">Development Mode — do not use in production</div>
    {{end}}
    {{if .ShowHeader}}
    {{template "header" .}}
    {{end}}
    <main class="content">
        {{block "content" .}}{{end}}
    </main>
    <div id="modal-overlay" class="modal-overlay" data-show="$modalOpen" data-on-click="$modalOpen = false">
        <div id="modal-content" class="modal-card" data-on-click.stop="">
        </div>
    </div>
</body>
</html>
{{end}}
```

**Step 2: Write header.html**

```html
{{define "header"}}
<header class="header">
    <div class="header-left">
        <img src="/static/mascot.png" alt="GitHub Proxy" class="header-logo">
        <span class="header-title">GitHub Proxy</span>
    </div>
    <nav class="header-nav">
        <a href="/dashboard/" class="header-link {{if eq .ActiveNav "dashboard"}}active{{end}}">Dashboard</a>
        {{if eq .Role "admin"}}
        <a href="/admin/" class="header-link {{if eq .ActiveNav "admin"}}active{{end}}">Admin</a>
        {{end}}
    </nav>
    <div class="header-right">
        <button class="header-icon" title="Toggle dark mode" disabled>
            <!-- Moon icon placeholder for future dark mode -->
        </button>
        <img src="https://github.com/{{.Username}}.png?size=32" alt="{{.Username}}" class="header-avatar">
        <a href="/logout/" class="header-link">Sign out</a>
    </div>
</header>
{{end}}
```

**Step 3: Commit**

```bash
git add internal/web/templates/base.html internal/web/templates/header.html
git commit -m "Add base layout and header partial templates"
```

---

### Task 8: Login Page Template

**Files:**
- Rewrite: `internal/web/templates/login.html`

**Step 1: Write login.html**

```html
{{define "title"}}Sign in — GitHub Proxy{{end}}

{{define "content"}}
<div class="login-card">
    <img src="/static/mascot.png" alt="GitHub Proxy" class="login-mascot">
    <h1 class="login-heading">GitHub Proxy</h1>
    <p class="login-subtitle">Scoped tokens for coding agents</p>
    <a href="/auth/github/" class="btn-primary btn-full-width login-btn">
        <svg class="github-icon" viewBox="0 0 16 16" width="20" height="20">
            <path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
        </svg>
        Sign in with GitHub
    </a>
</div>
{{end}}

{{template "base" .}}
```

Note: the login page sets `ShowHeader` to false in its template data so the header is hidden.

**Step 2: Update handleLogin handler**

In `internal/web/handler.go`, update `handleLogin` to pass the correct template data:
```go
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
    if err := h.templates.ExecuteTemplate(w, "login.html", data); err != nil {
        h.logger.Error("template execution failed", "error", err)
        http.Error(w, "Internal error", http.StatusInternalServerError)
    }
}
```

**Step 3: Run the app and verify visually**

Run: `go run ./cmd/ghp serve --config config.yaml`
Visit: `http://localhost:8080/login/`
Expected: centered login card with mascot, heading, subtitle, and GitHub sign-in button on cream background

**Step 4: Commit**

```bash
git add internal/web/templates/login.html internal/web/handler.go
git commit -m "Rebuild login page template with new design system"
```

---

### Task 9: Token Card Partial and Dashboard Page

**Files:**
- Create: `internal/web/templates/token_card.html`
- Create: `internal/web/templates/empty_state.html`
- Rewrite: `internal/web/templates/dashboard.html`
- Modify: `internal/web/handler.go` — update `handleIndex` to fetch tokens from store

**Step 1: Write token_card.html**

```html
{{define "token_card"}}
<div id="token-{{.ID}}" class="token-card">
    <div class="token-card-header">
        <span class="token-card-repo">{{.RepoDisplay}}</span>
        {{if .IsActive}}
        <span class="status-badge status-active">Expires in {{.ExpiresIn}}</span>
        {{else}}
        <span class="status-badge status-revoked">Revoked</span>
        {{end}}
    </div>
    <div class="token-card-prefix monospace">{{.TokenPrefix}}...</div>
    <div class="token-card-permissions">
        {{range .ScopeList}}
        <span class="permission-tag">{{.}}</span>
        {{end}}
    </div>
    {{if .SessionID}}
    <div class="token-card-session">{{.SessionID}}</div>
    {{end}}
    <div class="token-card-footer">
        <span class="token-card-type">{{.TokenType}}</span>
        {{if .IsActive}}
        <button class="btn-danger btn-outline" data-on-click="@get('/dashboard/token/{{.ID}}/revoke/')">Revoke</button>
        {{end}}
    </div>
</div>
{{end}}
```

**Step 2: Write empty_state.html**

```html
{{define "empty_state"}}
<div class="empty-state">
    <img src="/static/mascot-grey.png" alt="" class="empty-state-mascot">
    <p class="empty-state-text">No tokens yet. Create one to get started.</p>
    <button class="btn-primary" data-on-click="@get('/dashboard/token/add/')">New Token</button>
</div>
{{end}}
```

**Step 3: Write dashboard.html**

```html
{{define "title"}}Dashboard — GitHub Proxy{{end}}

{{define "content"}}
<div class="dashboard-header">
    <h1>Your Tokens</h1>
    {{if .Tokens}}
    <button class="btn-primary" data-on-click="@get('/dashboard/token/add/')">New Token</button>
    {{end}}
</div>
{{if .Tokens}}
<div class="card-grid" id="token-grid">
    {{range .Tokens}}
    {{template "token_card" .}}
    {{end}}
</div>
{{else}}
{{template "empty_state" .}}
{{end}}
{{end}}

{{template "base" .}}
```

**Step 4: Update handleIndex (now handleDashboard)**

In `internal/web/handler.go`, update the handler to fetch tokens from the store and prepare template data. The `Handler` struct needs access to `database.Store` and `token.Service`:

```go
type Handler struct {
    auth      *auth.Handler
    store     database.Store
    devMode   bool
    logger    *slog.Logger
    templates *template.Template
}
```

Update `NewHandler` to accept `store database.Store`.

The dashboard handler:
```go
func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
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

    if err := h.templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
        h.logger.Error("template execution failed", "error", err)
        http.Error(w, "Internal error", http.StatusInternalServerError)
    }
}
```

Add a helper `prepareTokenCards` that converts `[]*database.ProxyToken` to a slice of template-friendly structs with `RepoDisplay`, `ExpiresIn`, `IsActive`, `ScopeList`, etc.

**Step 5: Run and verify**

Run the app, log in, visit `/dashboard/`.
Expected: see token cards or empty state matching the screenshots.

**Step 6: Commit**

```bash
git add internal/web/templates/token_card.html internal/web/templates/empty_state.html internal/web/templates/dashboard.html internal/web/handler.go
git commit -m "Add dashboard page with token cards and empty state"
```

---

### Task 10: Dev Mode Filesystem Template Loading

Add filesystem-based template and static file loading when `dev_mode` is true.

**Files:**
- Modify: `internal/web/handler.go` — add filesystem fallback in `NewHandler`

**Step 1: Write the failing test**

```go
func TestNewHandlerDevModeLoadsFromDisk(t *testing.T) {
    // Create a temp dir with a test template
    dir := t.TempDir()
    tmplDir := filepath.Join(dir, "templates")
    os.MkdirAll(tmplDir, 0755)
    os.WriteFile(filepath.Join(tmplDir, "test.html"), []byte("{{define \"test\"}}hello{{end}}"), 0644)

    h := NewHandler(nil, nil, true, slog.Default(), dir)
    var buf bytes.Buffer
    err := h.templates.ExecuteTemplate(&buf, "test", nil)
    if err != nil {
        t.Fatal(err)
    }
    if buf.String() != "hello" {
        t.Errorf("got %q, want %q", buf.String(), "hello")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestNewHandlerDevMode -v`
Expected: FAIL

**Step 3: Implement**

Update `NewHandler` to accept a `baseDir string` parameter. When `devMode` is true and `baseDir` is not empty, parse templates from `filepath.Join(baseDir, "templates", "*.html")` instead of the embedded FS. For static files, serve from `filepath.Join(baseDir, "static")` instead of the embedded FS.

```go
func NewHandler(ah *auth.Handler, store database.Store, devMode bool, logger *slog.Logger, baseDir string) *Handler {
    var tmpl *template.Template
    if devMode && baseDir != "" {
        pattern := filepath.Join(baseDir, "templates", "*.html")
        tmpl = template.Must(template.ParseGlob(pattern))
        logger.Info("dev mode: loading templates from disk", "pattern", pattern)
    } else {
        tmpl = template.Must(template.ParseFS(templateFS, "templates/*.html"))
    }
    return &Handler{
        auth:      ah,
        store:     store,
        devMode:   devMode,
        logger:    logger,
        templates: tmpl,
        baseDir:   baseDir,
    }
}
```

For static files, expose a method or field so the route registration in `server.go` can choose between `http.FileServerFS(staticFS)` and `http.FileServer(http.Dir(baseDir + "/static"))`.

**Step 4: Run tests**

Run: `go test ./internal/web/ -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add internal/web/handler.go
git commit -m "Add dev mode filesystem template and static file loading"
```

---

### Task 11: Token Wizard — Encrypted Cookie State

Create the encrypted cookie helper for wizard state.

**Files:**
- Create: `internal/web/wizard.go`
- Create: `internal/web/wizard_test.go`

**Step 1: Write the failing test**

```go
package web

import (
    "net/http/httptest"
    "testing"

    "github.com/goodtune/ghp/internal/crypto"
)

func TestWizardStateRoundTrip(t *testing.T) {
    enc, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef")

    state := &WizardState{
        Repository:  "owner/repo",
        Permissions: map[string]string{"contents": "write", "pull_requests": "read"},
        Duration:    "24h",
        SessionID:   "test-session",
    }

    w := httptest.NewRecorder()
    if err := setWizardCookie(w, enc, state); err != nil {
        t.Fatal(err)
    }

    cookie := w.Result().Cookies()[0]
    r := httptest.NewRequest("GET", "/", nil)
    r.AddCookie(cookie)

    got, err := getWizardCookie(r, enc)
    if err != nil {
        t.Fatal(err)
    }
    if got.Repository != "owner/repo" {
        t.Errorf("repository = %q, want %q", got.Repository, "owner/repo")
    }
    if got.Permissions["pull_requests"] != "read" {
        t.Errorf("pull_requests = %q, want %q", got.Permissions["pull_requests"], "read")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestWizardState -v`
Expected: FAIL

**Step 3: Implement**

`internal/web/wizard.go`:
```go
package web

import (
    "encoding/json"
    "net/http"

    "github.com/goodtune/ghp/internal/crypto"
)

const wizardCookieName = "ghp_wizard"

type WizardState struct {
    Step        int               `json:"step"`
    Repository  string            `json:"repository,omitempty"`
    Permissions map[string]string `json:"permissions,omitempty"`
    Duration    string            `json:"duration,omitempty"`
    SessionID   string            `json:"session_id,omitempty"`
}

func setWizardCookie(w http.ResponseWriter, enc *crypto.Encryptor, state *WizardState) error {
    data, err := json.Marshal(state)
    if err != nil {
        return err
    }
    encrypted, err := enc.Encrypt(string(data))
    if err != nil {
        return err
    }
    http.SetCookie(w, &http.Cookie{
        Name:     wizardCookieName,
        Value:    encrypted,
        Path:     "/dashboard/token/add/",
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
    })
    return nil
}

func getWizardCookie(r *http.Request, enc *crypto.Encryptor) (*WizardState, error) {
    cookie, err := r.Cookie(wizardCookieName)
    if err != nil {
        return &WizardState{Step: 1}, nil // No cookie = fresh wizard
    }
    decrypted, err := enc.Decrypt(cookie.Value)
    if err != nil {
        return &WizardState{Step: 1}, nil // Corrupt cookie = start over
    }
    var state WizardState
    if err := json.Unmarshal([]byte(decrypted), &state); err != nil {
        return &WizardState{Step: 1}, nil
    }
    return &state, nil
}

func clearWizardCookie(w http.ResponseWriter) {
    http.SetCookie(w, &http.Cookie{
        Name:   wizardCookieName,
        Value:  "",
        Path:   "/dashboard/token/add/",
        MaxAge: -1,
    })
}
```

**Step 4: Run tests**

Run: `go test ./internal/web/ -run TestWizardState -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/web/wizard.go internal/web/wizard_test.go
git commit -m "Add encrypted cookie wizard state management"
```

---

### Task 12: Token Wizard Templates (Steps 1-4 + Created)

**Files:**
- Create: `internal/web/templates/token_wizard_step1.html`
- Create: `internal/web/templates/token_wizard_step2.html`
- Create: `internal/web/templates/token_wizard_step3.html`
- Create: `internal/web/templates/token_wizard_step4.html`
- Create: `internal/web/templates/token_created.html`

**Step 1: Write all wizard step templates**

Each template renders inside the modal container (`#modal-content`). All include the wizard dots indicator and close button. Templates use Datastar `data-on-click` for navigation.

Step 1 (repository selection): text input with `data-bind-repository`, "Next" posts to `/dashboard/token/add/`.

Step 2 (permissions): list of permission rows from `{{.Permissions}}`, each with a `<select>` for "No access"/"Read"/"Write". Include "Show all permissions" toggle. Uses `data-bind-*` for each permission select.

Step 3 (details): duration `<select>` with options (1h, 8h, 24h), session ID text input.

Step 4 (confirm): summary display of repository, permission pills, duration. "Create Token" button posts final data.

Token created: monospace box with token value, copy-to-clipboard behavior, green warning text.

**Step 2: Verify templates parse**

Run: `go test ./internal/web/ -v` (the existing test suite should exercise template parsing)
Expected: PASS

**Step 3: Commit**

```bash
git add internal/web/templates/token_wizard_step1.html internal/web/templates/token_wizard_step2.html internal/web/templates/token_wizard_step3.html internal/web/templates/token_wizard_step4.html internal/web/templates/token_created.html
git commit -m "Add token wizard step templates (1-4) and token created display"
```

---

### Task 13: Token Wizard Handlers

Wire up the wizard GET/POST handlers that serve step templates via Datastar SSE and manage wizard cookie state.

**Files:**
- Modify: `internal/web/handler.go` — add wizard handlers
- Modify: route registration to include wizard routes

**Step 1: Write test for wizard flow**

```go
func TestWizardStep1ReturnsSSE(t *testing.T) {
    h := setupTestHandler(t) // helper that creates Handler with test templates
    r := httptest.NewRequest("GET", "/dashboard/token/add/", nil)
    // Add auth session cookie...
    w := httptest.NewRecorder()
    h.handleWizardGet(w, r)
    if w.Header().Get("Content-Type") != "text/event-stream" {
        t.Errorf("content-type = %q, want text/event-stream", w.Header().Get("Content-Type"))
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestWizardStep1 -v`

**Step 3: Implement wizard handlers**

`handleWizardGet`: reads wizard cookie, returns current step template via `datastar.NewSSE(w, r)` + `sse.PatchElements(...)`. Also sets `$modalOpen = true` via SSE signal merge.

`handleWizardPost`: reads form data, merges into wizard cookie state, advances step. If step < 4, returns next step template via SSE. If step == 4 (final submit), creates the token via `h.tokenService.Create(...)`, clears wizard cookie, returns token created template + patches the dashboard token grid via SSE.

```go
func (h *Handler) handleWizardGet(w http.ResponseWriter, r *http.Request) {
    session := auth.SessionFromContext(r.Context())
    state, _ := getWizardCookie(r, h.encryptor)
    sse := datastar.NewSSE(w, r)
    html := h.renderTemplate("token_wizard_step1.html", map[string]interface{}{
        "Permissions": token.CommonPermissions(),
    })
    sse.MergeSignals([]byte(`{"modalOpen":true}`))
    sse.PatchElements(html)
}

func (h *Handler) handleWizardPost(w http.ResponseWriter, r *http.Request) {
    session := auth.SessionFromContext(r.Context())
    r.ParseForm()
    state, _ := getWizardCookie(r, h.encryptor)

    // Merge form data into state based on current step
    switch state.Step {
    case 1:
        state.Repository = r.FormValue("repository")
        state.Step = 2
    case 2:
        // Collect permissions from form
        state.Permissions = collectPermissions(r)
        state.Step = 3
    case 3:
        state.Duration = r.FormValue("duration")
        state.SessionID = r.FormValue("session_id")
        state.Step = 4
    case 4:
        // Create token
        h.createTokenFromWizard(w, r, session, state)
        return
    }

    setWizardCookie(w, h.encryptor, state)
    sse := datastar.NewSSE(w, r)
    // Render appropriate step template
    tmplName := fmt.Sprintf("token_wizard_step%d.html", state.Step)
    html := h.renderTemplate(tmplName, h.wizardTemplateData(state))
    sse.PatchElements(html)
}
```

Also handle "Back" — when a "back" form field is present, decrement the step instead.

**Step 4: Register routes**

In `RegisterRoutes`, within the authenticated group:
```go
r.Get("/dashboard/token/add/", h.handleWizardGet)
r.Post("/dashboard/token/add/", h.handleWizardPost)
```

**Step 5: Run tests**

Run: `go test ./internal/web/ -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/web/handler.go
git commit -m "Add token wizard handlers with SSE step navigation"
```

---

### Task 14: Revoke Confirmation and Handler

**Files:**
- Create: `internal/web/templates/revoke_confirm.html`
- Modify: `internal/web/handler.go` — add revoke handlers

**Step 1: Write revoke_confirm.html**

```html
{{define "revoke_confirm"}}
<div class="wizard-dots"><!-- empty for non-wizard modals --></div>
<button class="modal-close" data-on-click="$modalOpen = false">&times;</button>
<h2>Revoke Token</h2>
<p>Are you sure you want to revoke the token for <strong>{{.RepoDisplay}}</strong>?</p>
<p class="monospace">{{.TokenPrefix}}...</p>
<div class="modal-actions">
    <button class="btn-outline" data-on-click="$modalOpen = false">Cancel</button>
    <button class="btn-danger" data-on-click="@post('/dashboard/token/{{.ID}}/revoke/')">Confirm Revoke</button>
</div>
{{end}}
```

**Step 2: Implement handlers**

`handleRevokeConfirm` (GET): loads token by ID, verifies ownership, returns confirm dialog via SSE.

`handleRevoke` (POST): calls `h.store.RevokeProxyToken(ctx, id)`, returns updated token card (with revoked status) via SSE to replace the card in the DOM.

**Step 3: Register routes**

```go
r.Get("/dashboard/token/{id}/revoke/", h.handleRevokeConfirm)
r.Post("/dashboard/token/{id}/revoke/", h.handleRevoke)
```

**Step 4: Run tests**

Run: `go test ./internal/web/ -v`

**Step 5: Commit**

```bash
git add internal/web/templates/revoke_confirm.html internal/web/handler.go
git commit -m "Add token revoke confirmation dialog and handler"
```

---

### Task 15: Logout Page

**Files:**
- Create: `internal/web/templates/logout.html`
- Modify: `internal/web/handler.go` — add logout handlers

**Step 1: Write logout.html**

```html
{{define "title"}}Sign out — GitHub Proxy{{end}}

{{define "content"}}
<div class="login-card">
    <h1>Sign out</h1>
    <p>Are you sure you want to sign out?</p>
    <div class="modal-actions">
        <a href="/dashboard/" class="btn-outline">Cancel</a>
        <form method="POST" action="/logout/">
            <button type="submit" class="btn-danger">Sign Out</button>
        </form>
    </div>
</div>
{{end}}

{{template "base" .}}
```

**Step 2: Implement handlers**

`handleLogoutConfirm` (GET): renders logout confirmation page.

`handleLogoutExecute` (POST): calls existing `auth.Handler` logout logic, clears session cookie, redirects to `/login/`.

**Step 3: Register routes**

```go
r.Get("/logout/", h.handleLogoutConfirm)
r.Post("/logout/", h.handleLogoutExecute)
```

**Step 4: Commit**

```bash
git add internal/web/templates/logout.html internal/web/handler.go
git commit -m "Add logout confirmation page and handler"
```

---

### Task 16: Admin Layout, Users Tab, and User Detail

**Files:**
- Create: `internal/web/templates/admin_layout.html`
- Create: `internal/web/templates/admin_users.html`
- Create: `internal/web/templates/admin_user_detail.html`
- Modify: `internal/web/handler.go` — add admin handlers

**Step 1: Write admin_layout.html**

Template that extends base, adds Users/Tokens tab navigation.

**Step 2: Write admin_users.html**

Table with USERNAME, ROLE, CREATED columns. Each username links to `/admin/{username}/`. Role shown as badge.

**Step 3: Write admin_user_detail.html**

Shows username as heading, "Back to Users" link, grid of that user's token cards.

**Step 4: Implement handlers**

`handleAdminUsers` (GET `/admin/`): calls `h.store.ListUsers(ctx)`, renders users table.

`handleAdminUserDetail` (GET `/admin/{username}/`): gets username from `chi.URLParam`, lists their tokens, renders card grid.

**Step 5: Register routes**

```go
r.Group(func(r chi.Router) {
    r.Use(h.auth.RequireAdmin)
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
```

**Step 6: Run tests**

Run: `go test ./...`

**Step 7: Commit**

```bash
git add internal/web/templates/admin_layout.html internal/web/templates/admin_users.html internal/web/templates/admin_user_detail.html internal/web/handler.go
git commit -m "Add admin users tab and user detail page"
```

---

### Task 17: Admin Tokens Tab with Filtering

**Files:**
- Create: `internal/web/templates/admin_tokens.html`
- Modify: `internal/web/handler.go` — add admin tokens handler with filtering

**Step 1: Write admin_tokens.html**

Table with PREFIX, TYPE, USER, REPOS, SCOPES, SESSION, STATUS, EXPIRES columns. Filter bar at top with status dropdown, username/repository/scope text inputs, and Filter button. Filter button uses `data-on-click="@get('/admin/tokens/?status=...')"`.

**Step 2: Implement handler**

`handleAdminTokens` (GET `/admin/tokens/`): reads query params for filters, calls `h.store.ListAllProxyTokens(ctx)`, filters in-memory (or add a filtered query to the store interface), renders table. If request is Datastar SSE (check Accept header or a query param), return just the table body fragment via `sse.PatchElements`. Otherwise render the full page.

Note: the `Store` interface has `ListAllProxyTokens(ctx)` but no filtering. Filter in the handler for now; a filtered store method can be added later if needed.

**Step 3: Run and verify**

Run the app as admin, visit `/admin/tokens/`, apply filters.

**Step 4: Commit**

```bash
git add internal/web/templates/admin_tokens.html internal/web/handler.go
git commit -m "Add admin tokens tab with Datastar-powered filtering"
```

---

### Task 18: Admin Token Wizard and Revoke Handlers

**Files:**
- Modify: `internal/web/handler.go` — add admin wizard and revoke handlers

**Step 1: Implement admin wizard handlers**

Same pattern as user wizard (Tasks 12-13) but the admin wizard may also support agent token creation with installation ID. Reuse the wizard templates where possible — the permission step and details step are identical. Step 1 may have additional fields for admin (installation ID, token type).

**Step 2: Implement admin revoke handlers**

Same pattern as user revoke (Task 14) but for admin routes. Admin can revoke any token, not just their own.

`handleAdminTokenRevokeConfirm` / `handleAdminTokenRevoke` — for `/admin/tokens/{id}/revoke/`
`handleAdminUserTokenRevokeConfirm` / `handleAdminUserTokenRevoke` — for `/admin/{username}/{id}/revoke/`

**Step 3: Run tests**

Run: `go test ./...`

**Step 4: Commit**

```bash
git add internal/web/handler.go
git commit -m "Add admin token wizard and revoke handlers"
```

---

### Task 19: Remove Old Templates and Web Components

Clean up the old UI code that's been replaced.

**Files:**
- Delete: `internal/web/static/ghp-repo-select.js`
- Delete: `internal/web/static/ghp-permission-select.js`
- Delete: `internal/web/templates/admin-login.html` (admin login via dev mode handled differently now)
- Verify old `dashboard.html` and `admin.html` templates have been fully replaced

**Step 1: Remove files**

```bash
rm internal/web/static/ghp-repo-select.js
rm internal/web/static/ghp-permission-select.js
rm internal/web/templates/admin-login.html
```

**Step 2: Verify build**

Run: `go build ./...`
Expected: clean build (no references to deleted files)

**Step 3: Run all tests**

Run: `go test ./...`
Expected: all PASS

**Step 4: Commit**

```bash
git add internal/web/static/ internal/web/templates/
git commit -m "Remove old web components and replaced templates"
```

---

### Task 20: End-to-End Smoke Test

Write an integration test that exercises the main user flows.

**Files:**
- Create: `internal/web/handler_test.go` (or add to existing)

**Step 1: Write integration tests**

Test the following flows using `httptest.Server` with a real Chi router and in-memory SQLite:

1. **Unauthenticated redirect**: GET `/dashboard/` redirects to `/login/`
2. **Login page renders**: GET `/login/` returns 200 with "GitHub Proxy" text
3. **Dashboard renders with tokens**: seed DB with user + tokens, GET `/dashboard/` with session cookie returns 200 with token card HTML
4. **Dashboard empty state**: GET `/dashboard/` with no tokens returns empty state HTML
5. **Wizard step 1**: GET `/dashboard/token/add/` returns SSE with step 1 form
6. **Admin users table**: GET `/admin/` with admin session returns user table
7. **Admin tokens table**: GET `/admin/tokens/` returns token table

**Step 2: Run tests**

Run: `go test ./internal/web/ -v`
Expected: all PASS

**Step 3: Commit**

```bash
git add internal/web/handler_test.go
git commit -m "Add end-to-end smoke tests for web UI flows"
```

---

### Task 21: Static Asset Placeholders

Add the mascot images referenced by templates.

**Files:**
- Add: `internal/web/static/mascot.png` — the octopus-bear mascot (copy from existing assets or create placeholder)
- Add: `internal/web/static/mascot-grey.png` — greyed version for empty state

**Step 1: Check if mascot images exist elsewhere in the project**

Search for any existing mascot/logo images. If none exist, create simple placeholder PNGs.

**Step 2: Commit**

```bash
git add internal/web/static/mascot.png internal/web/static/mascot-grey.png
git commit -m "Add mascot images for login page and empty state"
```

---

### Task 22: Final Integration — Wire Everything in server.go

Ensure `server.go` correctly wires the new `Handler` with all its dependencies (store, encryptor, token service) and the Chi router groups are correct.

**Files:**
- Modify: `internal/server/server.go` — update `NewHandler` call with new parameters

**Step 1: Update server.go**

The `web.NewHandler` call needs to pass `store`, `encryptor`, `tokenService`, and the `baseDir` (derived from config or working directory when dev mode is on):

```go
var webBaseDir string
if s.cfg.DevMode {
    webBaseDir = "internal/web" // relative to working directory
}
webUI := web.NewHandler(authHandler, store, enc, tokenSvc, s.cfg.DevMode, s.logger, webBaseDir)
```

**Step 2: Verify full build and tests**

Run: `go build ./... && go test ./...`
Expected: clean build, all tests PASS

**Step 3: Manual smoke test**

Run the app in dev mode, exercise:
- Login page
- Dashboard (empty and with tokens)
- Token wizard (all 4 steps + token display)
- Revoke flow
- Admin users tab
- Admin user detail
- Admin tokens tab with filtering
- Logout

**Step 4: Commit**

```bash
git add internal/server/server.go
git commit -m "Wire new web UI handler with all dependencies in server"
```
