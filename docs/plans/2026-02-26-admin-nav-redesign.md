# Admin View & Navigation Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Consistent navigation header with GitHub avatars, fix admin tabs, add token filtering/pagination, and expandable user rows showing token cards.

**Architecture:** Server-side SSE fragments for all dynamic content (Datastar TAO). New filtered query method in the database layer with dynamic WHERE clauses. Admin tabs load content on-demand via SSE GET endpoints. User row expansion uses accordion pattern with SSE-fetched token cards.

**Tech Stack:** Go, Datastar SSE (datastar-go SDK), Playwright E2E tests, SQLite/PostgreSQL.

---

### Task 1: Consistent Navigation Header

Unify the header across dashboard and admin pages. Replace username text with a circular GitHub avatar linking to the user's profile. Add nav links for Dashboard (always) and Admin (admin-role only), with active state highlighting. Remove "admin" badge from admin page.

**Files:**
- Modify: `internal/web/templates/dashboard.html` (header section, lines 16-27)
- Modify: `internal/web/templates/admin.html` (header section, lines 14-26)
- Modify: `internal/web/static/theme.css` (header styles, lines 96-141)
- Modify: `internal/web/handler.go` (pass current page name to template data)
- Modify: `e2e/tests/dashboard.spec.ts` (update header assertions)
- Modify: `e2e/tests/admin.spec.ts` (update header assertions)

**Step 1: Update handler.go to pass page context**

Add `"Page"` to template data in `handleIndex` and `handleAdmin`:

```go
// In handleIndex (line 132):
data := map[string]interface{}{
    "Username": session.Username,
    "Role":     session.Role,
    "Tokens":   buildTokenViews(tokens),
    "DevMode":  h.devMode,
    "Page":     "dashboard",
}

// In handleAdmin (line 163):
data := map[string]interface{}{
    "Username": session.Username,
    "Role":     session.Role,
    "Page":     "admin",
}
```

**Step 2: Create shared header HTML**

Replace the header in both `dashboard.html` and `admin.html` with this identical structure:

```html
<header class="header">
    <div class="header-brand">
        <img src="/static/octobear.png" alt="" width="32" height="32">
        <span>GitHub Proxy</span>
    </div>
    <nav class="header-nav">
        <a href="/" class="nav-link{{ if eq .Page "dashboard" }} active{{ end }}">Dashboard</a>
        {{ if eq .Role "admin" }}<a href="/admin" class="nav-link{{ if eq .Page "admin" }} active{{ end }}">Admin</a>{{ end }}
    </nav>
    <div class="header-actions">
        <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme"></button>
        <a href="https://github.com/{{ .Username }}" target="_blank" rel="noopener" class="avatar-link">
            <img src="https://github.com/{{ .Username }}.png?size=64" alt="{{ .Username }}" class="avatar" width="32" height="32">
        </a>
        <button class="btn btn-ghost" data-on:click="@post('/ui/logout')">Sign out</button>
    </div>
</header>
```

**Step 3: Add CSS for new header elements**

Add to `theme.css` after the existing header styles:

```css
.header-nav {
    display: flex;
    gap: 0.25rem;
}

.nav-link {
    padding: 0.375rem 0.75rem;
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--color-text-secondary);
    text-decoration: none;
    border-radius: var(--radius-md);
    transition: color var(--transition), background var(--transition);
}

.nav-link:hover {
    color: var(--color-text);
    background: var(--color-border-subtle);
}

.nav-link.active {
    color: var(--color-accent);
    background: rgba(59,111,181,0.08);
}

.avatar-link {
    display: flex;
}

.avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    border: 1px solid var(--color-border);
}
```

Remove the `.header-actions .username` rule (no longer needed). Remove `.header-brand .badge-admin` rule.

**Step 4: Update E2E tests**

In `dashboard.spec.ts`, update "renders dashboard with user info" test — replace `toContainText("testuser")` with an avatar image check:

```ts
await expect(page.locator("header .avatar")).toBeVisible();
```

In `admin.spec.ts`, verify the nav link is active:

```ts
await expect(page.locator('header a.nav-link.active')).toHaveText("Admin");
```

**Step 5: Run tests, verify, commit**

```bash
cd /Users/gary/Projects/ghp.ui-redesign && go build ./...
cd e2e && npx playwright test
git add internal/web/templates/dashboard.html internal/web/templates/admin.html \
  internal/web/static/theme.css internal/web/handler.go \
  e2e/tests/dashboard.spec.ts e2e/tests/admin.spec.ts
git commit -m "feat(ui): consistent nav header with GitHub avatars and active nav links"
```

---

### Task 2: Fix Admin Tabs — On-Demand SSE Loading

Currently the admin SSE stream sends both panels on connect. Fix so only the active tab's panel loads initially, and switching tabs loads content via SSE.

**Files:**
- Modify: `internal/web/sse.go` (handleAdminStreamSSE, add tab-specific endpoints)
- Modify: `internal/web/handler.go` (register new routes)
- Modify: `internal/web/templates/admin.html` (tab buttons fire SSE requests)
- Modify: `e2e/tests/admin.spec.ts` (update tab switching test)

**Step 1: Add separate SSE endpoints for each tab**

In `sse.go`, add two new handlers:

```go
func (h *Handler) handleAdminUsersPanelSSE(w http.ResponseWriter, r *http.Request) {
    sse := datastar.NewSSE(w, r)
    h.sendAdminUsersPanel(sse, r.Context())
}

func (h *Handler) handleAdminTokensPanelSSE(w http.ResponseWriter, r *http.Request) {
    sse := datastar.NewSSE(w, r)
    h.sendAdminTokensPanel(sse, r.Context())
}
```

**Step 2: Modify handleAdminStreamSSE to only send users panel initially**

```go
func (h *Handler) handleAdminStreamSSE(w http.ResponseWriter, r *http.Request) {
    sse := datastar.NewSSE(w, r)

    // Send only the default tab (users) on connect.
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
```

**Step 3: Register new routes in handler.go**

Add to `RegisterRoutes`:

```go
mux.Handle("GET /ui/admin/users", h.auth.RequireAdmin(http.HandlerFunc(h.handleAdminUsersPanelSSE)))
mux.Handle("GET /ui/admin/tokens", h.auth.RequireAdmin(http.HandlerFunc(h.handleAdminTokensPanelSSE)))
```

**Step 4: Update admin.html tab buttons**

Replace the existing tab buttons with SSE-triggering versions:

```html
<div class="tabs">
    <button class="tab" data-class:active="$tab === 'users'"
        data-on:click="$tab = 'users'; @get('/ui/admin/users')">Users</button>
    <button class="tab" data-class:active="$tab === 'tokens'"
        data-on:click="$tab = 'tokens'; @get('/ui/admin/tokens')">Tokens</button>
</div>

<div id="admin-users-panel"></div>
<div id="admin-tokens-panel"></div>
```

Remove any `data-show` attributes on the panels — visibility is controlled by SSE patching (empty panel = nothing shown, loaded panel = content shown).

**Step 5: Update E2E test for tab switching**

Update "switches to tokens tab via SSE":

```ts
test("switches to tokens tab via SSE", async ({ page }, testInfo) => {
    await page.goto("/admin");
    await expect(page.locator("#admin-users-panel table")).toBeVisible({ timeout: 5_000 });

    // Tokens panel should be empty initially.
    await expect(page.locator("#admin-tokens-panel")).toBeEmpty();

    // Switch to Tokens tab.
    await page.click('button.tab:has-text("Tokens")');
    await expect(page.locator("#admin-tokens-panel h2")).toContainText("All Tokens");
});
```

**Step 6: Run tests, verify, commit**

```bash
cd /Users/gary/Projects/ghp.ui-redesign && go build ./...
cd e2e && npx playwright test
git add internal/web/sse.go internal/web/handler.go \
  internal/web/templates/admin.html e2e/tests/admin.spec.ts
git commit -m "fix(ui): admin tabs load content on-demand via SSE"
```

---

### Task 3: Database — Filtered Token Listing

Add a `ProxyTokenFilter` struct and `ListAllProxyTokensFiltered` method to both SQLite and PostgreSQL stores. This supports the admin tokens view filtering and pagination.

**Files:**
- Modify: `internal/database/models.go` (add ProxyTokenFilter, update Store interface)
- Modify: `internal/database/sqlite.go` (implement ListAllProxyTokensFiltered)
- Modify: `internal/database/postgres.go` (implement ListAllProxyTokensFiltered)
- Modify: `internal/database/sqlite_test.go` (add test)
- Modify: `internal/database/postgres_test.go` (add test)

**Step 1: Add ProxyTokenFilter to models.go**

```go
// ProxyTokenFilter controls filtering and pagination for token listings.
type ProxyTokenFilter struct {
    Status string // "active", "expired", "revoked", or "" for all
    UserID string // filter by user ID (exact match)
    Repo   string // substring match on repositories JSON
    Scope  string // substring match on scopes JSON
    Limit  int    // page size (default 25)
    Offset int    // pagination offset
}
```

Add to the Store interface:

```go
ListAllProxyTokensFiltered(ctx context.Context, filter ProxyTokenFilter) ([]*ProxyToken, int, error)
```

The second return value `int` is the total count (for pagination display).

**Step 2: Implement in sqlite.go**

Follow the same dynamic query pattern as `ListAuditEntries`:

```go
func (s *SQLiteStore) ListAllProxyTokensFiltered(ctx context.Context, filter ProxyTokenFilter) ([]*ProxyToken, int, error) {
    where := "WHERE 1=1"
    var args []interface{}

    if filter.Status != "" {
        switch filter.Status {
        case "active":
            where += " AND revoked_at IS NULL AND expires_at > datetime('now')"
        case "expired":
            where += " AND revoked_at IS NULL AND expires_at <= datetime('now')"
        case "revoked":
            where += " AND revoked_at IS NOT NULL"
        }
    }
    if filter.UserID != "" {
        where += " AND user_id = ?"
        args = append(args, filter.UserID)
    }
    if filter.Repo != "" {
        where += " AND repositories LIKE ?"
        args = append(args, "%"+filter.Repo+"%")
    }
    if filter.Scope != "" {
        where += " AND scopes LIKE ?"
        args = append(args, "%"+filter.Scope+"%")
    }

    // Count total matching rows.
    var total int
    countQuery := "SELECT COUNT(*) FROM proxy_tokens " + where
    if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
        return nil, 0, err
    }

    // Fetch page.
    limit := filter.Limit
    if limit <= 0 {
        limit = 25
    }
    query := fmt.Sprintf(
        "SELECT id, token_hash, token_prefix, token_type, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, last_used_at, request_count, created_at FROM proxy_tokens %s ORDER BY created_at DESC LIMIT %d OFFSET %d",
        where, limit, filter.Offset,
    )
    rows, err := s.db.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, 0, err
    }
    defer rows.Close()
    tokens, err := scanProxyTokenRows(rows)
    return tokens, total, err
}
```

**Step 3: Implement in postgres.go**

Same pattern but use `$N` parameter placeholders and `NOW()` instead of `datetime('now')`:

```go
func (s *PostgresStore) ListAllProxyTokensFiltered(ctx context.Context, filter ProxyTokenFilter) ([]*ProxyToken, int, error) {
    where := "WHERE 1=1"
    var args []interface{}
    argN := 1

    if filter.Status != "" {
        switch filter.Status {
        case "active":
            where += " AND revoked_at IS NULL AND expires_at > NOW()"
        case "expired":
            where += " AND revoked_at IS NULL AND expires_at <= NOW()"
        case "revoked":
            where += " AND revoked_at IS NOT NULL"
        }
    }
    if filter.UserID != "" {
        where += fmt.Sprintf(" AND user_id = $%d", argN)
        args = append(args, filter.UserID)
        argN++
    }
    if filter.Repo != "" {
        where += fmt.Sprintf(" AND repositories::text ILIKE $%d", argN)
        args = append(args, "%"+filter.Repo+"%")
        argN++
    }
    if filter.Scope != "" {
        where += fmt.Sprintf(" AND scopes::text ILIKE $%d", argN)
        args = append(args, "%"+filter.Scope+"%")
        argN++
    }

    var total int
    if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM proxy_tokens "+where, args...).Scan(&total); err != nil {
        return nil, 0, err
    }

    limit := filter.Limit
    if limit <= 0 {
        limit = 25
    }
    query := fmt.Sprintf(
        "SELECT %s FROM proxy_tokens %s ORDER BY created_at DESC LIMIT %d OFFSET %d",
        pgProxyTokenCols, where, limit, filter.Offset,
    )
    rows, err := s.db.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, 0, err
    }
    defer rows.Close()
    tokens, err := scanPostgresProxyTokenRows(rows)
    return tokens, total, err
}
```

**Step 4: Add unit tests**

Add tests to `sqlite_test.go` (and `postgres_test.go` if integration tests exist) that:
- Create several tokens with different repos, statuses, scopes
- Filter by status=active, verify only active returned
- Filter by repo substring, verify matches
- Verify total count is correct
- Verify limit/offset pagination works

**Step 5: Run tests, commit**

```bash
cd /Users/gary/Projects/ghp.ui-redesign && go test ./internal/database/...
git add internal/database/models.go internal/database/sqlite.go \
  internal/database/postgres.go internal/database/sqlite_test.go \
  internal/database/postgres_test.go
git commit -m "feat(db): add filtered and paginated token listing"
```

---

### Task 4: Admin Tokens — Filter Bar & Pagination UI

Wire the new `ListAllProxyTokensFiltered` into the admin tokens panel with a filter bar and pagination controls.

**Files:**
- Modify: `internal/web/sse.go` (update admin-tokens-panel template, update sendAdminTokensPanel, add filter handler)
- Modify: `internal/web/handler.go` (register filter route, add TokenFilterView, update UserView)
- Modify: `internal/web/static/theme.css` (filter bar styles, pagination styles)
- Modify: `e2e/tests/admin.spec.ts` (add filter/pagination tests)

**Step 1: Add username to TokenView for admin display**

In `handler.go`, add `Username` field to `TokenView`:

```go
type TokenView struct {
    ID         string
    Prefix     string
    Type       string
    Repos      string
    Scopes     []string
    SessionID  string
    Status     string
    ExpiryText string
    RawID      string
    Username   string // for admin display
}
```

Update `buildTokenViews` to accept an optional user lookup map, or create a new `buildAdminTokenViews` that joins user data. The simplest approach: add a `users` parameter to `buildTokenViews` — a `map[string]string` mapping userID to username. When nil, `Username` stays empty.

**Step 2: Update the admin-tokens-panel fragment template**

Replace the existing template with one that includes a filter bar and pagination:

```html
{{- define "admin-tokens-panel" -}}
<section id="admin-tokens-panel">
    <div class="section-header">
        <h2>All Tokens</h2>
        <button class="btn btn-primary" data-on:click="$agentOpen = true; $agentStep = 0">New Agent Token</button>
    </div>
    <div class="filter-bar">
        <select data-bind:filterStatus>
            <option value="">All statuses</option>
            <option value="active"{{ if eq .FilterStatus "active" }} selected{{ end }}>Active</option>
            <option value="expired"{{ if eq .FilterStatus "expired" }} selected{{ end }}>Expired</option>
            <option value="revoked"{{ if eq .FilterStatus "revoked" }} selected{{ end }}>Revoked</option>
        </select>
        <input type="text" placeholder="User..." data-bind:filterUser value="{{ .FilterUser }}">
        <input type="text" placeholder="Repository..." data-bind:filterRepo value="{{ .FilterRepo }}">
        <input type="text" placeholder="Scope..." data-bind:filterScope value="{{ .FilterScope }}">
        <button class="btn btn-ghost" data-on:click="@get('/ui/admin/tokens')">Filter</button>
    </div>
    {{ if .Tokens }}
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Prefix</th><th>Type</th><th>User</th><th>Repos</th>
                    <th>Scopes</th><th>Session</th><th>Status</th><th>Expires</th><th></th>
                </tr>
            </thead>
            <tbody>
                {{ range .Tokens }}
                <tr id="token-row-{{ .RawID }}">
                    <td class="text-mono">{{ .Prefix }}...</td>
                    <td><span class="badge badge-{{ .Type }}">{{ .Type }}</span></td>
                    <td>{{ .Username }}</td>
                    <td>{{ .Repos }}</td>
                    <td>{{ range .Scopes }}<span class="scope-chip">{{ . }}</span> {{ end }}</td>
                    <td>{{ if .SessionID }}{{ .SessionID }}{{ else }}-{{ end }}</td>
                    <td><span class="badge badge-{{ .Status }}">{{ .Status }}</span></td>
                    <td>{{ .ExpiryText }}</td>
                    <td>{{ if eq .Status "active" }}
                        <button class="btn btn-danger" onclick="if(!confirm('Revoke this token?'))event.stopImmediatePropagation()" data-on:click="@delete('/ui/tokens/{{ .RawID }}')">Revoke</button>
                    {{ end }}</td>
                </tr>
                {{ end }}
            </tbody>
        </table>
    </div>
    <div class="pagination">
        {{ if gt .Page 1 }}
        <button class="btn btn-ghost" data-on:click="$filterPage = {{ .PrevPage }}; @get('/ui/admin/tokens')">Previous</button>
        {{ end }}
        <span class="pagination-info">Page {{ .Page }} of {{ .TotalPages }}</span>
        {{ if lt .Page .TotalPages }}
        <button class="btn btn-ghost" data-on:click="$filterPage = {{ .NextPage }}; @get('/ui/admin/tokens')">Next</button>
        {{ end }}
    </div>
    {{ else }}
    <div class="empty-state">
        <p>No tokens found.</p>
    </div>
    {{ end }}
</section>
{{- end -}}
```

**Step 3: Update sendAdminTokensPanel to read filter signals**

Create a new `handleAdminTokensPanelSSE` that reads filter signals from the GET request:

```go
type adminTokenFilterSignals struct {
    FilterStatus string `json:"filterStatus"`
    FilterUser   string `json:"filterUser"`
    FilterRepo   string `json:"filterRepo"`
    FilterScope  string `json:"filterScope"`
    FilterPage   int    `json:"filterPage"`
}

func (h *Handler) handleAdminTokensPanelSSE(w http.ResponseWriter, r *http.Request) {
    var signals adminTokenFilterSignals
    _ = datastar.ReadSignals(r, &signals)

    page := signals.FilterPage
    if page < 1 {
        page = 1
    }
    pageSize := 25

    // Resolve username to userID if provided.
    var userID string
    if signals.FilterUser != "" {
        // Look up user by username substring — query users, find match.
        users, _ := h.store.ListUsers(r.Context())
        for _, u := range users {
            if strings.Contains(strings.ToLower(u.GitHubUsername), strings.ToLower(signals.FilterUser)) {
                userID = u.ID
                break
            }
        }
        if userID == "" && signals.FilterUser != "" {
            // No matching user — return empty results.
            userID = "no-match"
        }
    }

    filter := database.ProxyTokenFilter{
        Status: signals.FilterStatus,
        UserID: userID,
        Repo:   signals.FilterRepo,
        Scope:  signals.FilterScope,
        Limit:  pageSize,
        Offset: (page - 1) * pageSize,
    }

    tokens, total, err := h.store.ListAllProxyTokensFiltered(r.Context(), filter)
    if err != nil {
        h.logger.Error("failed to list filtered tokens", "error", err)
        tokens = nil
    }

    // Build user lookup for usernames.
    userMap := h.buildUserMap(r.Context())

    totalPages := (total + pageSize - 1) / pageSize
    if totalPages < 1 {
        totalPages = 1
    }

    sse := datastar.NewSSE(w, r)
    data := map[string]interface{}{
        "Tokens":       buildAdminTokenViews(tokens, userMap),
        "FilterStatus": signals.FilterStatus,
        "FilterUser":   signals.FilterUser,
        "FilterRepo":   signals.FilterRepo,
        "FilterScope":  signals.FilterScope,
        "Page":         page,
        "TotalPages":   totalPages,
        "PrevPage":     page - 1,
        "NextPage":     page + 1,
    }
    h.renderFragment(sse, "admin-tokens-panel", data)
}
```

Add helper to build username map:

```go
func (h *Handler) buildUserMap(ctx context.Context) map[string]string {
    users, err := h.store.ListUsers(ctx)
    if err != nil {
        return nil
    }
    m := make(map[string]string, len(users))
    for _, u := range users {
        m[u.ID] = u.GitHubUsername
    }
    return m
}

func buildAdminTokenViews(tokens []*database.ProxyToken, userMap map[string]string) []TokenView {
    views := buildTokenViews(tokens)
    for i, t := range tokens {
        if t.UserID != nil && userMap != nil {
            views[i].Username = userMap[*t.UserID]
        }
    }
    return views
}
```

**Step 4: Add filter signals to admin.html body**

Update the `data-signals` on the body tag to include filter signals:

```html
<body data-signals="{tab: 'users', ..., filterStatus: '', filterUser: '', filterRepo: '', filterScope: '', filterPage: 1}">
```

**Step 5: Add CSS for filter bar and pagination**

```css
.filter-bar {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
}

.filter-bar select,
.filter-bar input[type="text"] {
    padding: 0.5rem 0.75rem;
    font-size: 0.875rem;
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-surface);
    color: var(--color-text);
}

.filter-bar input[type="text"] {
    width: 10rem;
}

.pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 1rem;
    margin-top: 1rem;
    padding: 0.75rem 0;
}

.pagination-info {
    font-size: 0.875rem;
    color: var(--color-text-secondary);
}
```

**Step 6: Add E2E test for filtering**

```ts
test("filters tokens by status", async ({ page }) => {
    await page.goto("/admin");
    await expect(page.locator("#admin-users-panel table")).toBeVisible({ timeout: 5_000 });

    // Switch to tokens tab.
    await page.click('button.tab:has-text("Tokens")');
    await expect(page.locator("#admin-tokens-panel h2")).toContainText("All Tokens");

    // Filter by revoked status.
    await page.selectOption('#admin-tokens-panel select', 'revoked');
    await page.click('#admin-tokens-panel button:has-text("Filter")');

    // All visible status badges should be "revoked".
    const badges = page.locator('#admin-tokens-panel .badge-revoked');
    await expect(badges.first()).toBeVisible({ timeout: 5_000 });
});
```

**Step 7: Run tests, commit**

```bash
cd /Users/gary/Projects/ghp.ui-redesign && go build ./...
cd e2e && npx playwright test
git add internal/web/sse.go internal/web/handler.go \
  internal/web/static/theme.css internal/web/templates/admin.html \
  e2e/tests/admin.spec.ts
git commit -m "feat(ui): admin token filtering and pagination"
```

---

### Task 5: Admin Users — Expandable Token Cards

Make user rows clickable. Clicking a row fires an SSE GET to fetch that user's tokens as cards, displayed in an accordion row below.

**Files:**
- Modify: `internal/web/sse.go` (add user-tokens endpoint, add user-tokens-row fragment)
- Modify: `internal/web/handler.go` (register route)
- Modify: `internal/web/static/theme.css` (expandable row styles)
- Modify: `internal/web/templates/admin.html` (add expandedUser signal)
- Modify: `e2e/tests/admin.spec.ts` (add expand test)

**Step 1: Add the SSE endpoint**

In `sse.go`, add a handler that returns a user's token cards:

```go
func (h *Handler) handleAdminUserTokensSSE(w http.ResponseWriter, r *http.Request) {
    userID := r.PathValue("id")

    tokens, err := h.store.ListProxyTokens(r.Context(), userID)
    if err != nil {
        h.logger.Error("failed to list user tokens", "error", err)
        tokens = nil
    }

    sse := datastar.NewSSE(w, r)
    var buf bytes.Buffer
    if err := fragmentTemplates.ExecuteTemplate(&buf, "user-tokens-expansion", map[string]interface{}{
        "UserID": userID,
        "Tokens": buildTokenViews(tokens),
    }); err != nil {
        h.logger.Error("fragment render failed", "error", err)
        return
    }
    sse.PatchElements(buf.String())
}
```

**Step 2: Add the fragment template**

```html
{{- define "user-tokens-expansion" -}}
<tr id="user-expansion-{{ .UserID }}">
    <td colspan="3" class="expansion-cell">
        {{ if .Tokens }}
        <div class="token-grid">
            {{ range .Tokens }}
            {{ template "token-card" . }}
            {{ end }}
        </div>
        {{ else }}
        <p class="expansion-empty">No tokens for this user.</p>
        {{ end }}
    </td>
</tr>
{{- end -}}
```

**Step 3: Update admin-users-panel template for clickable rows**

Update the user rows in the `admin-users-panel` fragment to be clickable:

```html
{{ range .Users }}
<tr class="expandable-row" data-on:click="
    if ($expandedUser === '{{ .ID }}') {
        $expandedUser = '';
        document.getElementById('user-expansion-{{ .ID }}')?.remove();
    } else {
        if ($expandedUser) document.getElementById('user-expansion-' + $expandedUser)?.remove();
        $expandedUser = '{{ .ID }}';
        @get('/ui/admin/users/{{ .ID }}/tokens')
    }
">
    <td>{{ .Username }}</td>
    <td><span class="badge badge-{{ .Role }}">{{ .Role }}</span></td>
    <td>{{ .Created }}</td>
</tr>
{{ end }}
```

**Step 4: Add expandedUser signal to admin.html**

Add `expandedUser: ''` to the body `data-signals`.

**Step 5: Register route in handler.go**

```go
mux.Handle("GET /ui/admin/users/{id}/tokens", h.auth.RequireAdmin(http.HandlerFunc(h.handleAdminUserTokensSSE)))
```

**Step 6: Add CSS for expandable rows**

```css
.expandable-row {
    cursor: pointer;
}

.expandable-row:hover td {
    background: var(--color-bg);
}

.expansion-cell {
    padding: 1rem !important;
    background: var(--color-bg);
}

.expansion-empty {
    font-size: 0.875rem;
    color: var(--color-text-secondary);
    padding: 0.5rem 0;
}
```

**Step 7: Add E2E test**

```ts
test("clicking a user row expands to show their tokens", async ({ page }) => {
    await page.goto("/admin");
    await expect(page.locator("#admin-users-panel table")).toBeVisible({ timeout: 5_000 });

    // Click on a user row.
    const userRow = page.locator('#admin-users-panel tr.expandable-row').first();
    await userRow.click();

    // Expansion row should appear with token cards or empty message.
    const expansion = page.locator('[id^="user-expansion-"]');
    await expect(expansion).toBeVisible({ timeout: 5_000 });
});
```

**Step 8: Run tests, commit**

```bash
cd /Users/gary/Projects/ghp.ui-redesign && go build ./...
cd e2e && npx playwright test
git add internal/web/sse.go internal/web/handler.go \
  internal/web/static/theme.css internal/web/templates/admin.html \
  e2e/tests/admin.spec.ts
git commit -m "feat(ui): expandable user rows with token cards in admin view"
```

---

### Task Summary

| Task | Description | Key Files |
|------|-------------|-----------|
| 1 | Consistent nav header with avatars | templates, theme.css, handler.go |
| 2 | Fix admin tabs — on-demand SSE | sse.go, admin.html, handler.go |
| 3 | Database filtered token listing | models.go, sqlite.go, postgres.go |
| 4 | Admin tokens filter bar & pagination | sse.go, theme.css, admin.html |
| 5 | Admin users expandable token cards | sse.go, handler.go, admin.html |
