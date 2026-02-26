# Web UI Frontend Design

**Date:** 2026-02-26

## Overview

Rebuild the GitHub Proxy web frontend using Chi router, Datastar hypermedia framework, and vanilla CSS. Replace the existing `http.ServeMux` and custom web component-based UI with a server-driven hypermedia architecture.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Router | Chi globally, replacing `http.ServeMux` | Single routing pattern, better middleware composability |
| Frontend framework | Datastar via CDN | Server-driven, no JS build step, SSE for partial updates |
| URL convention | Trailing slash canonical | Safe wildcard matching; `middleware.RedirectSlashes` |
| Template serving | Embedded + filesystem override in dev mode | Single binary for prod, hot reload for dev |
| Wizard state | Encrypted cookie | Stateless across instances for horizontal scaling |
| Permission names | GitHub canonical (`InstallationPermissions` JSON tags) | Fix existing `pulls` bug, single source of truth |
| JSON APIs | Kept alongside HTML UI | No breakage for CLI/agent consumers |
| Dark mode | Deferred (CSS custom properties plumbed) | Not critical for initial delivery |
| CSS | Single vanilla stylesheet, no build tools | Matches project philosophy |

## Architecture

### Router Migration

Replace `http.ServeMux` with `chi.Router` in `internal/server/`. All routes re-registered on Chi.

Middleware stack:
- `middleware.Logger` (request logging)
- `middleware.Recoverer` (panic recovery)
- `middleware.RedirectSlashes` (trailing slash enforcement)
- Existing `RequireAuth`, `RequireAdmin`, rate limiters adapted to Chi's `func(http.Handler) http.Handler`

Host-based routing preserved via top-level middleware dispatching by `Host` header. Proxy catch-all routes register as Chi wildcards.

### Datastar Integration

Full page loads return complete HTML via `template.ExecuteTemplate`. Partial updates use `datastar.NewSSE(w, r)` + `sse.PatchElements(...)` for:
- Token wizard modal (open, step transitions, create)
- Revoke confirmation dialogs
- Admin token table filtering

Modal pattern: empty `<div id="modal-overlay">` in base layout. Server patches content into it via SSE. Dismiss (X) is client-side signal toggle, no server round-trip.

### Wizard State

Each wizard step POSTs form data. Handler merges with accumulated state from an encrypted `ghp_wizard` cookie (signed + encrypted using app's existing encryption key). Returns next step HTML via SSE. Final submit reads cookie, creates token, clears cookie.

### Template Structure

```
internal/web/templates/
  base.html, header.html, login.html, dashboard.html,
  token_card.html, token_wizard_step{1-4}.html,
  token_created.html, revoke_confirm.html, empty_state.html,
  admin_layout.html, admin_users.html, admin_user_detail.html,
  admin_tokens.html, logout.html
```

Embedded via `//go:embed`. When `dev_mode` is true, loaded from filesystem for hot reload.

### Static Files

```
internal/web/static/
  style.css, mascot.png, mascot-grey.png
```

Existing `ghp-repo-select.js` and `ghp-permission-select.js` removed — functionality moves server-side with Datastar.

## Permission System Fix

### Problem

The codebase uses `pulls` as the scope name, but GitHub's API uses `pull_requests` (the JSON tag on `InstallationPermissions.PullRequests`). This aliasing is a bug source.

### Solution

Adopt GitHub's canonical JSON field names from `go-github`'s `InstallationPermissions` struct as the single source of truth.

A permission registry maps each permission to display metadata:

```go
type Permission struct {
    Key         string   // JSON tag, e.g. "pull_requests"
    DisplayName string   // e.g. "Pull requests"
    Description string
    Levels      []string // e.g. ["read", "write"]
}
```

Changes required:
- `internal/proxy/scope.go`: update regex rules from `"pulls"` to `"pull_requests"`
- `internal/token/`: update scope parsing/formatting
- Database migration: update stored `pulls` to `pull_requests` in scopes JSON
- CLI flags: update `--scope` examples in help text
- Tests: update all `"pulls"` references

### Wizard Display

Step 2 shows a curated common set by default (~10 permissions coding agents need: actions, checks, contents, issues, metadata, pull_requests, statuses, deployments, workflows, packages). A "Show all permissions" toggle expands to the full list from `InstallationPermissions`.

## URL Scheme

All URLs end with `/`.

### Public
- `GET /login/` — login page
- `GET /auth/github/` — OAuth redirect
- `GET /auth/github/callback/` — OAuth callback

### Authenticated
- `GET /dashboard/` — user token cards
- `GET /dashboard/token/add/` — open wizard (SSE)
- `POST /dashboard/token/add/` — wizard steps + create (SSE)
- `GET /dashboard/token/{id}/revoke/` — revoke confirm (SSE)
- `POST /dashboard/token/{id}/revoke/` — execute revoke (SSE)
- `GET /logout/` — logout confirmation
- `POST /logout/` — execute logout

### Admin
- `GET /admin/` — users table
- `GET /admin/tokens/` — all tokens with filters
- `GET /admin/tokens/add/` — admin wizard (SSE)
- `POST /admin/tokens/add/` — admin wizard steps + create (SSE)
- `GET /admin/tokens/{id}/revoke/` — revoke confirm (SSE)
- `POST /admin/tokens/{id}/revoke/` — execute revoke (SSE)
- `GET /admin/{username}/` — user's tokens
- `GET /admin/{username}/{id}/revoke/` — revoke confirm (SSE)
- `POST /admin/{username}/{id}/revoke/` — execute revoke (SSE)

### Unchanged
- `/api/*` — JSON API endpoints
- `/api/v3/*`, `/api/graphql` — GitHub proxy
- `/metrics` — Prometheus
- `/docs/` — embedded documentation
- `/static/` — static files
- `/.well-known/jwks.json` — JWKS

## CSS Design System

Single `style.css` using CSS custom properties:
- Background: warm off-white (`#f5f0eb`)
- Cards: white with subtle shadow
- Primary action: steel blue (`#4a76a8`)
- Danger: muted red, outlined
- Admin banner: red (`#8b2500`)
- Status badges: green (active), grey (revoked), amber (expired)
- Role badges: grey (user), blue (admin)
- Permission tags: light tan background, monospace, rounded pills

Layout: system font stack, max-width ~1100px, CSS Grid (3/2/1 columns responsive). Dark mode selector `[data-theme="dark"]` defined but empty for future use.

## Dependencies Added

```
github.com/go-chi/chi/v5
github.com/starfederation/datastar-go/datastar
```

No other new dependencies.
