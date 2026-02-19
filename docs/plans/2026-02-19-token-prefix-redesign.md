# Token Prefix Redesign: `ghx_` and `gha_` Tokens

**Date:** 2026-02-19
**Status:** Approved
**Branch:** feature/multi-virtualhost

## Problem

The proxy currently uses the `ghp_` prefix for issued tokens. This conflicts with GitHub's own `ghp_` prefix for personal access tokens, making it impossible to distinguish a genuine GitHub PAT from a proxy-issued token.

## Decision

Introduce two distinct token prefixes that avoid collision with GitHub's official prefixes (`ghp`, `gho`, `ghu`, `ghs`, `ghr`):

- **`ghx_`** — Proxy tokens. 1:1 replacement of the existing `ghp_` implementation. User-scoped, backed by a stored OAuth token (`ghu_` type). Used by agents acting on behalf of a specific user.
- **`gha_`** — Agent tokens. New type. App-scoped, backed by a GitHub App installation token (`ghs_` type). Used for autonomous workflows without a user context (automated code reviews, team management, etc.).

## Token Type Enum

```go
type TokenType string

const (
    TokenTypeProxy TokenType = "proxy"
    TokenTypeAgent TokenType = "agent"
)
```

Stored as a PostgreSQL `ENUM` and a SQLite `TEXT` with `CHECK` constraint.

Prefix-to-type mapping is centralized:

```go
var TokenPrefixes = map[TokenType]string{
    TokenTypeProxy: "ghx_",
    TokenTypeAgent: "gha_",
}

func TokenTypeFromPrefix(s string) (TokenType, bool)
```

## `ghx_` Token Flow (Renamed from `ghp_`)

Identical to current behavior with the prefix changed:

1. User authenticates via OAuth session.
2. `POST /api/tokens` with `{repository, scopes, duration, session_id}`.
3. Token generated as `ghx_<base62(32 random bytes)>`.
4. SHA-256 hash stored, linked to user's encrypted OAuth `GitHubToken` via `github_token_id`.
5. On resolve: hash lookup, load linked `GitHubToken`, decrypt, rewrite `Authorization` header.

The `repositories` field is a JSON array but will always contain a single element for proxy tokens.

## `gha_` Token Flow (New)

1. Admin authenticates via OAuth session (requires `admin` role).
2. `POST /api/tokens` with `{type: "agent", installation_id, repositories: [...], scopes}`.
3. Token generated as `gha_<base62(32 random bytes)>`.
4. SHA-256 hash stored with `installation_id` and `repositories`. `user_id` set to the creating admin for audit purposes. `github_token_id` is NULL.
5. On resolve: hash lookup, use `installation_id` to generate a `ghs_` installation access token via the App PEM, rewrite `Authorization` header.

Agent tokens have indefinite shelf-life but should be rotated for good management.

## App Credential Configuration

Required only when `gha_` tokens are in use:

- `GHP_GITHUB_APP_ID` — the App's numeric ID.
- `GHP_GITHUB_APP_PRIVATE_KEY` — PEM contents via env var.
- `GHP_GITHUB_APP_PRIVATE_KEY_FILE` — alternative: path to PEM file.

If a `gha_` token is presented but no App credentials are configured, the proxy returns a clear error. On startup, if App credentials are provided, the PEM is validated.

### Installation Token Management

A new `AppTokenProvider` component handles:

- Signing a JWT with the PEM (standard GitHub App auth).
- Calling `POST /app/installations/{id}/access_tokens` with the token's repositories and permissions.
- Caching the resulting `ghs_` token until near expiry (1 hour lifetime).
- Transparent renewal.

## Database Schema Changes

Migration 001 is rewritten (no production data exists). Key changes to `proxy_tokens`:

| Column | Before | After |
|--------|--------|-------|
| `token_type` | — | `ENUM('proxy','agent')` (PG) / `TEXT CHECK` (SQLite), `NOT NULL DEFAULT 'proxy'` |
| `user_id` | `NOT NULL` | Nullable (agent tokens set to creating admin for audit) |
| `github_token_id` | `NOT NULL` | Nullable (agent tokens don't use stored OAuth tokens) |
| `repository` | `TEXT NOT NULL` | Removed |
| `repositories` | — | `JSONB NOT NULL DEFAULT '[]'` (PG) / `TEXT NOT NULL DEFAULT '[]'` (SQLite) |
| `installation_id` | — | `BIGINT` nullable (agent tokens only) |

## Proxy Layer Changes

- `extractGhpToken` renamed to `extractClientToken`.
- Detection checks both `ghx_` and `gha_` prefixes via `TokenTypeFromPrefix()`.
- After hash lookup, resolution branches by `TokenType`:
  - `proxy` → existing OAuth decrypt path.
  - `agent` → App installation token generation path.

## Scope Model

Both token types use the same scope model (`permission:level` pairs like `contents:read`, `pulls:write`). Agent tokens support multiple repositories.

## What Does NOT Change

- `ghpr_` session token prefix (unrelated).
- `ghp_session` cookie name (product branding).
- `ghp_` Prometheus metric namespace (product namespace).

## File Impact Summary

- `internal/token/token.go` — type enum, dual prefixes, `generateToken(TokenType)`
- `internal/database/models.go` — `ProxyToken` model changes
- `internal/database/migrations/` — rewrite migration 001 (both PG and SQLite)
- `internal/proxy/passthrough.go` — `extractClientToken`, dual-prefix detection
- `internal/proxy/proxy.go` — resolution branching
- `internal/proxy/resolver.go` — branch by token type
- `internal/server/api.go` — accept type/installation_id/repositories in create
- `internal/config/` — App credential fields
- New: `AppTokenProvider` component (JWT, installation token, caching)
- `cmd/ghp/token.go` — CLI help text
- Tests, e2e, docs — prefix updates
