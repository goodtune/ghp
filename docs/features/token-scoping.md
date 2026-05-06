# Token Scoping

ghp issues short-lived tokens that control what an agent can access on GitHub.
Two dimensions of scoping are available — repository restrictions and permission
restrictions — and both are optional.

## Token Types

### Proxy Tokens (`ghx_`)

Proxy tokens are backed by a user's GitHub OAuth credential. When an agent uses
a proxy token, requests go through to GitHub using that user's access. The token
holder never sees the real credential.

Create a proxy token from the [web dashboard](../web-ui.md) or the CLI:

    ghp token create \
      --repo owner/repo \
      --scope contents:read,pull_requests:write \
      --duration 48h

### Agent Tokens (`gha_`)

Agent tokens are backed by a GitHub App installation rather than a specific
user. They are intended for automated workflows and CI pipelines where no
individual user context is appropriate.

Agent tokens require the administrator to configure a
[GitHub App](../admin/github-app.md) on the server. Only administrators can
create agent tokens:

    ghp token create \
      --app mybot \
      --installation myorg \
      --repos owner/repo1,owner/repo2 \
      --scope contents:read,pull_requests:write

The `--app` and `--installation` flags accept human-readable names (app name
and GitHub account login respectively) and resolve to IDs automatically. The
numeric `--installation-id` and `--app-id` flags are also available.

## Repository Restrictions

When a token specifies one or more repositories, ghp enforces that only those
repositories can be accessed. API requests targeting a different repository
are rejected with `403 Forbidden`.

- Proxy tokens use `--repo` (single repository)
- Agent tokens use `--repos` (comma-separated list)

If no repository is specified, the token is not restricted to any particular
repository — it can access any repository the underlying credential has access
to.

## Permission Restrictions

Tokens can specify which operations are permitted using permission scopes.
These follow the GitHub API permission model:

| Scope | Description |
|-------|-------------|
| `contents:read` | Read repository contents (files, commits) |
| `contents:write` | Push commits, create/update files |
| `pull_requests:read` | Read pull requests |
| `pull_requests:write` | Create and update pull requests |
| `issues:read` | Read issues |
| `issues:write` | Create and update issues |
| `metadata:read` | Read repository metadata (always permitted) |

If no scopes are specified, the token carries the full permissions of the
underlying credential without additional filtering.

## Open-Scoped Tokens

When a token has neither repository nor permission restrictions, it is
considered "open-scoped." Open-scoped tokens forward all requests directly to
GitHub using the underlying credential's full permissions. This is useful when
an agent legitimately needs broad access and scoping would be too restrictive.

Open-scoped tokens are the default for proxy tokens created without `--repo`
and `--scope` flags.

## GraphQL Limitation

Tokens that are restricted to specific repositories cannot use the GraphQL API.
GraphQL queries can span multiple repositories in a single request, and ghp
cannot reliably enforce repository restrictions on GraphQL without parsing
every query. Repository-restricted tokens that attempt a GraphQL request will
receive a `403 Forbidden` response.

Open-scoped and permission-only tokens (no repository restriction) can use
GraphQL, but ghp does not currently enforce permission scopes on GraphQL
requests; the effective permissions are those of the underlying GitHub
credential.

## Expiration and Revocation

All tokens have a configurable lifetime. The default is 24 hours, with a
server-configured maximum (default 7 days). Tokens can be revoked immediately
at any time from the CLI or web dashboard — once revoked, any further requests
using that token are rejected.

When the server has `tokens.allow_no_expiry` enabled, tokens can be created
with no expiry (`"duration": "never"` in the API, `--duration never` on the
CLI). Non-expiring tokens are useful for long-lived automation managed via
infrastructure-as-code (e.g. Terraform), where token lifecycle is controlled
through revocation rather than time-based expiry.
