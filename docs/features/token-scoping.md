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
      --type agent \
      --installation-id 12345678 \
      --repos owner/repo1,owner/repo2 \
      --scope contents:read,pull_requests:write

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

## GraphQL Scope Enforcement

ghp enforces token scopes on GraphQL requests for repository-restricted
and/or permission-restricted tokens via static analysis of the incoming
query. For those scoped-token requests the body is parsed (using
`vektah/gqlparser`) and walked to extract three things:

- **Required permission scopes**, derived from a curated map of
  `Mutation.<field>` and field-name → scope mappings (e.g.
  `Mutation.createIssue` → `issues:write`, `pullRequests` → `pull_requests:read`).
- **Referenced repositories**, extracted from `repository(owner, name)`
  arguments where both arguments are string literals.
- **Cross-repository fields** (e.g. `search`, `node`, `viewer.repositories`)
  that can return data from outside any explicit `repository(...)` selection.

The proxy uses the analysis to apply a deny-by-default policy:

- **Open-scoped tokens** bypass GraphQL static analysis entirely; the
  underlying credential's permissions remain the only enforcement layer.
- **Repository-restricted tokens** must reference at least one
  `repository(owner, name)` with literal arguments, and every referenced
  repository must appear in the token's allowlist. Cross-repository fields
  are rejected outright: ghp cannot statically prove their results stay
  inside the allowlist.
- **Permission-restricted tokens** must grant every scope the analysis
  identifies. Mutations whose name does not appear in the curated mutation
  map are rejected — the proxy never grants a write scope it cannot
  classify.
- **Subscriptions** are rejected unconditionally: GitHub's GraphQL endpoint
  does not support them over HTTP, and the proxy cannot stream-scope
  per-event payloads.
- **Unknown object-typed fields** (fields with their own selection set that
  do not appear in the allowlist or scope map) are rejected for any
  scoped token. Scalar leaves are permitted without a per-field mapping
  because their parent field's scope already gates them.

Variable-driven repository lookups (`repository(owner: $owner, ...)`) cannot
be statically validated; the analyzer treats them as if no repository was
referenced, so a repository-restricted token must use literal arguments. For
requests that go through GraphQL static analysis the request body is capped
at 1 MiB to bound memory usage. Open-scoped tokens bypass static analysis,
so this cap does not apply to them.

Operators reading 403 responses with a "GraphQL request references unmapped
fields" message can use the named field as a hint for extending
`fieldScopeRequirements` or `mutationScopeRequirements` in
`internal/proxy/graphql.go` to cover legitimate use cases.

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
