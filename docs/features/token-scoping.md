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

A repo-restricted token can only reach REST paths of the form
`/repos/{owner}/{repo}/...` for an allowed repository, plus a short list of
identity and service endpoints: `GET /`, `/user`, `/rate_limit`, `/meta`,
`/octocat` and `/zen`. Every other path is rejected with `403 Forbidden`,
because ghp cannot tie it to the allowlist. This includes
`/repositories/{id}`, `/search/*`, `/user/repos`, `/orgs/*`, `/users/*`,
`/gists` and package endpoints.

ghp rejects some request paths with `403 Forbidden` before any scope check.
This applies to all `ghx_` and `gha_` tokens.
A path is rejected if it contains a `.` or `..` segment or an empty segment (`//`).
A path is also rejected if, after URL decoding, it contains `?`, `#`, `%`, `\`
or a control character.
This stops a path such as `/repos/A/x/../../B/y/contents` from passing the
check as `A/x`.

ghp builds the upstream URL from the escaped request path.
Other encoded characters (for example `%2B` in a ref name) reach GitHub
unchanged.

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

### Deny by default

For any scoped token (a repository restriction, a permission restriction, or
both), REST requests are deny-by-default. ghp keeps a curated table that maps
each known REST method and path to a permission and level. A request that
matches no entry in the table, and is not on the identity allowlist above, is
rejected with `403 Forbidden`. The message names the method and path, for
example `Endpoint POST /user/repos is not permitted for scoped tokens`. The
counter `ghp_scope_unmapped_denied_total` records these denials.

Known limitations:

- The table is curated, so some legitimate GitHub endpoints are denied for
  scoped tokens until an entry is added. Use an open-scoped token, or ask the
  operator to add the endpoint.
- `GET /search/issues` (used by `gh search prs` and `gh search issues`) is
  denied for every scoped token. Search spans repositories and has no single
  permission.
- `HEAD` is evaluated as `GET`.

Rules that differ from the general area of the path:

| Endpoint | Permission |
|---|---|
| `actions/permissions/*`, `actions/runners/*` | `administration:read` (GET) / `administration:write` |
| `actions/variables/*` | `variables:read` (GET) / `variables:write` |
| `PUT`/`DELETE environments/{name}` (create, update or delete the environment) | `administration:write` |
| `DELETE git/refs/*`, `PATCH`/`DELETE releases/*`, `POST merges`, `POST dispatches` | `contents:write` |
| `readme`, `tags`, `git/ref/*`, `git/matching-refs/*` | `contents:read` |
| `keys`, `rulesets` | `administration:read` / `administration:write` |
| `POST forks` | `administration:write` |
| repository `labels`, `milestones`, `issues/comments/*` | `issues:read` / `issues:write` |
| `pulls/comments/*`, `PUT pulls/{n}/update-branch` | `pull_requests:read` / `pull_requests:write` |
| `PATCH check-runs/{id}`, `check-suites` writes | `checks:write` |

### Valid permission names

GHP accepts only canonical permission names. These are the GitHub App
repository and organization permission names that agent tokens pass to
GitHub, plus the names that scope enforcement uses. One name, `projects`, is
enforcement-only: the GraphQL Projects v2 tables use it, but it is not a
GitHub App permission name, so agent tokens should not rely on it.

`actions`, `administration`, `checks`, `codespaces`, `contents`,
`dependabot_secrets`, `deployments`, `discussions`, `environments`, `issues`,
`members`, `metadata`, `organization_administration`,
`organization_custom_roles`, `organization_hooks`, `organization_packages`,
`organization_plan`, `organization_projects`, `organization_secrets`,
`organization_self_hosted_runners`, `organization_user_blocking`, `packages`,
`pages`, `projects`, `pull_requests`, `repository_custom_properties`,
`repository_hooks`, `repository_projects`, `secret_scanning_alerts`,
`secrets`, `security_events`, `single_file`, `statuses`, `team_discussions`,
`variables`, `vulnerability_alerts`, `workflows`.

The level must be `read` or `write`. GHP does not accept aliases. For example,
`pulls:write` is rejected: the GitHub permission is `pull_requests`.

Token creation (`POST /api/tokens`, `ghp token create`) and scope updates
(`PATCH /api/tokens/{id}`) return HTTP 400 for an unknown name or level. The
error message lists the valid names. Each rejection increments
`ghp_token_scope_rejected_total` (label `reason`: `unknown_permission` or
`invalid_level`).

Tokens created before this check may still hold an unknown name. GHP does not
migrate them. They resolve as before, but the unknown entry never satisfies a
permission check. The server logs one warning per unknown name.

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
`github.com/vektah/gqlparser/v2`) and walked to extract three things:

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
  inside the allowlist. GraphQL mutations are also rejected for
  repository-restricted tokens — GitHub's mutation inputs identify their
  target with an opaque global node ID (`repositoryId`) rather than
  `owner`/`name`, which the proxy cannot statically map to the
  allowlist. Use the REST API for repo-scoped writes, or use a
  permission-only token if mutations across multiple repositories are
  required.
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
be statically validated against a token's repository allowlist. For
repository-restricted tokens, the proxy rejects any request that contains
even one such variable-driven `repository(...)` selection, even if other
literal allowlisted lookups are present in the same query — otherwise an
attacker could mix one literal allowlisted lookup with an unbounded
variable-driven lookup that bypasses the allowlist. Tokens with no
repository restriction (permission-only or open-scoped) are unaffected.
For requests that go through GraphQL static analysis the request body is
capped at 1 MiB to bound memory usage. Open-scoped tokens bypass static
analysis, so this cap does not apply to them.

Operators reading 403 responses with a "GraphQL request references unmapped
fields" message can use the named field as a hint for extending
`fieldScopeRequirements` or `mutationScopeRequirements` in
`internal/proxy/graphql.go` to cover legitimate use cases.

### Known limitations

- **Scalar leaves under always-allowed parents are not deny-by-default.**
  Without loading GitHub's full SDL the proxy cannot enumerate every
  scalar field name, so unmapped scalars projected directly under an
  always-allowed parent (e.g. `repository(owner, name) { someScalar }`)
  pass static analysis. The risk is bounded by the underlying
  credential's permissions and by GitHub's own access checks; operators
  who need stricter enforcement should map the affected scalar in
  `fieldScopeRequirements` or use REST scoping for the affected flow.
- **Repository-restricted GraphQL mutations are not supported.** GitHub
  mutation inputs identify their target by opaque global node ID
  (`repositoryId`), which the proxy cannot statically map to a
  repository. Use the REST API or a permission-only token instead.
- The scope regression rig tracks open scoping gaps; see Development → [Scope Regression Rig](../development/scope-regression-rig.md).

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
