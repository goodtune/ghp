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

The allowlist compare ignores case for ASCII letters only. A non-ASCII
spelling that Unicode case rules would map to an allowed name (for example
`ſ`, U+017F, for `s`, or the Kelvin sign, U+212A, for `k`) does not match.
GitHub owner and repository names are ASCII. The same rule applies to the
releases and codeload allow lists, the enterprise exception match list, the git cache, installation and team cache keys, and
the admin user list.

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
| `actions/workflows/*` (list, get, runs; `PUT enable`/`disable`, `POST dispatches`) | `actions:read` (GET) / `actions:write` |
| `actions/permissions/*`, `actions/runners/*` | `administration:read` (GET) / `administration:write` |
| `actions/variables/*` | `variables:read` (GET) / `variables:write` |
| `PUT`/`DELETE environments/{name}` (create, update or delete the environment) | `administration:write` |
| `DELETE git/refs/*`, `PATCH`/`DELETE releases/*`, `POST merges`, `POST dispatches` | `contents:write` |
| `readme`, `tags`, `git/ref/*`, `git/matching-refs/*` | `contents:read` |
| `keys`, `rulesets` | `administration:read` / `administration:write` |
| `POST forks` | `administration:write` |
| repository `labels`, `milestones`, `issues/comments/*` | `issues:read` / `issues:write` |
| `pulls/comments/*`, `PUT pulls/{n}/update-branch` | `pull_requests:read` / `pull_requests:write` |
| Reactions: `issues/{n}/reactions`, `issues/comments/{id}/reactions` (GET, `POST`, `DELETE .../reactions/{id}`) | `issues:read` / `issues:write` |
| Reactions: `pulls/comments/{id}/reactions` (GET, `POST`, `DELETE .../reactions/{id}`) | `pull_requests:read` / `pull_requests:write` |
| Reactions: commit comment `comments/{id}/reactions` (GET, `POST`, `DELETE .../reactions/{id}`) | `contents:read` / `contents:write` |
| Classic projects: `projects/*`, `repos/{o}/{r}/projects`, `orgs/{o}/projects` | `projects:read` / `projects:write` (see [Permission aliases](#permission-aliases)) |
| `PATCH check-runs/{id}`, `check-suites` writes | `checks:write` |

### Valid permission names

GHP accepts only canonical permission names. These are the repository and
organization permission names of the GitHub App permissions object (the
`app-permissions` schema in GitHub's REST description, used by
[Create an installation access token for an app](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)),
plus the names that scope enforcement uses. Account (user) permissions such
as `gpg_keys` are not accepted. GHP also keeps `variables` and
`team_discussions`, which older tokens use.

`actions`, `administration`, `artifact_metadata`, `attestations`, `checks`,
`code_quality`, `codespaces`, `contents`,
`custom_properties_for_organizations`, `dependabot_secrets`, `deployments`,
`discussions`, `enterprise_custom_properties_for_organizations`,
`environments`, `issues`, `members`, `merge_queues`, `metadata`,
`organization_administration`, `organization_announcement_banners`,
`organization_copilot_agent_settings`, `organization_copilot_requests`,
`organization_copilot_seat_management`, `organization_custom_org_roles`,
`organization_custom_properties`, `organization_custom_roles`,
`organization_events`, `organization_external_properties_for_repos`,
`organization_hooks`, `organization_packages`,
`organization_personal_access_token_requests`,
`organization_personal_access_tokens`, `organization_plan`,
`organization_projects`, `organization_secrets`,
`organization_self_hosted_runners`, `organization_user_blocking`,
`packages`, `pages`, `projects`, `pull_requests`,
`repository_custom_properties`, `repository_hooks`, `repository_projects`,
`secret_scanning_alerts`, `secrets`, `security_events`, `single_file`,
`statuses`, `team_discussions`, `variables`, `vulnerability_alerts`,
`workflows`.

### Permission aliases

Two names have special handling. Both checks run inside the
`scope_enforcement` decision stage.

- `projects` is an enforcement name. The GraphQL Projects v2 tables and the
  classic REST project rules (including the repository-level
  `repos/{o}/{r}/projects` rules) require `projects:<level>`.
  `projects:<level>`, `repository_projects:<level>` and
  `organization_projects:<level>` each satisfy that requirement on their own.
  The levels match as usual: read satisfies read, write satisfies read and
  write, and read never satisfies write. The alias does not bypass anything
  else: the repository allowlist still applies, and GitHub still runs its own
  permission check on the forwarded request.
- Agent (`gha_`) tokens: GitHub has no `projects` App permission, so GHP
  mints `projects:<level>` at GitHub as both `repository_projects` and
  `organization_projects` at that level. When the token also names one of
  those keys, the higher level wins. This grant is wider than a
  repository-only need. If a token needs only repository projects, request
  `repository_projects` directly instead of `projects`.
- `workflows:read` is **deprecated**. GitHub's `workflows` permission has
  only a write level, and it controls editing workflow files. GitHub gates
  the workflow REST endpoints (list, get, enable, disable, dispatch) on
  `actions`. GHP still accepts `workflows:read` for one release. Creating a
  token with it logs a warning. Enforcement treats it as `actions:read`, and
  agent tokens send it to GitHub as `actions:read`. Use `actions:read`
  instead. `workflows:write` is unchanged and does not grant `actions:read`.

Behaviour change: before this release the workflow endpoints required
`workflows:read`/`workflows:write`. A token with `workflows:write` and no
`actions` permission can no longer list, enable, disable or dispatch
workflows; add `actions:read` or `actions:write`.

The level must be `read` or `write`. Apart from the aliases above, GHP does not accept aliases. For example,
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

## github.com and codeload.github.com

Scoped tokens are also checked on the `github.com` and `codeload.github.com`
virtual hosts. GHP maps each request to a repository and a permission. Then it
applies the same repository allowlist and permission checks as on the API.

| Virtual host | Path | Methods | Permission |
|---|---|---|---|
| `github.com` | `/{owner}/{repo}.git/info/refs?service=git-upload-pack`, `/{owner}/{repo}.git/git-upload-pack` | GET, POST | `contents:read` |
| `github.com` | `/{owner}/{repo}.git/info/refs?service=git-receive-pack`, `/{owner}/{repo}.git/git-receive-pack` | GET, POST | `contents:write` |
| `github.com` | `/{owner}/{repo}/archive/...` | GET, HEAD | `contents:read` |
| `github.com` | `/{owner}/{repo}/releases/download/...` | GET, HEAD | `contents:read` |
| `codeload.github.com` | `/{owner}/{repo}/{tar.gz,zip,legacy.tar.gz,legacy.zip}/{ref}` | GET, HEAD | `contents:read` |

If a scoped token sends any other request to these hosts, GHP denies it with
403. This includes `info/refs` without a known `service`, other `.git/` paths,
and web pages. The denial applies even to a token that has only a repository
restriction, because GHP cannot prove that an unmapped path stays inside the
allowlist. Open-scoped tokens and requests without a GHP token are not
changed. On `codeload.github.com`, GHP always replaces a GHP token with the
real credential, so a `ghx_` or `gha_` token never goes to GitHub.

The scope check on `codeload.github.com` runs before the
[codeload redirect](codeload.md). On `github.com`, the
[release download controls](release-controls.md) run first. In `redirect`
mode, an out-of-scope release download therefore still gets a redirect to the
operator's mirror. GHP does not send a credential to GitHub for it.

## GraphQL Scope Enforcement

ghp enforces token scopes on GraphQL requests for repository-restricted
and/or permission-restricted tokens via static analysis of the incoming
query. For those scoped-token requests the body is parsed (using
`github.com/vektah/gqlparser/v2`) and walked to extract three things:

- **Required permission scopes**, derived from a curated map of
  `Mutation.<field>` and field-name → scope mappings (e.g.
  `Mutation.createIssue` → `issues:write`, `pullRequests` → `pull_requests:read`).
- **Referenced repositories**, extracted from `repository(owner, name)`
  arguments where each argument is a string literal or a `String` variable
  with a string value (see below).
- **Cross-repository fields** (e.g. `search`, `node`, `viewer.repositories`)
  that can return data from outside any explicit `repository(...)` selection.

The proxy uses the analysis to apply a deny-by-default policy:

- **Open-scoped tokens** bypass GraphQL static analysis entirely; the
  underlying credential's permissions remain the only enforcement layer.
- **Repository-restricted tokens** must reference at least one pinned
  `repository(owner, name)`, and every referenced
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

A `repository(owner, name)` lookup is *pinned* to a repository when each
of `owner` and `name` is one of these:

- a literal string, for example `repository(owner: "octo", name: "app")`;
- a variable `$v` that the operation declares with the type `String` or
  `String!` (not a list), and whose value in the request's `variables`
  object is a JSON string. This is the form that the GitHub CLI (`gh`)
  sends.

A variable does not pin the lookup when its value is `null`, a number, a
boolean, an array or an object, or when the key is not in `variables`.
The default value in the operation (`$v: String = "app"`) is never used.
No variable pins a lookup when the `variables` object has duplicate keys,
or when the document has more than one operation: in these cases the
proxy and GitHub could read different values. The proxy forwards the
same bytes that it analyses.

For scoped tokens the request body must be a JSON object whose top-level
keys are each `query`, `operationName`, `variables` or
`extensions` exactly, after JSON string decoding (case-sensitive, no Unicode folding), with no duplicates. Any other
key, including `Query` or a look-alike such as `variableſ`, gives a 400.

For repository-restricted tokens, the proxy rejects any request that
contains even one unpinned `repository(...)` selection, even if other
allowlisted lookups are present in the same query. Every pinned
repository, literal or variable, must be in the allowlist. Tokens with no
repository restriction (permission-only or open-scoped) are unaffected.

### Cross-repository subtrees

Some fields return an object that can belong to a repository outside the
allowlist, even when the query starts at a pinned `repository(owner, name)`.
For repository-restricted tokens ghp applies two rules to them. Each rule
only adds a cross-repository denial; the scope requirements stay the same,
so permission-only tokens are not affected.

- **Metadata-only subtrees.** `headRepository`, `headRepositoryOwner`,
  `parent` (`Repository.parent` and `Issue.parent`), `subIssues`,
  `blockedBy` and `blocking` can point to a fork, an owner or an issue in
  another repository. Beneath these fields a query can select only
  metadata: the always-allowed fields (for example `id`, `name`,
  `nameWithOwner`, `url`, `owner { login }`, `repository { nameWithOwner }`)
  and the scalar leaves `number`, `title` and `state`. Any other field, for
  example `headRepository { issues { ... } }`, `parent { body }` or
  `headRepository { object(expression: ...) { ... } }`, is a
  cross-repository field and the request gets a 403 that names it (for
  example `headRepository.issues`). `gh pr view` and `gh issue view` select
  only metadata here, so they keep working.
- **User-level connections.** `issues`, `pullRequests`, `issueComments`
  and `commitComments` are cross-repository unless their immediate parent
  is a pinned `repository(owner, name)` lookup. Under `viewer`, `user`,
  `organization`, `author`, `assignees`, `owner`, a bare
  `Issue.repository`, a root lookup or a metadata-only subtree they return
  data from every repository the credential can see, so the request gets a
  403 that names the parent and the field (for example `viewer.issues` or
  `author.issues`). Fragments do not change the parent: inside
  `author { ... on User { issues { ... } } }` the parent of `issues` is
  `author`.

### Introspection-only queries

A query whose root selections are only `__type`, `__schema` or
`__typename` reads no repository data. A repository-restricted token does
not need a `repository(owner, name)` selection for such a query. gh sends
these probes before some commands (for example
`query PullRequest_fields2 { WorkflowRun: __type(name: "WorkflowRun") { fields(includeDeprecated: true) { name } } }`).
All other checks still apply: a field under `__type` or `__schema` that is
not in the allowlist is denied as unmapped, and a query that adds any other
root field (for example `viewer`) still needs a pinned repository.

### Root object lookups

The root fields `node(id:)`, `nodes(ids:)`, `resource(url:)` and
`search(...)` fetch objects of any type by global ID, URL or search query.
The field name does not tell ghp which type the client reads, so for
permission-restricted tokens ghp gates these lookups on the type condition
of each fragment beneath them:

| Type condition | Required scope |
|---|---|
| `Issue` | `issues:read` |
| `PullRequest` | `pull_requests:read` |
| `Discussion` | `discussions:read` |
| `Commit`, `Release` | `contents:read` |
| `CheckRun`, `CheckSuite` | `checks:read` |
| `StatusContext` | `statuses:read` |
| `Repository`, `User`, `Organization`, `Bot`, `Team` | `metadata:read` |

Inline fragments (`... on Issue { body }`) and named fragments
(`...F` with `fragment F on Issue`) are both checked. A fragment with no
type condition (`... @include(if: $x) { ... }`) is transparent: the
fragments inside it are checked. For `search`, the fragments under `nodes`
and `edges { node }` are checked, and scalar fields such as `issueCount`
can be selected beside them.

ghp rejects the request as unmapped when a lookup has no fragment (for
example `{ node(id: "...") { id } }`, or a `search` that selects only
counts), when a fragment names a type that is not in the table (including
interfaces such as `Node`), or when a field other than `id` or
`__typename` is selected outside a fragment. The fields inside a fragment
are then checked as usual. A fragment nested directly in the body of a
gated fragment must have the same type condition, or it is gated the
same way and its scope is also required: `... on Bot { ...F }` with
`fragment F on Issue` needs `issues:read` as well as `metadata:read`. The same field names in nested positions, for
example `Connection.nodes`, are pagination helpers and are not affected.
These four lookups are still cross-repository fields, so
repository-restricted tokens cannot use them.

At a mutation root, `__typename` needs no scope. All other mutation root
fields still need a mapped write scope, and a mutation that selects only
`__typename` is still rejected for scoped tokens.
For requests that go through GraphQL static analysis the request body is
capped at 1 MiB to bound memory usage. Open-scoped tokens bypass static
analysis, so this cap does not apply to them.

Operators reading 403 responses with a "GraphQL request references unmapped
fields" message can use the named field as a hint for extending
`fieldScopeRequirements`, `mutationScopeRequirements` or
`typeConditionScopeRequirements` in
`internal/proxy/graphql.go` to cover legitimate use cases.

### gh CLI commands

With a permission-restricted token, each `gh` 2.102.0 command needs these
scopes (`metadata:read` is implied). The scope regression rig and the
query corpus in `rig/corpus/gh/` check this table.

| Command | Scopes |
|---|---|
| `gh repo view` | `contents:read` (the README is read with REST) |
| `gh repo list` | `metadata:read` |
| `gh pr list` | `pull_requests:read` |
| `gh pr view` | `pull_requests:read`, `issues:read`, `contents:read`, `checks:read`, `statuses:read`, `actions:read`; `projects:read` for project items |
| `gh pr status` | `pull_requests:read`, `contents:read`, `checks:read`, `statuses:read`, `administration:read` (`baseRef.branchProtectionRule`) |
| `gh pr checks` | `pull_requests:read`, `contents:read`, `checks:read`, `statuses:read`, `actions:read` |
| `gh pr create` | `pull_requests:write`, `issues:read` (`Repository.parent` has the same name as `Issue.parent`) |
| `gh issue list` | `issues:read` |
| `gh issue view` | `issues:read`; `projects:read` for project items |
| `gh label list` | `issues:read` |
| `gh release list` | `contents:read` |
| `gh search prs` | denied: `GET /search/issues` is denied for every scoped token |

With a repository-restricted token, `gh repo list`, `gh pr status`,
`gh pr checks` and `gh search prs` are denied because they use
cross-repository fields. Their introspection probes (for example
`Release_fields`, `SearchType_enumValues`, `PullRequest_fields2`) are
allowed (see [Introspection-only queries](#introspection-only-queries)),
so `gh release list` works.

### Known limitations

- **Some harmless root lookups are denied for every scoped token.** A
  `search` that selects only counts (for example `repositoryCount`), a
  root `node`, `nodes` or `resource` that selects only `id` or
  `__typename`, and `textMatches` under `search { edges { ... } }` have no
  fragment type that ghp can gate on, so they are rejected as unmapped.
  Add a fragment with a mapped type condition (for example
  `... on Repository { id }`) to send such a query.
- **Scalar leaves under always-allowed parents are not deny-by-default.**
  Without loading GitHub's full SDL the proxy cannot enumerate every
  scalar field name, so unmapped scalars projected directly under an
  always-allowed parent (e.g. `repository(owner, name) { someScalar }`)
  pass static analysis. The risk is bounded by the underlying
  credential's permissions and by GitHub's own access checks; operators
  who need stricter enforcement should map the affected scalar in
  `fieldScopeRequirements` or use REST scoping for the affected flow.
- **Variable pinning trusts the `variables` object of the forwarded
  body.** A lookup with variables is checked against the values that the
  request sends, which are the values that GitHub uses. A client that
  sends duplicate keys in `variables`, more than one operation, or a non-string value
  gets a 403 for a repository-restricted token.
- **Metadata-only subtrees disclose some data from other repositories.**
  Under `headRepository`, `headRepositoryOwner`, `parent`, `subIssues`,
  `blockedBy` and `blocking` a repository-restricted token can read
  metadata about a fork, owner or linked issue outside its allowlist: the
  name and owner of the repository, and the `number`, `title` and `state`
  of a linked issue. This keeps `gh pr view` and `gh issue view` working.
  Everything else under these fields is denied (see
  [Cross-repository subtrees](#cross-repository-subtrees)). A query that
  selects `viewerPermission` under `Repository.parent` (as
  `gh pr create` does) is denied; repository-restricted tokens cannot send
  the `createPullRequest` mutation in any case.
- **Cross-repository rules match field names and the immediate parent.**
  ghp does not load GitHub's schema. `issues`, `pullRequests`,
  `issueComments` and `commitComments` are allowed only directly under a
  pinned `repository(owner, name)`; any other parent is treated as
  cross-repository, even where the real type would stay inside the
  repository.
- **`contexts` needs only `checks:read`.** A table entry holds one scope.
  `StatusCheckRollup.contexts` returns check runs and commit statuses, and
  is mapped to `checks:read`. A `... on StatusContext` fragment inside it
  also needs `statuses:read`, as does `statusContextCountsByState`.
- **`projectItems` and `fieldValueByName` need the `projects` scope.**
  Grant `projects:read` to let `gh issue view` and `gh pr view` read the
  project items of an issue or pull request.
- **`labels`, `milestone` and `comments` need `issues:read`.** The names
  are the same on issues and pull requests, so the stricter meaning is
  used: a token with only `pull_requests:read` cannot select them.
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
