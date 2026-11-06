# REST deny-by-default for scoped tokens (#290, #291, #295)

## Problem

- #290: `ServeHTTP` checked a permission only when a rule in `scope.go`
  matched. A scoped `ghx_` token could call any unmapped endpoint, for
  example `DELETE /repos/W/git/refs/heads/x` with `contents:read`.
- #291: the repository allowlist ran only for `/repos/{o}/{r}` paths.
  `/repositories/{id}`, `/search/*`, `/user/repos`, `/orgs/...` and
  `/users/...` were forwarded for a repo-restricted token.
- #295: dot segments were not rejected. `/repos/A/x/../../B/y/contents`
  passed the allowlist as `A/x`.

## Decision

Open-scoped tokens (no repos and no scopes) are unchanged. For a scoped
token (any repo restriction or any permission restriction), the API host
evaluates each REST request in this order:

1. Path hygiene (all `ghx_`/`gha_` requests, before token resolution): a
   path with a `.` or `..` segment, or an empty segment (`//`), is a 403.
2. Non-repository allowlist: `GET`/`HEAD` on `/`, `/user`, `/rate_limit`,
   `/meta`, `/octocat`, `/zen`. These are allowed with no further check.
   They expose only the identity and service metadata that `gh auth status`
   and similar commands read. `/user` is now `GET`/`HEAD` only (it matched
   every method before, so `PATCH /user` was allowed as metadata).
3. Repository restriction: when the token has a repo restriction, the path
   must be `/repos/{o}/{r}[/...]` with an allowed `{o}/{r}`. Any other path
   is a 403 ("does not target a repository"). This denies
   `/repositories/{id}`, `/search/*`, `/user/repos`, `/orgs/*`, `/users/*`,
   `/projects/*`, `/gists`, and the org/user package endpoints.
4. Rule lookup: the method and path must match a rule in `scope.go`. No
   match is a 403 that names the method and path, and increments
   `ghp_scope_unmapped_denied_total{token_type,method}`. This is the
   deny-by-default step. `HEAD` matches as `GET`.
5. Permission check (unchanged): when the token has scope restrictions and
   the rule is not `metadata`, the token must hold `permission:level`.

All steps 2 to 5 are timed under the existing `scope_enforcement` stage.

## Newly mapped rules

| Endpoint | Permission |
|---|---|
| `DELETE git/refs/*` | contents:write |
| `GET git/ref/*`, `GET git/matching-refs/*` | contents:read |
| `GET readme[/dir]` | contents:read |
| `GET tags` | contents:read |
| `PATCH`/`DELETE releases/*` | contents:write |
| `POST merges` | contents:write |
| `POST dispatches` | contents:write |
| `GET keys`, `POST/DELETE keys` | administration:read / write |
| `labels`, `milestones` (repo level) | issues:read / write |
| `issues/comments[/id...]` | issues:read / write |
| `issues/{n}/(events|timeline|reactions)` GET | issues:read |
| `pulls/comments[/id...]` | pull_requests:read / write |
| `GET pulls/{n}/merge` | pull_requests:read |
| `PUT pulls/{n}/update-branch` | pull_requests:write |
| `PATCH check-runs/*`, `POST/PATCH check-suites/*` | checks:write |
| `rulesets` | administration:read / write |
| `GET forks`, `GET languages`, `GET contributors` | metadata |
| `POST forks` | administration:write |

## What is denied now that was forwarded before

For scoped tokens only:

- Any REST method and path with no rule (for example `POST /user/repos`,
  `/gists`, `PUT /repos/o/r/subscription`, `/repos/o/r/traffic/*`).
- For repo-restricted tokens, every path outside `/repos/{o}/{r}` except the
  allowlist above, even when a rule exists (packages, projects, org
  members, org security advisories). These cannot be tied to the allowlist.
- `GET /search/issues` (used by `gh search prs`): denied for every scoped
  token. Search is cross-repository and has no single permission. Use an
  open token for search.
- Non-`GET` methods on `/user`.

## Trade-offs and limits

- The rule table is curated, so some legitimate endpoints are now denied for
  scoped tokens until a rule is added. The 403 message names the method and
  path. The fix is to add a rule, not to relax the default.
- Path hygiene does not decode `%2F` in raw paths beyond Go's decoding of
  `URL.Path`; decoded dot segments are rejected.
