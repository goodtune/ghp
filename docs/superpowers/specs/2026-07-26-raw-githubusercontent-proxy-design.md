# raw.githubusercontent.com proxy handler

**Date:** 2026-07-26
**Status:** Design approved, pending implementation

## Background

GHP proxies `api.github.com`, `github.com`, `codeload.github.com`, and
`*.githubcopilot.com`. It does not proxy `raw.githubusercontent.com`. Agents
holding a `ghx_` token therefore cannot fetch raw file URLs, and any raw
traffic that does occur is invisible to GHP — in a typical deployment it
collapses into a single `CONNECT` line in the upstream squid log.

### Research findings

Empirically verified against a private repository using an OAuth (`gho_`)
token, 2026-07-25:

| Method | Result |
| --- | --- |
| No credential | `404` |
| `Authorization: token gho_…` | `200` |
| `Authorization: Bearer gho_…` | `200` |
| Basic `user:token` | `200` |
| Basic `x-access-token:token` | `200` |
| Invalid token | `404` (existence masked, not `401`) |
| `POST` / `PUT` with valid token | `403` |

Additional observations:

- **No rate-limit surface.** `raw.githubusercontent.com` returns no
  `X-RateLimit-*`, no `X-OAuth-Scopes`, no `X-GitHub-SSO`. The equivalent
  `api.github.com` request with `Accept: application/vnd.github.raw` returns
  the full set.
- **Fastly edge cache.** `via: 1.1 varnish`, `x-cache: HIT`,
  `cache-control: max-age=300`, keyed by `vary: Authorization`. Private
  content is edge-cached but isolated per Authorization value (verified: same
  URL and cache-buster returns `200` with a token and `404` without).
- **`github.com/{owner}/{repo}/raw/{ref}/{path}` does not honour an
  `Authorization` header** (returns `404`). Only the
  `raw.githubusercontent.com` host does.
- **Not verified:** `ghs_` installation tokens. No GitHub App private key was
  available to mint one. All evidence above is OAuth-token evidence.
  Installation tokens behave consistently with OAuth tokens across the other
  backends GHP proxies, so this design assumes equivalence on raw. If that
  assumption proves wrong, only the `gha_` header path is affected — the
  query-token and anonymous paths carry no GHP credential.

### The `download_url` query token

The REST contents endpoint returns `download_url` values of the form
`https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}?token=…`.
Probed properties:

- Freshly minted per request — two calls 2s apart returned different values.
- Path-scoped, not repo-scoped — a token minted for one blob returns `404` on
  a different blob in the same repository.
- 31-character uppercase base32, opaque.
- Lifetime is undocumented for the contents endpoint. Community reports
  indicate roughly 7 days for private repositories, against 5 minutes for
  archive links. Treat it as days, not minutes.
- Not verifiably user-scoped. Assume it is not.

It is therefore a bearer capability for a single blob path, valid for days,
that GHP cannot attribute to an agent and cannot revoke.

GHP does not rewrite response bodies, so these URLs pass through to agents
unmodified.

### Enterprise proxy header enforcement

The corporate-proxy restriction header is
`sec-GitHub-allowed-enterprise: ENTERPRISE-ID`. Per the GitHub Enterprise
Cloud documentation, the supported endpoints for header injection are
`github.com/*`, `api.github.com/*`, and `*.githubcopilot.com`.

`*.githubusercontent.com` is listed under *"Endpoints that don't require
restriction"*, with the rationale that such endpoints *"only provide data, and
do not accept it."*

`raw.githubusercontent.com` is consequently **not subject to enterprise header
enforcement**. GitHub's threat model there addresses data ingress into
personal accounts; read-only egress of private repository content via a
personal token is out of scope by design. An enterprise that believes the
proxy header has closed off personal-account use still has this path open.

Source: [Restricting access to GitHub.com using a corporate proxy](https://docs.github.com/en/enterprise-cloud@latest/admin/configuring-settings/hardening-security-for-your-enterprise/restricting-access-to-githubcom-using-a-corporate-proxy)

## Goals

1. **Capability** — agents holding a `ghx_` token can fetch raw file URLs.
2. **Containment** — raw requests authenticated with a GHP-issued token are
   scope-enforced like every other backend.
3. **Observability** — raw traffic produces access log lines and metrics
   instead of a single opaque `CONNECT` entry.

## Non-goals

Rewriting `download_url` in API responses. This would make every raw fetch
attributable without requiring client cooperation, but it means GHP would
start buffering and rewriting response bodies, which it deliberately does not
do today. The design below is forward-compatible with adding it later: doing
so converts the `query_token` result class from unattributed passthrough into
a fully attributed path.

## Guiding principle

> GHP is an enforcement point for tokens it issued and a telemetry point for
> everything else.

This is to be added to `CLAUDE.md`. It is what makes the asymmetry below
deliberate rather than a half-finished enforcement point, and it should guide
future handlers for non-API GitHub hosts.

## Design

### Routing and placement

- New `backend.Raw = "raw.githubusercontent.com"` const in
  `internal/backend/backend.go`.
- New `case host == backend.Raw` in `newHostDispatch`
  (`internal/server/server.go:764`).
- New handler in `internal/proxy/raw.go`, wired in `server.go` alongside
  `codeloadHandler` and wrapped in `accessLogHandler(backend.Raw, …)`.

**Path grammar:** `^/+([^/]+)/([^/]+)/(.+)$` → owner, repo, remainder.

Only the first two segments are used for enforcement. This sidesteps the ref
ambiguity entirely: both `/{owner}/{repo}/{ref}/{path}` and the newer
`/{owner}/{repo}/refs/heads/{branch}/{path}` form yield the same owner/repo.
The remainder is never parsed into ref-versus-path; it is treated as opaque.

Owner and repo are lowercased before use as Prometheus labels, matching
`internal/proxy/codeload.go`.

Paths that do not match the grammar (fewer than three segments) are passed
through anonymously and not counted, matching how `codeload.go` treats
non-archive paths — the counter stays scoped to well-formed requests so label
cardinality remains predictable.

**Methods:** `GET` and `HEAD` only. Any other method returns `403` without
forwarding, mirroring upstream behaviour. The method check runs after path
parsing so the `denied_method` counter always carries real owner/repo labels;
a non-matching path with a disallowed method is passed through and left to
upstream to reject.

### Request classification

Evaluated in this order:

| Inbound | Action |
| --- | --- |
| `Authorization: ghx_…` / `gha_…` | Resolve token, enforce `contents:read` against the repository allowlist, strip any `?token=`, forward with the real credential |
| `?token=` present, no GHP token | Policy check, then passthrough unmodified, unattributed |
| Neither | Passthrough anonymously, unattributed |

`contents:read` matches the existing mapping for
`GET /repos/{owner}/{repo}/contents/…` in `internal/proxy/scope.go:29`.

Anonymous passthrough is unconditional — there is no `raw.require_token`
knob. Anonymous requests cannot reach private content by definition (GitHub
returns `404` without a credential), so blocking them buys no confidentiality
and breaks ordinary tooling that fetches public install scripts, action
manifests, and templates. They are still logged.

### Configuration

New `RawConfig` struct in `internal/config/config.go` following
`CodeloadConfig`'s shape, with a single field:

```yaml
raw:
  allow_query_token: true   # GHP_RAW_ALLOW_QUERY_TOKEN
```

Default `true`. When `false`, the query-token case returns `403` with a
message naming the policy, rather than a silent `404`.

`Raw` must be included in the in-place mutation set in `ReloadFrom`
(`config.go:466`) so `SIGUSR1` hot-reload takes effect without a restart, with
a `RawAllowQueryToken()` accessor taking the read lock, matching
`CodeloadRedirectTo()`.

### Accepted limitations

Two, both to be documented plainly rather than glossed:

1. **The query-token path is unenforced.** A `ghx_` token scoped to repository
   A can still fetch repository B's private content through this handler if
   the agent holds a GitHub-issued `?token=` for it. `allow_query_token:
   false` is the switch that closes this. Post-hoc attribution is possible by
   correlating a recent REST API request with a subsequent raw request from
   the same user-agent and source IP; the `x-github-request-id` response
   header provides a join key against GitHub's own audit log.
2. **No rate-limit visibility.** Raw returns no `X-RateLimit-*` headers, so
   this traffic will never appear in `ghp_github_ratelimit_*`. Quota consumed
   via raw is invisible to GHP by construction.

## Observability

### Access log

Reuses `accessLogHandler(backend.Raw, …)`, so the standard attribute set is
inherited. Two changes are required.

**Query redaction (general fix, not raw-specific).**
`internal/server/accesslog.go:125` currently emits `r.URL.RawQuery` verbatim.
Headers are redacted via `redactRequestHeader`, but query strings are not.
Passing through query-token raw requests would therefore write live GitHub
blob capabilities — valid for days — into the access log.

Add a `redactQueryParam(name string) bool` alongside the existing header
redactors and emit a rewritten query where sensitive values are replaced with
the same placeholder headers use. Redact `token`, `access_token`, and
`client_secret`. This improves every backend, not just raw.

**Attribution slot.** A new slot using the same mechanism as `CacheState` and
`CacheRepo`, carrying how the request authenticated: `proxy_token`,
`query_token`, or `anonymous`. Emitted as `ghp.raw.auth`, so a log query can
partition attributable from inferred traffic directly.

### Metrics

One new counter, mirroring `CodeloadRedirectTotal`:

```
ghp_raw_request_total{owner, repo, result}
```

`result` ∈ `authenticated`, `query_token`, `anonymous`, `denied_scope`,
`denied_policy`, `denied_method`.

For the header-authenticated path, reuse the existing
`ghp_proxy_decision_duration_seconds` stages rather than adding new ones —
`token_extraction`, `token_resolution`, `scope_enforcement`,
`github_token_resolution`, and `upstream_roundtrip` all apply unchanged,
labelled `token_type=proxy`. The two unattributed paths observe only
`upstream_roundtrip` with `token_type=unknown`, which reads correctly: no
decision was made, so there is no decision time to attribute.

## Testing

`internal/proxy/raw_test.go`, table-driven with an `httptest` upstream,
following `codeload_test.go`:

- Path parsing: both ref forms, owner/repo casing normalisation, malformed
  paths.
- Each of the three classification cases.
- `allow_query_token` true and false, including hot-reload behaviour.
- Method rejection for non-`GET`/`HEAD`.
- Scope denial for a repository outside the token's allowlist.
- Query token is stripped on the header path and preserved on the passthrough
  path.

`internal/metrics/metrics_test.go`: one case per `result` label value, per the
existing CLAUDE.md requirement that every metric has a test.

`internal/server/accesslog_test.go`: assert `token=` never appears in the
emitted `url.query` attribute.

## Documentation

- `docs/admin/configuration.md` — `raw.allow_query_token` in both the
  environment variable table and the full YAML reference.
- `docs/how-it-works.md` — classification behaviour and both stated
  limitations.
- `CLAUDE.md` — the guiding principle above, and a note that
  `raw.githubusercontent.com` is exempt from enterprise header enforcement so
  future contributors understand why the handler exists.
