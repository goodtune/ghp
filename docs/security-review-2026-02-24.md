# Security Review — 2026-02-24

**Reviewer:** Automated security review (Claude)
**Scope:** Full codebase review of all source files, configuration, templates, deployment, and CI/CD
**Objective:** Identify security concerns and produce actionable recommendations for GitHub issue tracking

---

## Acknowledged Trade-offs

The following risk is acknowledged and accepted by the project:

- **Secrets stored alongside encrypted data.** The database contains AES-256-GCM
  encrypted GitHub tokens, but the encryption key is stored in the same
  configuration layer (config file or environment variable). If the database
  file is exfiltrated alongside the config/env, the tokens are recoverable.
  This is accepted for the "home user" deployment model. A Vault-backed secret
  engine is under development on a separate branch for production use.

---

## Findings

### SEC-001: Session cookie missing `Secure` flag

**Severity:** High
**Location:** `internal/auth/auth.go:332-339`

The session cookie is set with `HttpOnly: true` and `SameSite: Lax`, but the
`Secure` flag is never set. When the server is running behind TLS (which is the
intended production configuration), this means the cookie can be transmitted
over plain HTTP if a user is tricked into visiting an HTTP URL or if an HTTP
redirect server is misconfigured.

The logout cookie at `internal/auth/auth.go:348-354` has the same omission,
though the impact is lower since it clears the cookie.

**Recommendation:** Set `Secure: true` on all session cookies when TLS is
configured or when `BaseURL` uses an `https://` scheme. Consider making the
`Secure` flag always-on unless explicitly in dev mode.

---

### SEC-002: In-memory sessions are not bounded or pruned

**Severity:** Medium
**Location:** `internal/auth/auth.go:46-47`, `internal/auth/auth.go:167-178`

Sessions are stored in an unbounded `map[string]*Session`. While expired
sessions are correctly rejected on lookup, they are never deleted from the map.
An attacker who can trigger many OAuth login flows (or, in dev mode, many
`/auth/test-login` requests) can cause unbounded memory growth.

The OAuth state tokens (`states` map at line 50) have the same issue — they are
cleaned on successful validation but never pruned if the callback is never
completed.

The `brokerStates` map (line 53) does have cleanup of expired entries during
new broker authorization requests (`internal/auth/broker.go:48-52`), which is
better but still relies on new requests arriving to trigger cleanup.

**Recommendation:** Implement a periodic goroutine (e.g., every 5 minutes) that
prunes expired entries from `sessions`, `states`, and `brokerStates` maps. Alternatively,
move session storage to the database for persistence across restarts and
bounded storage.

---

### SEC-003: No CSRF protection on state-changing endpoints

**Severity:** Medium
**Location:** `internal/server/api.go:47-61`, `internal/auth/auth.go:76-79`

The `POST /api/tokens`, `DELETE /api/tokens/{id}`, and `POST /auth/logout`
endpoints rely on cookie-based authentication from the web UI but do not verify
a CSRF token. The `SameSite: Lax` attribute on the cookie provides some
protection (it blocks cross-site POST requests from forms in modern browsers),
but this is not a complete defence:

- `SameSite: Lax` does not protect against same-site attacks (e.g., if any
  subdomain of the management host is compromised).
- Older browsers may not enforce `SameSite` correctly.

**Recommendation:** Add a synchronizer token pattern (CSRF token) or require a
custom request header (e.g., `X-GHP-Token`) for all state-changing requests
from the web UI. API requests using `Authorization: Bearer` headers are already
immune to CSRF.

---

### SEC-004: No rate limiting on authentication endpoints

**Severity:** Medium
**Location:** `internal/auth/auth.go:192-208`, `internal/auth/auth.go:380-455`

There is no rate limiting on any endpoint, most critically:

- `POST /auth/test-login` (dev mode) — no limit on login attempts.
- `GET /auth/github` — each request generates a state token stored in memory
  (see SEC-002).
- `GET /auth/authorize` (broker) — each request generates a broker state entry.
- `POST /api/tokens` — no limit on token creation rate.

**Recommendation:** Implement rate limiting middleware, at minimum on
authentication endpoints. Consider using a token-bucket or sliding-window
approach, keyed by IP address. The `/auth/test-login` endpoint is especially
critical since it creates sessions without any external validation.

---

### SEC-005: TLS `MinVersion` not explicitly set

**Severity:** Low
**Location:** `internal/server/tls.go:13-39`

The TLS configuration does not set `MinVersion`, which means Go's default is
used (TLS 1.2 as of Go 1.18+). While this is currently acceptable, explicitly
setting `MinVersion: tls.VersionTLS12` (or `tls.VersionTLS13`) documents the
intent and protects against future Go changes or misconfigurations.

Additionally, no `CipherSuites` are specified. While Go's defaults are
reasonable, production deployments may want to restrict to a known-good set.

**Recommendation:** Explicitly set `MinVersion: tls.VersionTLS12` and consider
configuring an explicit cipher suite list for compliance environments.

---

### SEC-006: GraphQL endpoint bypasses scope enforcement

**Severity:** Medium
**Location:** `internal/proxy/proxy.go:100-103`, `internal/proxy/proxy.go:155-173`

The comment at `proxy.go:156-157` states: "For GraphQL, we forward the request
and check the token's scopes in a simplified manner. Full GraphQL query parsing
is complex; for now, we require that the token has at least one scope."

In practice, the `handleGraphQL` method does not actually check any scopes at
all — it only requires a valid token. This means a token scoped to
`issues:read` on repo A could potentially be used to execute any GraphQL
mutation on any repository the underlying GitHub credential has access to.

**Recommendation:** At minimum, enforce repository scoping for GraphQL requests
by parsing the `repository` or `owner`/`name` variables from the GraphQL query
body. Consider restricting GraphQL access to tokens with specific scope grants.
Document the current limitation clearly until full enforcement is implemented.

---

### SEC-007: Unrecognized REST API endpoints are forwarded without scope checks

**Severity:** Low
**Location:** `internal/proxy/proxy.go:116-133`

The comment at `proxy.go:117` states: "Unrecognized endpoints are forwarded —
GitHub's token handles access." When `EndpointScope()` returns empty strings
(the endpoint is not in the rules table), the request is forwarded to GitHub
with the real token, bypassing scope enforcement entirely.

This is a fail-open design. Any new GitHub API endpoint or any endpoint not
yet mapped in `scope.go` will be accessible to all valid tokens regardless of
their configured scopes.

**Recommendation:** Consider switching to a fail-closed model where
unrecognized endpoints are blocked by default, with an explicit allowlist for
"metadata"-level endpoints. Alternatively, add a configuration option to choose
between fail-open (current) and fail-closed behaviour. At minimum, log these
unrecognized-endpoint forwards at a higher level for visibility.

---

### SEC-008: Installation token cache is keyed only by installation ID

**Severity:** Medium
**Location:** `internal/github/app.go:136-138`

The installation token cache in `AppTokenProvider.GetInstallationToken` is keyed
by `installationID` alone. If a first request creates a token scoped to repo A
with `contents:read`, and a second request asks for the same installation but
repo B with `contents:write`, the cached token from the first request is
returned.

This cached token may not have the permissions or repository access that the
second request requires, or it may have broader access than intended.

**Recommendation:** Include the repository list and permissions in the cache key
(e.g., hash the sorted repos + permissions alongside the installation ID). This
ensures each unique scope combination gets its own installation token.

---

### SEC-009: `http.DefaultClient` used for OAuth code exchange

**Severity:** Low
**Location:** `internal/auth/auth.go:479`, `internal/auth/auth.go:513`

The OAuth code exchange and GitHub user info requests use
`http.DefaultClient`, which has no timeout set. A slow or unresponsive GitHub
API could cause goroutine and connection leaks. The proxy handler correctly uses
a client with a 30-second timeout (`internal/proxy/proxy.go:52-54`), but the
auth handler does not.

**Recommendation:** Create a dedicated `http.Client` with a reasonable timeout
(e.g., 30 seconds) for all outbound HTTP requests in the auth handler.

---

### SEC-010: Sensitive values in CLI config file lack restrictive permissions check

**Severity:** Low
**Location:** `cmd/ghp/auth.go:54-68`

The CLI config file at `~/.config/ghp/config.yaml` stores the `user_token`
(session token) in plaintext. While the file is created with `0600` permissions
(line 67), the code does not check the file's permissions before reading it. If
a user or another process has changed the permissions to be world-readable, the
session token is exposed without warning.

**Recommendation:** When reading the config file, check that its permissions
are no more permissive than `0600` and warn the user if they are.

---

### SEC-011: No `Content-Security-Policy` or other security headers on web UI responses

**Severity:** Medium
**Location:** `internal/web/handler.go`, `internal/web/templates/*.html`

The web UI templates do not set any security response headers:

- No `Content-Security-Policy` header (allows inline scripts, which are used
  extensively in the templates).
- No `X-Content-Type-Options: nosniff` header.
- No `X-Frame-Options` header (the management UI could be framed by a
  malicious page for clickjacking).
- No `Referrer-Policy` header.

**Recommendation:** Add a middleware that sets standard security headers on all
management UI responses:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
```

As a follow-up, migrate inline `<script>` blocks to external JS files with
nonce-based CSP to eliminate `'unsafe-inline'`.

---

### SEC-012: DevMode has no runtime safeguard beyond a config flag

**Severity:** Medium
**Location:** `internal/auth/auth.go:98-102`, `internal/config/config.go:32`

When `dev_mode: true` is set, the `/auth/test-login` endpoint is enabled, which
allows creating sessions for any username with any role (including `admin`)
without any authentication. There is no safeguard to prevent this from being
accidentally enabled in a deployment:

- No warning is emitted at startup beyond a `slog.Warn` (which may be missed
  in production log noise).
- The config can be set via the `GHP_DEV_MODE` environment variable.
- There is no check that the server is listening only on localhost when dev
  mode is enabled.

**Recommendation:** Add multiple layers of protection:

1. Refuse to start in dev mode if the listen address is not localhost
   (or require an additional `--i-know-what-i-am-doing` flag).
2. Add a prominent banner to web UI pages when dev mode is active.
3. Consider restricting the test-login endpoint to requests from localhost only.

---

### SEC-013: OAuth `code` parameter is not URL-encoded in exchange request body

**Severity:** Low
**Location:** `internal/auth/auth.go:465-466`

The OAuth code exchange constructs the request body using `fmt.Sprintf` with
string interpolation rather than `url.Values`. While the `code` parameter from
GitHub is expected to be safe, the `client_id` and `client_secret` values are
also interpolated directly. If any of these values contain characters special
to `application/x-www-form-urlencoded` encoding (e.g., `&`, `=`, `+`), the
request body would be malformed.

**Recommendation:** Use `url.Values` to construct the form body (as is
correctly done in `proxy.go:255-260` for the refresh flow), ensuring proper
URL encoding of all parameters.

---

### SEC-014: Audit log has no retention policy or size limit

**Severity:** Low
**Location:** `internal/database/migrations/sqlite/001_initial.up.sql:44-58`

The `audit_log` table grows unboundedly. For a proxy that handles many
requests, this table will grow large over time, potentially impacting query
performance and disk usage. There is no mechanism to prune old entries.

**Recommendation:** Implement an audit log retention policy, either:

- A periodic cleanup job that deletes entries older than a configurable
  threshold (e.g., 90 days).
- Database-level partitioning (PostgreSQL) by month with automatic partition
  drops.
- A configurable `max_audit_entries` setting.

---

### SEC-015: Expired/revoked proxy tokens remain in database indefinitely

**Severity:** Low
**Location:** `internal/database/models.go:34-51`

Proxy tokens are soft-deleted (revoked via `revoked_at` timestamp) and expired
tokens remain in the database. While they are correctly rejected during
resolution, the `token_hash` column remains populated, meaning the cryptographic
hash of every token ever issued is retained permanently.

**Recommendation:** Implement a periodic cleanup that hard-deletes proxy tokens
that have been expired for longer than a configurable grace period (e.g., 30
days after expiry or revocation). This reduces the attack surface for offline
hash-based attacks and keeps the database size manageable.

---

### SEC-016: `ListAllProxyTokens` has no pagination

**Severity:** Low
**Location:** `internal/database/sqlite.go:359-368`, `internal/database/postgres.go:299-307`

The `ListAllProxyTokens` query fetches all tokens without any `LIMIT` clause.
In a deployment with many tokens, this could cause high memory usage and slow
responses. The admin UI calls this endpoint on page load.

**Recommendation:** Add pagination support (limit/offset) to
`ListAllProxyTokens` and the corresponding API endpoint.

---

### SEC-017: Copilot passthrough proxy performs no token interception

**Severity:** Low (informational)
**Location:** `internal/proxy/passthrough.go:196-217`

The Copilot passthrough handler (`NewCopilotPassthroughHandler`) forwards all
traffic to `copilot-proxy.githubusercontent.com` without any token
interception, scope checking, or audit logging. Any credential in the
`Authorization` header is forwarded verbatim.

This is by design (the handler is documented as transparent), but it means
Copilot traffic bypasses all ghp access controls.

**Recommendation:** Document this behaviour clearly in the deployment guide.
Consider whether Copilot traffic should be subject to audit logging even if
scope enforcement is not applied.

---

### SEC-018: `User.Role` can be set via `UpsertUser` without re-evaluation

**Severity:** Low
**Location:** `internal/auth/auth.go:283-286`, `internal/database/sqlite.go:116-123`

When a user logs in, their role is determined by checking `cfg.IsAdmin(username)`.
However, the `UpsertUser` call uses `ON CONFLICT ... DO UPDATE SET` which does
**not** update the `role` field — it only updates `github_username` and
`github_email`. This means:

- If a user is added to the `admins` config list, they will not become admin
  until their user record is manually updated or recreated.
- If a user is removed from the `admins` list, they retain their admin role
  indefinitely.

**Recommendation:** Include `role` in the `ON CONFLICT DO UPDATE SET` clause so
that the configured admin list is the source of truth on every login. Add a
note in the configuration documentation about this behaviour.

---

### SEC-019: Broker JWT uses HMAC-SHA256 (symmetric) rather than asymmetric signing

**Severity:** Low (informational)
**Location:** `internal/auth/broker.go:128`

The OAuth broker mints JWTs signed with HMAC-SHA256 (`jwt.SigningMethodHS256`)
using a shared secret. This means any downstream service that needs to verify
the JWT must also possess the signing secret, which means it can also forge
JWTs.

This is acceptable for a single-operator deployment where the same entity
controls both ghp and the downstream services. However, for multi-tenant or
third-party integrations, asymmetric signing (RS256/ES256) would be more
appropriate.

**Recommendation:** Consider supporting asymmetric JWT signing (e.g., RS256)
as an option for the broker, allowing downstream services to verify tokens
using a public key without being able to forge them. Document the current
symmetric trust model in the OAuth broker documentation.

---

### SEC-020: No request body size limits

**Severity:** Low
**Location:** `internal/auth/auth.go:385`, `internal/server/api.go:77`, `internal/proxy/proxy.go:392`

None of the JSON request decoders (`json.NewDecoder(r.Body).Decode(...)`) are
preceded by an `http.MaxBytesReader` call. An attacker could send an arbitrarily
large request body to cause memory exhaustion.

The proxy handler also copies the entire upstream request body
(`io.Copy(w, resp.Body)` at `proxy.go:383`, `proxy.go:447`), but this is
streaming and bounded by the HTTP client timeout.

**Recommendation:** Wrap `r.Body` with `http.MaxBytesReader` on all API
endpoints that parse JSON request bodies. A limit of 1 MB should be more than
sufficient for all current API payloads.

---

### SEC-021: Docker image runs as root inside distroless container

**Severity:** Low
**Location:** `Dockerfile:15-19`

The multi-stage Dockerfile copies the binary into
`gcr.io/distroless/static-debian12` without specifying a `USER` directive. The
process runs as root (UID 0) inside the container. While distroless images have
minimal attack surface, running as a non-root user is a defence-in-depth best
practice.

The systemd service file correctly uses `DynamicUser=yes` for non-Docker
deployments.

**Recommendation:** Add a non-root user to the Dockerfile:

```dockerfile
FROM gcr.io/distroless/static-debian12
COPY --from=build /ghp /ghp
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/ghp"]
```

(The `nonroot` user is built into distroless images.)

---

### SEC-022: Wildcard redirect URI matching in broker could be overly permissive

**Severity:** Medium
**Location:** `internal/auth/broker.go:177-190`

The redirect URI validation supports wildcard patterns like `*.example.com`.
The matching logic checks `strings.HasSuffix(host, suffix) && len(host) > len(suffix)`,
which correctly prevents matching the bare domain, but:

- A pattern of `*.example.com` will match `evil.example.com` — this is
  expected and correct.
- However, it will also match `evil.notexample.com` if a pattern like
  `*.notexample.com` is configured — wait, that's fine too.

The actual concern is that wildcard patterns delegate trust to all subdomains.
If an attacker can create a subdomain under the allowed domain (e.g., via a
subdomain takeover or a shared hosting platform), they can intercept broker
tokens.

**Recommendation:** Document the security implications of wildcard redirect
patterns in the configuration guide. Consider supporting more specific patterns
(e.g., path-level matching) or recommending exact URL matches for production
deployments.

---

### SEC-023: `exchangeCode` does not validate that the OAuth `redirect_uri` matches

**Severity:** Low
**Location:** `internal/auth/auth.go:253`, `internal/auth/auth.go:464-469`

The main OAuth callback (`handleGitHubCallback`) calls `exchangeCode(code, "")`
with an empty `redirect_uri`. GitHub's OAuth spec requires that if a
`redirect_uri` was provided in the authorization request, the same URI must be
included in the token exchange. Currently, the authorization request at line
198 does not include a `redirect_uri`, so omitting it from the exchange is
technically correct.

However, this means GitHub will redirect to any URL registered as a callback
URL in the OAuth App settings, which may be overly broad if multiple callback
URLs are configured.

**Recommendation:** Explicitly set and validate the `redirect_uri` in both the
authorization and token exchange requests to ensure they match and prevent
authorization code injection attacks.

---

## Summary of Findings

| ID | Severity | Title |
|----|----------|-------|
| SEC-001 | High | Session cookie missing `Secure` flag |
| SEC-002 | Medium | In-memory sessions are not bounded or pruned |
| SEC-003 | Medium | No CSRF protection on state-changing endpoints |
| SEC-004 | Medium | No rate limiting on authentication endpoints |
| SEC-005 | Low | TLS `MinVersion` not explicitly set |
| SEC-006 | Medium | GraphQL endpoint bypasses scope enforcement |
| SEC-007 | Low | Unrecognized REST API endpoints forwarded without scope checks |
| SEC-008 | Medium | Installation token cache keyed only by installation ID |
| SEC-009 | Low | `http.DefaultClient` used for OAuth code exchange (no timeout) |
| SEC-010 | Low | CLI config file permissions not validated on read |
| SEC-011 | Medium | No `Content-Security-Policy` or security headers on web UI |
| SEC-012 | Medium | DevMode has no runtime safeguard beyond a config flag |
| SEC-013 | Low | OAuth `code` parameter not URL-encoded in exchange body |
| SEC-014 | Low | Audit log has no retention policy or size limit |
| SEC-015 | Low | Expired/revoked proxy tokens retained indefinitely |
| SEC-016 | Low | `ListAllProxyTokens` has no pagination |
| SEC-017 | Low | Copilot passthrough bypasses all access controls (by design) |
| SEC-018 | Low | Admin role not re-evaluated on login |
| SEC-019 | Low | Broker JWT uses symmetric signing (HMAC-SHA256) |
| SEC-020 | Low | No request body size limits on API endpoints |
| SEC-021 | Low | Docker image runs as root |
| SEC-022 | Medium | Wildcard redirect URI patterns trust all subdomains |
| SEC-023 | Low | OAuth `redirect_uri` not explicitly set in auth flow |

## Positive Observations

The following security practices are already well-implemented:

- **AES-256-GCM encryption at rest** for GitHub tokens with proper nonce
  generation (`internal/crypto/crypto.go`).
- **Token hashing with SHA-256** — plaintext tokens are never stored; only
  hashes are persisted (`internal/token/token.go`).
- **Strong token entropy** — 32 bytes of `crypto/rand` for session tokens,
  OAuth state, and proxy tokens.
- **JWT secret minimum length enforcement** — broker endpoints are disabled if
  `jwt_secret` is shorter than 32 bytes (`internal/auth/auth.go:84-86`).
- **Systemd security hardening** — the service unit uses `ProtectSystem=strict`,
  `NoNewPrivileges`, `MemoryDenyWriteExecute`, and other sandboxing directives.
- **Parameterised SQL queries** throughout — no string interpolation in SQL
  queries, preventing SQL injection.
- **XSS prevention** — the web UI uses a JavaScript `esc()` helper function
  that creates a text node to sanitise all dynamic content before inserting
  into the DOM. Go templates use `html/template` which auto-escapes.
- **Access log redaction** — sensitive headers (`Authorization`, `Cookie`,
  `X-API-Key`, etc.) are redacted in access logs
  (`internal/server/accesslog.go:122-130`).
- **Redirect URI validation** — the broker validates redirect URIs against an
  allowlist and requires HTTPS (except localhost in dev mode).
- **Distroless Docker base image** — minimal attack surface with no shell or
  package manager.
- **CGO_ENABLED=0** — statically linked binary with no C library dependencies.
- **Shadow DOM in web components** — the custom elements use shadow DOM
  isolation, reducing the risk of style/script injection.

---

## Recommended Issue Priority

**Immediate (next sprint):**

1. SEC-001 — Secure flag on cookies
2. SEC-006 — GraphQL scope enforcement
3. SEC-011 — Security response headers
4. SEC-012 — DevMode safeguards

**Short-term (next 2-3 sprints):**

5. SEC-002 — Session memory pruning
6. SEC-003 — CSRF protection
7. SEC-004 — Rate limiting
8. SEC-008 — Installation token cache key
9. SEC-018 — Admin role re-evaluation on login
10. SEC-020 — Request body size limits
11. SEC-022 — Wildcard redirect documentation

**Longer-term / Housekeeping:**

12. SEC-005 — Explicit TLS MinVersion
13. SEC-007 — Fail-closed scope enforcement option
14. SEC-009 — HTTP client timeout in auth handler
15. SEC-013 — URL-encode OAuth exchange body
16. SEC-014 — Audit log retention
17. SEC-015 — Expired token cleanup
18. SEC-016 — Token list pagination
19. SEC-017 — Copilot passthrough documentation
20. SEC-019 — Asymmetric JWT option for broker
21. SEC-021 — Docker non-root user
22. SEC-023 — Explicit redirect_uri in OAuth flow
23. SEC-010 — CLI config permission check
