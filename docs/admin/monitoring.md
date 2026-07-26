# Monitoring

ghp exposes Prometheus metrics and structured access logs for observability.

## Prometheus Metrics

When metrics are enabled (the default), ghp runs a dedicated metrics server
on a separate port. This keeps metrics traffic isolated from the main proxy.

```yaml
metrics:
  enabled: true
  listen: ":9136"
```

Scrape the metrics endpoint at `http(s)://<ghp-server>:9136/metrics` (HTTPS when ghp runs with TLS enabled, HTTP otherwise).

### Available Metrics

#### HTTP Request Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_http_request_duration_seconds` | Histogram | Duration of all HTTP requests (labels: `backend`, `method`, `status`) |
| `ghp_http_request_total` | Counter | Total HTTP requests (labels: `backend`, `method`, `status`) |

The `backend` label distinguishes traffic by virtualhost: `api.github.com`,
`github.com`, `codeload.github.com`, `raw.githubusercontent.com`, `copilot`,
or `management`.

#### Proxy Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_proxy_request_duration_seconds` | Histogram | Duration of authenticated requests processed by the proxy (API and git smart-HTTP) (labels: `backend`, `method`, `status`, `token_type`, `type`, `user`, `app`) |
| `ghp_proxy_request_total` | Counter | Total authenticated requests processed by the proxy (API and git smart-HTTP) (labels: `backend`, `method`, `status`, `token_type`, `type`, `user`, `app`) |
| `ghp_proxy_decision_duration_seconds` | Histogram | Time spent in each stage of the proxy decision pipeline (labels: `stage`, `token_type`) |

The `type` label distinguishes API traffic from git smart-HTTP traffic (e.g.
`type="git"` for git operations proxied via the `github.com` backend). The
decision pipeline metric breaks down the overhead ghp adds to each request
into individually timed stages so you can identify where latency originates.
The stages are:

| Stage | What it measures |
|-------|------------------|
| `total` | Full pre-forward overhead: arrival to GitHub forward |
| `token_extraction` | Unpacking the Authorization header, identifying token prefix |
| `border_policy_check` | Evaluating the token type border policy |
| `token_resolution` | SHA-256 hash, database lookup, expiry & revocation check |
| `username_resolution` | Resolving GitHub username from internal user ID |
| `scope_parsing` | JSON unmarshalling of repository & permission scopes |
| `scope_enforcement` | Repository allowlist + permission level checks |
| `github_token_resolution` | Loading, decrypting (or refreshing) the real GitHub credential |
| `upstream_roundtrip` | Proxying the request to GitHub and streaming the response |
| `redirect_head_check` | HEAD request to the release redirect target to verify asset availability (releases handler only) |
| `cache_lookup` | Checking whether a request targets a cache-enabled repository |

#### Git Cache Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ghp_cache_fetch_total` | Counter | `result` | Git fetch requests to cached repos |
| `ghp_cache_lsrefs_total` | Counter | — | ls-refs commands forwarded upstream for cached repos |
| `ghp_cache_warm_total` | Counter | `result` | Async cache warming operations |
| `ghp_cache_repos_active` | Gauge | — | Number of repositories with caching enabled |
| `ghp_cache_request_total` | Counter | `owner`, `repo`, `result` | Per-repository git smart HTTP requests with cache outcome |

**`ghp_cache_fetch_total` result values:**

| Value | Meaning |
|-------|---------|
| `hit` | Served from local cache |
| `miss` | Cache miss — fetched from upstream, then served from cache |
| `rejected` | Access denied by upstream (401/403/404) |
| `error` | Cache or upstream failure |

**`ghp_cache_request_total` result values:**

| Value | Meaning |
|-------|---------|
| `hit` | Served from local cache |
| `miss` | Cache miss — fetched from upstream, then served from cache |
| `nocache` | Repository not configured for caching |
| `bypass` | Repository configured but caching is disabled |
| `rejected` | Access denied by upstream |
| `error` | Cache or upstream failure |
| `passthrough` | Delegated to upstream proxy (e.g., cache miss with no token) |

##### Identifying cache candidates

The `ghp_cache_request_total` metric includes `owner` and `repo` labels,
enabling per-repository analysis. Use it to identify repositories that would
benefit from caching:

```promql
# Top 10 uncached repos by request volume — candidates for adding to cache
topk(10, sum by (owner, repo) (ghp_cache_request_total{result="nocache"}))

# Repos configured but disabled — consider re-enabling
sum by (owner, repo) (ghp_cache_request_total{result="bypass"})

# Cache hit rate per repo — verify caching is effective
sum by (owner, repo) (ghp_cache_request_total{result="hit"})
/ sum by (owner, repo) (ghp_cache_request_total)

# Repos with high miss rates — may need cache warming or service token
sum by (owner, repo) (ghp_cache_request_total{result="miss"})
/ sum by (owner, repo) (ghp_cache_request_total{result=~"hit|miss"})
```

!!! note "Label cardinality"
    The `owner` and `repo` labels on `ghp_cache_request_total` are bounded by
    the number of distinct repositories accessed through the proxy. For typical
    deployments (hundreds of repos), this is well within Prometheus limits.

See [Git Cache](../features/git-cache.md) for configuration details.

#### Token Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_token_active` | Gauge | Number of active (non-expired, non-revoked) tokens per user (label: `user`) |
| `ghp_token_created_total` | Counter | Total tokens created per user (label: `user`) |
| `ghp_token_revoked_total` | Counter | Total tokens revoked per user (label: `user`) |

#### GitHub Rate Limit Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_github_ratelimit_remaining` | Gauge | Remaining GitHub API rate limit, per user |
| `ghp_github_ratelimit_limit` | Gauge | GitHub API rate limit ceiling, per user |
| `ghp_github_token_refresh_total` | Counter | OAuth token refresh attempts per user (labels: `user`, `status`; `status` is `success` or `failure`) |

#### Security Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_auth_rate_limit_total` | Counter | Rate limiter rejections on auth endpoints (label: `endpoint`) |
| `ghp_block_anonymous_git_total` | Counter | Anonymous git requests blocked |
| `ghp_block_anonymous_git_enabled` | Gauge | Whether anonymous git blocking is active (1 or 0) |
| `ghp_cli_auth_device_started_total` | Counter | CLI device-authorization requests initiated (one per `ghp auth login` invocation) |
| `ghp_cli_auth_device_completed_total` | Counter | CLI device-authorization requests that reached a terminal state (label: `result` — `approved`, `denied`, or `expired`) |

#### Release Controls Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_releases_redirect_head_check_total` | Counter | Outcomes of HEAD requests to the release redirect target (label: `result`) |

The `result` label on the HEAD check counter has three values:

| Value | Meaning |
|-------|---------|
| `found` | Mirror returned a non-404 response; redirect proceeds normally |
| `not_found` | Mirror returned 404; ghp served a friendly error page instead of redirecting |
| `error` | HEAD request failed (network error, timeout); redirect proceeds normally |

When `redirect_head_check` is enabled, each HEAD request is also timed in the
decision pipeline histogram (`ghp_proxy_decision_duration_seconds`) under the
`redirect_head_check` stage. This lets you monitor how much latency the
availability probe adds to redirected release downloads.

See [Release Download Controls](../features/release-controls.md) for
configuration details.

#### Codeload Redirect Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_codeload_redirect_total` | Counter | codeload.github.com archive requests handled by the codeload handler (labels: `owner`, `repo`, `archive`, `result`) |

The `archive` label is one of `tar.gz`, `zip`, `legacy.tar.gz`, or
`legacy.zip`. The `result` label is `redirect` (302 to the configured
caching mirror) or `passthrough` (forwarded to upstream codeload because the
org/repo is in the allow list or no `redirect_to` is configured). The full
ref (SHA, branch, or tag) is intentionally omitted from labels to keep
cardinality bounded; query the access log for per-ref breakdowns.

See [Codeload Redirect](../features/codeload.md) for configuration details.

#### Raw Content Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_raw_request_total` | Counter | raw.githubusercontent.com requests handled by the raw handler (labels: `owner`, `repo`, `result`) |

The `result` label records how the request was classified:

| `result` | Meaning |
|---|---|
| `authenticated` | ghp-issued token present; scope enforced; forwarded with the resolved GitHub credential |
| `query_token` | GitHub-issued `?token=` present, no ghp token; forwarded unmodified and unattributed |
| `foreign_credential` | An `Authorization` credential ghp did not issue (e.g. `ghp_`, `ghs_`) that the border policy permits; forwarded intact and unattributed |
| `anonymous` | No credential at all; forwarded unmodified |
| `denied_scope` | ghp token not scoped to the requested repository, or lacking `contents:read` |
| `denied_token` | ghp token could not be resolved (revoked, expired, unknown), or its GitHub credential could not be resolved |
| `denied_policy` | Query token rejected because `raw.allow_query_token` is `false` |
| `denied_border` | Credential rejected by the [token type border policy](../features/border-policy.md) |
| `denied_method` | Method other than GET or HEAD |
| `error` | ghp-side fault (corrupt token scope JSON) |

Requests whose path has fewer than three segments are forwarded without being
counted — they are not repository content paths, so there is no meaningful
`owner`/`repo` to label them with.

!!! warning "Cardinality is client-controlled"
    `owner` and `repo` are taken from the request path, and the `anonymous`,
    `foreign_credential`, and `query_token` classifications require no
    ghp-issued credential. Any client that can reach the raw virtualhost can
    therefore create a new time series per invented `/owner/repo`. Budget
    metric storage accordingly, or restrict network access to the raw
    virtualhost.

See [How It Works — raw.githubusercontent.com](../how-it-works.md#rawgithubusercontentcom)
for the classification rules.

## Logging

ghp treats **OpenTelemetry log records** as its first-class logging primitive.
Every log — operational messages, the HTTP access log, and the audit log — is
emitted as an OTel log record described using OpenTelemetry
[semantic conventions](https://opentelemetry.io/docs/specs/semconv/) rather than
the legacy Caddy-style JSON field names. Records are always written to the
console (stdout or a file) using the OTel stdout exporter, and can additionally
be shipped to an OTLP collector (see [OpenTelemetry](#opentelemetry) below).

Each emitted record carries a `service.name=ghp` resource attribute and an
**instrumentation scope** that identifies the stream. Aggregators can route on
the scope name the same way they previously keyed on the Caddy `logger` field:

| Scope name | Stream |
|---|---|
| `github.com/goodtune/ghp` | Operational logs (emitted via `log/slog`) |
| `github.com/goodtune/ghp/access` | HTTP access log |
| `github.com/goodtune/ghp/audit` | Audit log |

### Access Logs

An access log record is emitted for every request across all virtualhosts, with
body `handled request`. Attributes use HTTP semantic conventions:

| Attribute | Meaning |
|---|---|
| `http.request.method` | HTTP method |
| `url.path`, `url.query`, `url.scheme` | Request target |
| `http.response.status_code` | Response status |
| `http.response.body.size` | Response body bytes |
| `http.server.request.duration` | Request duration (seconds) |
| `network.protocol.name` / `network.protocol.version` | e.g. `http` / `1.1` |
| `client.address` / `client.port` | Remote peer |
| `server.address` / `server.port` | Host the request targeted |
| `user_agent.original` | User-Agent header |
| `enduser.id` | GitHub username when available, otherwise the internal user ID |
| `http.request.header.<name>` / `http.response.header.<name>` | Selected headers (sensitive values such as `authorization` and `set-cookie` are `REDACTED`) |
| `ghp.backend` | Backend identifier (same values as the `backend` metric label) |
| `ghp.cache.state` / `ghp.cache.repo` | Git cache outcome, when applicable |
| `ghp.raw.auth` | How a raw.githubusercontent.com request authenticated, when applicable |

`ghp.raw.auth` takes one of `proxy_token`, `query_token`, `foreign_credential`,
`anonymous`, or a denial reason (`denied_method`, `denied_border`,
`denied_policy`, `denied_scope`, `denied_token`, `error`). These match the
`ghp_raw_request_total` `result` values with one exception: a request
authenticated with a ghp-issued token logs `ghp.raw.auth=proxy_token` but is
counted as `result="authenticated"` — the log records the kind of credential
presented, the metric the outcome of the decision.

Records for responses with a 5xx status are emitted at `Error` severity; all
others at `Info`.

Configure logging output and level:

```yaml
logging:
  output: "stdout"         # "stdout" or "file"
  level: "info"            # "debug", "info", "warn", "error" (operational logs)
  file:
    path: "/var/log/ghp/ghp.log"
```

The `level` setting filters operational (`slog`) records; access and audit
records are always emitted.

### Audit Logs

API proxy requests and token lifecycle events (creation, revocation, scope
updates) emit audit records under the `github.com/goodtune/ghp/audit` scope with
body `audit event`. Attributes:

| Attribute | Meaning |
|---|---|
| `ghp.audit.action` | Event type (e.g. `proxy_request`, `token_created`, `token_revoked`, `token_scopes_updated`) |
| `enduser.id` | Internal user ID |
| `ghp.user.name` | GitHub username |
| `ghp.token.id` / `ghp.token.type` | Token involved |
| `ghp.session.id` | Session that created or used the token |
| `http.request.method` / `url.path` | Request context (proxy requests) |
| `ghp.repository` | Target repository, when applicable |
| `http.response.status_code` | Upstream status (proxy requests) |
| `http.server.request.duration` | Request duration in seconds (proxy requests) |

Token lifecycle events omit the request- and repository-related attributes.

### OpenTelemetry export

In addition to the console exporter, ghp can ship every log record to an OTLP
collector. Enable it under `otel` (see
[Configuration → OpenTelemetry](configuration.md#opentelemetry)):

```yaml
otel:
  enabled: true
  endpoint: "http://localhost:4318"   # http:// → TLS disabled (insecure)
  protocol: "http"                     # "grpc" (default) or "http"
```

When enabled, records are batched and exported to the collector while still
being written to the console. Capturing and indexing logs that are only written
to the console is the responsibility of the deployment environment (e.g. Splunk,
Elastic, Datadog).

## Server Response Headers

Every response from ghp includes two identifying headers, set by a
server-wide middleware regardless of which backend served the request:

- `Server: GitHub Proxy` — a fixed value that overrides any upstream
  `Server` header (e.g. GitHub's own `server: github.com`), making it easy to
  verify that traffic is flowing through ghp rather than directly to GitHub.
- `X-GitHub-Proxy-Version: <version>` — the build version of the running ghp
  binary, so operators can identify exactly which image a deployment is
  serving. The header is omitted when no version was compiled in.

You can confirm the deployed version from the command line:

    curl -sI https://ghp.example.com/docs/ | grep -i x-github-proxy-version

The same version string is also displayed beneath the login form in the web
UI, so managers rolling out a new image can identify the running version at a
glance without inspecting headers.

## Health Check

The `/auth/status` endpoint on the management host returns the current
authentication status. It requires authentication and returns HTTP 401
when no valid session cookie is present, and HTTP 200 only when the user
is authenticated. This makes it unsuitable for unauthenticated liveness
checks that expect a 2xx response.

For basic unauthenticated liveness checks, use the documentation endpoint
which is always accessible without authentication:

    curl -s https://ghp.example.com/docs/

To verify both service health and authentication, use `/auth/status` with
an authenticated session and expect HTTP 200 on success:

    curl -s https://ghp.example.com/auth/status
