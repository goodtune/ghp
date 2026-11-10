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
| `ghp_client_request_total` | Counter | Requests by originating client (labels: `client`, `backend`, `token_type`, `status`) |

The `backend` label distinguishes traffic by virtualhost: `api.github.com`,
`github.com`, `codeload.github.com`, `copilot`, or `management`.

The `client` label on `ghp_client_request_total` is the source IP of the
request, so operators can spot a host generating disproportionate traffic.
By default it is the direct peer address. Behind a reverse proxy, set
`server.client_ip_header` to the *one* forwarded header your proxy is
documented to set — `forwarded` (RFC 7239 `for=`), `x-real-ip`, or
`x-forwarded-for` — and only that header is consulted. All other forwarded
headers are ignored: most proxies set exactly one family and pass the
others through untouched, so trusting more than the configured header
would let clients spoof attribution (and rotate per-IP rate-limit buckets)
via a header the proxy never rewrites. The setting assumes exactly one
trusted reverse proxy, so for the chain-style headers (`Forwarded`,
`X-Forwarded-For`) the *rightmost* entry is used — that is the one
appended by the trusted proxy; entries to its left arrived inside the
client's own request and are spoofable. Header values must parse as an IP
address (an optional port is tolerated); anything else — including RFC
7239 `unknown` and obfuscated identifiers — falls back to the peer
address, so clients cannot inject arbitrary strings into label values.
The same attribution is used for the per-IP authentication rate limiter,
so behind a reverse proxy `client_ip_header` must be set for rate limits
to apply per client rather than per proxy. The `token_type` label is
`proxy` (ghx_), `agent` (gha_), a native GitHub prefix (`gho`, `ghp`,
`ghs`, ...), or `unknown` for unauthenticated traffic. Cardinality is
bounded by the number of distinct client hosts; map IPs to hostnames in
Grafana or with recording rules if needed.

#### Proxy Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_proxy_request_duration_seconds` | Histogram | Duration of authenticated requests processed by the proxy (API and git smart-HTTP) (labels: `backend`, `method`, `status`, `token_type`, `type`, `user`, `app`) |
| `ghp_proxy_request_total` | Counter | Total authenticated requests processed by the proxy (API and git smart-HTTP) (labels: `backend`, `method`, `status`, `token_type`, `type`, `user`, `app`) |
| `ghp_proxy_decision_duration_seconds` | Histogram | Time spent in each stage of the proxy decision pipeline (labels: `stage`, `token_type`, `vhost`) |

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
| `graphql_analysis` | Parsing a `/graphql` request body and computing its scope and repository requirements (scoped tokens only; open-scoped tokens record no sample) |
| `cache_lookup` | Checking whether a git request targets a cache-enabled repository (always `token_type="unknown"`) |
| `forward_proxy_selection` | Selecting the upstream forward proxy for the outbound request |
| `enterprise_exception` | Evaluating enterprise access restriction exceptions |
| `request_body_read` | Reading the client's `/graphql` request body before analysis (scoped tokens only). This includes the time the client takes to upload the body |
| `request_build` | Building the outbound request: URL, request copy and header copy |
| `pipeline_other` | Not timed directly: `total` minus the sum of the other stages for the same request. Recorded for `ghx_`/`gha_` and passthrough requests on the API handler |

`pipeline_other` shows time that no stage covers. It should stay near zero.
If its p99 follows the `total` p99, the time is spent outside any stage, for
example in a garbage collection pause or while the goroutine waits for a CPU.
Compare it with `go_gc_duration_seconds` for the same window.

### Slow decision log

When the `total` of one request reaches `metrics.slow_decision_threshold`
(default `10ms`), ghp writes one `slow_decision` line at warn level. Use it to
explain a single slow sample. The line has these fields:

| Field | Value |
|-------|-------|
| `total_ms` | The `total` sample, in milliseconds |
| `pipeline_other_ms` | The part of `total` that no stage covers |
| `<stage>_ms` | One field for each stage that ran before the forward, for example `token_resolution_ms` |
| `token_type` | `proxy`, `agent` or `unknown` |
| `vhost` | The `vhost` label value |
| `method`, `path` | The request method and URL path (no query string) |

The line never contains the token. Set the threshold to `0` to disable the
log.

Lines from paths outside the proxy API handler (for example `github.com`
passthrough and management-host rejections) have no stage trace. They carry
only `total_ms`, `token_type` and `vhost`.

`request_body_read` is client upload time. A slow client can make `total`
reach the threshold, so the 10ms default can write many lines on a busy
deployment. Increase the threshold if this occurs.

Likely cause of slow samples (#355): before `request_body_read` existed, the
wait for a slow `/graphql` request body upload was outside every stage. A
client that sends the headers first and the body later adds that wait to
`total`. Deployment data must confirm this. To check it, make sure that the
`request_body_read` p99 follows the `total` p99 and that `pipeline_other`
stays near zero.

All hosts emit the same stage names. The `vhost` label tells you which host
received the request:

| `vhost` | Host |
|---------|------|
| `api` | `api.github.com` |
| `web` | `github.com` |
| `codeload` | `codeload.github.com` |
| `management` | The management host (web UI and its `/api/v3/` and `/api/graphql` paths) |
| `copilot` | `*.githubcopilot.com` (only `forward_proxy_selection` samples) |
| `unknown` | No inbound request, for example a background control-plane call |

Outbound requests keep the vhost of the inbound request. For example, a
`forward_proxy_selection` sample for a `git clone` has `vhost="web"`.

Example: 95th percentile of `scope_enforcement` per host:

```promql
histogram_quantile(0.95,
  sum by (le, vhost) (rate(ghp_proxy_decision_duration_seconds_bucket{stage="scope_enforcement"}[5m])))
```

!!! warning "Label change"
    Releases after 0.24.0 add the `vhost` label. Queries that aggregate with
    `sum by (...)` are unaffected. Queries, alerts or recording rules that
    match an exact label set must add `vhost`.

The `vhost` label on `ghp_passthrough_scope_denied_total` uses host names
(`github.com`, `codeload.github.com`), not these short values.

A stage that does not run on a code path records no sample. The histogram
never contains hard-coded zero durations.

**Histogram buckets.** The decision histogram uses these upper bounds:
10µs, 25µs, 50µs, 100µs, 250µs, 500µs, 1ms, 2.5ms, 5ms, 7.5ms, 10ms, 25ms,
50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s and 10s.

!!! warning "Bucket change"
    Releases after 0.24.0 add the 10µs, 25µs, 250µs, 2.5ms and 7.5ms buckets.
    All earlier buckets are kept. Quantile estimates for cheap stages become
    more accurate. If a dashboard or alert uses a specific `le` value, check
    it after you upgrade. Panels that compare data from before and after
    the upgrade can show a step change.

#### Upstream Transport Metrics

Recorded for every request ghp sends to GitHub, including its own
control-plane calls (those have `vhost="unknown"`). `protocol` is `h2`,
`http/1.1` or `unknown`; `vhost` uses the values listed above. No host, path
or proxy URL is used as a label.

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_upstream_sent_bytes_total` | Counter | Request body bytes sent upstream (labels: `protocol`, `vhost`) |
| `ghp_upstream_received_bytes_total` | Counter | Response body bytes received from upstream, added while the body streams (labels: `protocol`, `vhost`) |
| `ghp_upstream_connections_total` | Counter | Connection used by each upstream request (labels: `protocol`, `vhost`, `result` = `opened`, `reused`) |
| `ghp_upstream_first_byte_seconds` | Histogram | Time from the start of the upstream request (after proxy selection) to the first response byte; uses the decision histogram buckets (labels: `protocol`, `vhost`) |

```promql
# Upstream download throughput in Mbit/s, by protocol
sum by (protocol) (rate(ghp_upstream_received_bytes_total[5m])) * 8 / 1e6

# Share of upstream requests that had to dial a new connection
sum(rate(ghp_upstream_connections_total{result="opened"}[5m]))
  / sum(rate(ghp_upstream_connections_total[5m]))
```

Byte counters count HTTP body bytes only: no headers, HTTP/2 framing or TLS
overhead. A request body that the transport replays after a retry is not
counted again. Response bodies of `101 Switching Protocols` responses are not
counted.

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
| `ghp_token_scope_rejected_total` | Counter | Token scope entries rejected at creation or scope update (label: `reason` = `unknown_permission`, `invalid_level`) |

#### GitHub Rate Limit Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_github_ratelimit_remaining` | Gauge | Remaining GitHub API rate limit, per user |
| `ghp_github_ratelimit_limit` | Gauge | GitHub API rate limit ceiling, per user |
| `ghp_agent_repo_narrowing_failed_total` | Counter | Installation token mints refused because the repositories could not be narrowed to bare names of the installation account (label: `reason` = `owner_mismatch`, `malformed`, `lookup_failed`, `empty_login`). No request is sent to GitHub. |
| `ghp_github_token_refresh_total` | Counter | OAuth token refresh attempts per user (labels: `user`, `status`; `status` is `success` or `failure`) |

#### Security Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_auth_rate_limit_total` | Counter | Rate limiter rejections on auth endpoints (label: `endpoint`) |
| `ghp_scope_unmapped_denied_total` | Counter | Scoped-token REST requests denied because no scope rule matched the method and path (labels: `token_type`, `method`) |
| `ghp_block_anonymous_git_total` | Counter | Anonymous git requests blocked |
| `ghp_block_anonymous_git_enabled` | Gauge | Whether anonymous git blocking is active (1 or 0) |
| `ghp_management_host_rejected_total` | Counter | Requests to the management host's `/api/v3/` and `/api/graphql` paths rejected for lack of a GHP-issued token (label: `reason` — `anonymous` (401) or `native_token` (403)) |
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
| `ghp_passthrough_scope_denied_total` | Counter | Scoped client-token requests denied on the `github.com` and `codeload.github.com` virtual hosts (labels: `vhost`, `reason` = `unmapped`, `repo`, `permission`) |

The `archive` label is one of `tar.gz`, `zip`, `legacy.tar.gz`, or
`legacy.zip`. The `result` label is `redirect` (302 to the configured
caching mirror) or `passthrough` (forwarded to upstream codeload because the
org/repo is in the allow list or no `redirect_to` is configured). The full
ref (SHA, branch, or tag) is intentionally omitted from labels to keep
cardinality bounded; query the access log for per-ref breakdowns.

See [Codeload Redirect](../features/codeload.md) for configuration details.

### Webhook Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ghp_webhook_received_total` | Counter | `event`, `result` | Webhook deliveries presented to the ingress, by GitHub event and outcome |
| `ghp_webhook_publish_duration_seconds` | Histogram | — | JetStream publish + acknowledgement latency per delivery |
| `ghp_webhook_ngrok_tunnel_up` | Gauge | — | 1 while the embedded ngrok session is connected |
| `ghp_webhook_stream_messages` | Gauge | — | Deliveries currently retained in the JetStream stream (refreshed every 30 s) |
| `ghp_webhook_stream_bytes` | Gauge | — | Bytes currently retained in the stream |
| `ghp_webhook_subscribers_active` | Gauge | `kind` | Open subscribers: `sse` (admin stream / CLI) and `nats` (native clients) |

**`ghp_webhook_received_total` result values:**

- `published` — verified and stored
- `duplicate` — verified, but the delivery GUID was already stored within the dedupe window
- `invalid_signature` — no candidate secret verified `X-Hub-Signature-256` (or the header was missing)
- `unknown_app` — no secret could be resolved for the delivery's target
- `bad_request` — missing headers, malformed form body, or oversized payload
- `publish_error` — JetStream publish failed (`503` returned so the delivery can be resent)
- `internal_error` — secret lookup failed

The `event` label is bounded by GitHub's event catalogue; unknown names are
reported as `unknown`. The `backend` label on the HTTP metrics is `webhook`
for deliveries that arrived through the ngrok tunnel.

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
| `client.address` / `client.port` | Client address (honours the header named by `server.client_ip_header`; the port is omitted when the address came from a forwarded header) |
| `server.address` / `server.port` | Host the request targeted |
| `user_agent.original` | User-Agent header |
| `enduser.id` | GitHub username when available, otherwise the internal user ID |
| `http.request.header.<name>` / `http.response.header.<name>` | Selected headers (sensitive values such as `authorization` and `set-cookie` are `REDACTED`) |
| `ghp.backend` | Backend identifier (same values as the `backend` metric label) |
| `ghp.cache.state` / `ghp.cache.repo` | Git cache outcome, when applicable |

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
