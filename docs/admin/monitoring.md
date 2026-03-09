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
`github.com`, `copilot`, or `management`.

#### Proxy Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ghp_proxy_request_duration_seconds` | Histogram | Duration of authenticated requests processed by the proxy (API and git smart-HTTP) (labels: `backend`, `method`, `status`, `token_type`, `type`, `user`, `app`) |
| `ghp_proxy_request_total` | Counter | Total authenticated requests processed by the proxy (API and git smart-HTTP) (labels: `backend`, `method`, `status`, `token_type`, `type`, `user`, `app`) |
| `ghp_proxy_decision_duration_seconds` | Histogram | Time spent in each stage of the proxy decision pipeline (labels: `stage`, `token_type`) |

The `type` label distinguishes API traffic from git smart-HTTP traffic (e.g.
`type="git"` for git operations proxied via the `github.com` backend). The
decision pipeline metric breaks down the overhead ghp adds to each request
into individually timed stages (token extraction, scope enforcement, credential
resolution, etc.), so you can identify where latency originates.

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

## Access Logs

ghp writes structured JSON access logs for every request across all four
virtualhosts. Each log entry typically includes:

- HTTP method, host, URI/path, and status code
- Request duration
- Backend identifier (same values as the `backend` label used in metrics)
- User identifier (GitHub username when available)
- Selected request and response headers (sensitive values such as `Authorization` and `Set-Cookie` are redacted)

Configure logging output and level:

```yaml
logging:
  output: "stdout"         # "stdout" or "file"
  level: "info"            # "debug", "info", "warn", "error"
  file:
    path: "/var/log/ghp/ghp.log"
```

## Server Response Header

Every response from ghp includes a `Server: GitHub Proxy <version>` header.
This makes it easy to verify that traffic is flowing through ghp rather than
directly to GitHub, and to identify which version of ghp is running.

## Health Check

The `/auth/status` endpoint on the management host returns the current
authentication status and can be used as a basic health check:

    curl -s https://ghp.example.com/auth/status
