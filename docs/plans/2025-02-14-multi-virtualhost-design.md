# Multi-Virtualhost Architecture

ghp evolves from a single-purpose API proxy behind a reverse proxy into a
direct-listening TLS termination point that serves four distinct virtualhosts.

## Motivation

Deploying ghp behind a reverse proxy (e.g. Caddy) adds operational complexity
and limits what ghp can do. By listening directly on :443 and routing by Host
header, ghp can:

- Proxy both API and web/git traffic to GitHub transparently
- Intercept ghp_ tokens on any GitHub-bound request
- Inject enterprise access restriction headers without a separate MITM proxy
- Serve its own management UI on a dedicated hostname

## Virtual Hosts

| Host | Behavior |
|------|----------|
| `api.github.com` | API proxy with ghp_ token resolution and scope enforcement (existing) |
| `github.com` | Transparent reverse proxy to real GitHub; intercepts ghp_ tokens when present |
| `*.githubcopilot.com` | Transparent reverse proxy preserving original subdomain; no token interception |
| Configured management host | Management UI, OAuth auth, management API (existing mux) |

Requests to unrecognized hosts receive a 404.

## Architecture

### Single server, host-based dispatch

One `http.Server` on :443 with SNI-based TLS cert selection. A top-level
handler dispatches by `r.Host`:

```
request arrives on :443
  ├─ Host: api.github.com       →  proxyHandler (existing)
  ├─ Host: github.com           →  githubPassthroughHandler (new)
  ├─ Host: *.githubcopilot.com  →  copilotPassthroughHandler (new)
  ├─ Host: <management_host>    →  mux (existing)
  └─ anything else              →  404
```

A second `http.Server` on :80 redirects all HTTP requests to HTTPS.

Both servers share the same graceful shutdown lifecycle.

### TLS

Manual PEM cert+key files loaded at startup. The `tls.Config.GetCertificate`
callback selects the certificate by SNI hostname. Wildcard certs (e.g.
`*.githubcopilot.com`) are matched automatically by Go's TLS library.

No ACME/Let's Encrypt — the impersonated domains (`github.com`,
`api.github.com`) require internally-generated certificates since you don't
control those domains at public CAs.

### Configuration

```yaml
server:
  https_listen: ":443"
  http_listen: ":80"
  management_host: "ghp.example.com"
  # Legacy: plain HTTP mode (no TLS, single port, behind reverse proxy)
  # listen: ":8080"

tls:
  certificates:
    - cert_file: /etc/ghp/certs/api.github.com.pem
      key_file: /etc/ghp/certs/api.github.com-key.pem
    - cert_file: /etc/ghp/certs/github.com.pem
      key_file: /etc/ghp/certs/github.com-key.pem
    - cert_file: /etc/ghp/certs/githubcopilot.com.pem
      key_file: /etc/ghp/certs/githubcopilot.com-key.pem
    - cert_file: /etc/ghp/certs/ghp.example.com.pem
      key_file: /etc/ghp/certs/ghp.example.com-key.pem

github:
  enterprise_slug: "my-enterprise-id"  # optional
```

The `api.github.com` and `github.com` hostnames are implicit — they are always
those names. Only `management_host` is configurable.

### Backward compatibility

If the legacy `server.listen` field is set and `https_listen` is not, the
server runs as plain HTTP on a single port — exactly as it does today. This
preserves the reverse-proxy deployment model and keeps dev mode simple.

## Component Details

### github.com passthrough handler

`httputil.ReverseProxy` targeting `https://github.com`. The `Director` function:

1. Sets upstream scheme/host to `https://github.com`
2. Copies path and query string unchanged
3. Checks `Authorization` header for `ghp_` token prefix
4. If present: resolves token, swaps for real GitHub credential
5. If not present: leaves all headers as-is (passthrough)

No scope enforcement. No path inspection. GitHub decides access.

Works for web pages, git smart HTTP protocol (clone, fetch, push), and any
other github.com traffic.

### *.githubcopilot.com passthrough handler

Same transparent reverse proxy pattern, but:

- Forwards to the **original host** (preserves subdomain, e.g.
  `api.githubcopilot.com` → real `api.githubcopilot.com`)
- No ghp_ token interception (Copilot uses its own auth)
- Host matching by suffix: `.githubcopilot.com` or exact `githubcopilot.com`

### Enterprise access restriction header

When `github.enterprise_slug` is configured, every request forwarded to
real GitHub across all three GitHub-facing virtualhosts gets the header:

```
sec-GitHub-allowed-enterprise: <enterprise_slug>
```

This replaces the need for a separate "break and inspect" proxy to enforce
GitHub Enterprise Managed Users restrictions. Combined with corporate DNS
pointing `github.com`, `api.github.com`, and `*.githubcopilot.com` at ghp,
this enforces enterprise access restrictions for web, API, git, and Copilot
traffic in a single deployment.

### Access logging

All requests on the three GitHub-facing virtualhosts get standard HTTP access
log entries via slog at info level:

- Timestamp, client IP, method, host, path, status code, response size,
  duration, user agent

This is separate from the existing audit trail, which only fires for ghp_
token usage.

### HTTP redirect server

Minimal handler on :80 that issues `301 Moved Permanently` redirects to
`https://{host}{path}` for all requests.

## Dev / Local Testing

In dev mode (plain HTTP, single port), all host routing still works via the
`Host` header — no TLS certs needed:

```bash
# API proxy
curl -H "Host: api.github.com" http://localhost:8080/user

# github.com passthrough
curl -H "Host: github.com" http://localhost:8080/org/repo

# Copilot passthrough
curl -H "Host: api.githubcopilot.com" http://localhost:8080/...

# Management UI
curl -H "Host: ghp.example.com" http://localhost:8080/
```

Host routing operates at the HTTP layer, not the TLS layer. SNI is only
used for certificate selection.
