<p align="center">
  <img src="assets/octobear.png" width="300" alt="ghp logo">
</p>

# ghp

**GitHub Proxy for Autonomous Coding Agents**

Issue scoped, auditable tokens to coding agents. Agents interact with GitHub
through the proxy using opaque `ghp_`-prefixed tokens — they never see real
GitHub credentials.

- Agents use standard `gh` CLI, GitHub SDKs, or raw HTTP — no custom clients
- Repository and permission scopes enforced at the proxy
- Full audit trail of every proxied request
- Single static Go binary, self-hosted for your team

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Production Deployment](#production-deployment)
- [CLI](#cli)
- [Configuration](#configuration)
- [Development](#development)

## Quick Start

Build the binary (requires Go 1.24+):

```bash
CGO_ENABLED=0 go build -o ghp ./cmd/ghp
```

Generate an encryption key:

```bash
export GHP_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

Start the server in dev mode with SQLite (no GitHub App needed):

```bash
export GHP_DEV_MODE=true
export GHP_DATABASE_DRIVER=sqlite
export GHP_DATABASE_DSN=ghp.db
export GHP_SERVER_LISTEN=:8080
export GHP_GITHUB_CLIENT_ID=unused
export GHP_GITHUB_CLIENT_SECRET=unused

./ghp migrate
./ghp serve
```

In another terminal, create a test session (dev mode only):

```bash
curl -s -X POST http://localhost:8080/auth/test-login \
  -H 'Content-Type: application/json' \
  -d '{"username": "dev", "role": "admin"}'
```

Save the `session_token` from the response, then create a scoped proxy token:

```bash
curl -s -X POST http://localhost:8080/api/tokens \
  -H "Authorization: Bearer <session_token>" \
  -H 'Content-Type: application/json' \
  -d '{"repository": "owner/repo", "scopes": "contents:read,pulls:write", "duration": "1h"}'
```

Point your agent at the proxy:

```bash
export GH_HOST=localhost:8080
export GH_TOKEN=ghp_...  # token from the response above
```

The agent now uses GitHub through the proxy with scoped permissions.

## How It Works

Agents set `GH_HOST` to the proxy address and `GH_TOKEN` to a `ghp_`-prefixed
token. When the agent makes a GitHub API call, the proxy:

1. Validates the token and checks it hasn't expired or been revoked
2. Verifies the request targets the allowed repository and permission scope
3. Injects the real GitHub credentials (stored server-side, encrypted at rest)
4. Forwards the request to `api.github.com` and returns the response

```
Agent                        ghp                         GitHub
(GH_TOKEN=ghp_xxx)          (scope check +              (api.github.com)
(GH_HOST=proxy.local)        credential injection)
      │                          │                          │
      │─── GET /api/v3/... ─────▶│                          │
      │                          │── validate token         │
      │                          │── check scope            │
      │                          │── inject real credential  │
      │                          │─── GET /repos/... ───────▶│
      │                          │◀── 200 OK ───────────────│
      │◀── 200 OK ──────────────│                          │
```

The proxy supports both the REST API (`/api/v3/*`) and GraphQL API (`/api/graphql`).

## Production Deployment

### 1. Create a GitHub App

1. Go to **Settings > Developer Settings > GitHub Apps > New GitHub App**
2. Set the callback URL to `https://ghp.example.com/auth/github/callback`
3. Under **Permissions**, enable the permissions your agents will need
4. Enable **User-to-server tokens** under the OAuth section
5. Note the **Client ID** and generate a **Client Secret**

### 2. Configure the Server

Create `/etc/ghp/server.yaml`:

```yaml
github:
  client_id: "Iv1.abc123"
  client_secret: "your-client-secret"

database:
  driver: "postgres"
  dsn: "postgres://ghp:password@localhost:5432/ghp?sslmode=require"

server:
  listen: "unix:///run/ghp/ghp.sock"
  base_url: "https://ghp.example.com"

tokens:
  default_duration: "24h"
  max_duration: "168h"

metrics:
  enabled: true
  listen: ":9090"

admins:
  - "alice"
  - "bob"
```

Set the encryption key separately (don't put it in the config file):

```bash
# In the systemd unit's Environment or a drop-in
GHP_ENCRYPTION_KEY=<output of: openssl rand -hex 32>
```

### 3. Run Migrations

```bash
ghp migrate --config /etc/ghp/server.yaml
```

### 4. Systemd Units

Create `/etc/systemd/system/ghp.service`:

```ini
[Unit]
Description=ghp — GitHub Proxy for Coding Agents
After=network.target postgresql.service
Requires=ghp.socket

[Service]
Type=notify
ExecStart=/usr/local/bin/ghp serve --config /etc/ghp/server.yaml
User=ghp
Group=ghp
Restart=on-failure
WatchdogSec=30

Environment=GHP_ENCRYPTION_KEY=<your-key>

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ghp /var/log/ghp
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/ghp.socket`:

```ini
[Unit]
Description=ghp socket

[Socket]
ListenStream=/run/ghp/ghp.sock
SocketUser=www-data
SocketGroup=www-data
SocketMode=0660

[Install]
WantedBy=sockets.target
```

### 5. Reverse Proxy (Caddy)

Add to your Caddyfile:

```
ghp.example.com {
    reverse_proxy unix//run/ghp/ghp.sock
}
```

Caddy handles TLS automatically via Let's Encrypt.

### 6. Start

```bash
systemctl daemon-reload
systemctl enable --now ghp.socket
```

Verify the server is running:

```bash
curl -s https://ghp.example.com/auth/status
```

## CLI

```
ghp serve                 Run the server (proxy + web UI + API)
ghp migrate               Run database migrations
ghp auth login            Authenticate with the ghp server via GitHub OAuth
ghp auth status           Show current authentication status
ghp token create          Create a new scoped ghp_ token
ghp token list            List active tokens
ghp token revoke <id>     Revoke a token
ghp version               Print version information
```

### `ghp token create`

```bash
ghp token create \
  --repo goodtune/myproject \
  --scope contents:read,pulls:write,issues:write \
  --duration 48h \
  --session "claude-code-feature-123"
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--repo` | Yes | | Target repository (`owner/repo`) |
| `--scope` | Yes | | Comma-separated permissions (e.g. `contents:read,pulls:write`) |
| `--duration` | No | `24h` | Token lifetime (max: server-configured, default max 7 days) |
| `--session` | No | | Session identifier for audit tracking |

## Configuration

Server configuration is loaded from a YAML file (via `--config` flag or `GHP_CONFIG` env var). Environment variables override config file values using the `GHP_` prefix.

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_ENCRYPTION_KEY` | AES-256-GCM key for encrypting GitHub tokens at rest | (required) |
| `GHP_DATABASE_DRIVER` | `sqlite` or `postgres` | `sqlite` |
| `GHP_DATABASE_DSN` | Database connection string | `ghp.db` |
| `GHP_SERVER_LISTEN` | Listen address (TCP or `unix:///path`) | `:8080` |
| `GHP_GITHUB_CLIENT_ID` | GitHub App client ID | |
| `GHP_GITHUB_CLIENT_SECRET` | GitHub App client secret | |
| `GHP_TOKENS_DEFAULT_DURATION` | Default token lifetime | `24h` |
| `GHP_TOKENS_MAX_DURATION` | Maximum token lifetime | `168h` |
| `GHP_METRICS_ENABLED` | Enable Prometheus `/metrics` endpoint | `false` |
| `GHP_METRICS_LISTEN` | Metrics listener address (separate port) | `:9090` |
| `GHP_DEV_MODE` | Enable test endpoints (never use in production) | `false` |

See [SPEC.md](SPEC.md) for the complete configuration reference.

## Development

Run unit tests:

```bash
go test ./...
```

Run E2E tests (requires Node.js):

```bash
cd e2e
npm ci
npx playwright install --with-deps chromium
npx playwright test
```

Dev mode (`GHP_DEV_MODE=true`) enables the `/auth/test-login` endpoint, which
creates a test session without requiring GitHub OAuth. See [Quick Start](#quick-start)
for a full dev setup.
