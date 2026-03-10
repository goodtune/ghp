# Configuration

Server configuration is loaded from a YAML file (via `--config` flag or
`GHP_CONFIG` env var). Environment variables with the `GHP_` prefix override
values from the config file.

## Environment Variables

### Core

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_ENCRYPTION_KEY` | AES-256-GCM key for encrypting GitHub tokens at rest (required) | |
| `GHP_DEV_MODE` | Enable test endpoints — never use in production | `false` |
| `GHP_ADMINS` | Comma-separated list of admin GitHub usernames | |

### Database

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_DATABASE_DRIVER` | `sqlite` or `postgres` | `sqlite` |
| `GHP_DATABASE_DSN` | Database connection string | `ghp.db` |

### Server

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_SERVER_LISTEN` | Listen address for plain HTTP mode | `:8080` |
| `GHP_SERVER_HTTPS_LISTEN` | HTTPS listen address (enables TLS mode) | |
| `GHP_SERVER_HTTP_LISTEN` | HTTP listen address for HTTPS redirects | |
| `GHP_SERVER_MANAGEMENT_HOST` | Hostname for the management UI and API | |
| `GHP_SERVER_BASE_URL` | Public base URL for OAuth callbacks and links | |
| `GHP_SERVER_SYSTEMD_SOCKET_ACTIVATION` | Accept sockets from systemd instead of binding addresses | `false` |

### GitHub

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_GITHUB_CLIENT_ID` | GitHub App client ID (for OAuth login) | |
| `GHP_GITHUB_CLIENT_SECRET` | GitHub App client secret (for OAuth login) | |
| `GHP_GITHUB_APP_ID` | GitHub App ID (enables `gha_` agent tokens) | |
| `GHP_GITHUB_PRIVATE_KEY` | PEM-encoded GitHub App private key content | |
| `GHP_GITHUB_PRIVATE_KEY_FILE` | Path to GitHub App private key PEM file | |
| `GHP_GITHUB_ENTERPRISE_SLUG` | Enterprise slug for access restriction header | |
| `GHP_GITHUB_BASE_URL` | Reserved for future GitHub Enterprise Server support; currently ignored (server always uses `https://api.github.com`) | `https://api.github.com` |

### TLS

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_TLS_CERT_FILE` | Path to TLS certificate file (single-cert convenience) | |
| `GHP_TLS_KEY_FILE` | Path to TLS private key file (single-cert convenience) | |
| `GHP_TLS_MIN_VERSION` | Minimum TLS version: `1.2` or `1.3` | `1.2` |

### Tokens

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_TOKENS_DEFAULT_DURATION` | Default token lifetime | `24h` |
| `GHP_TOKENS_MAX_DURATION` | Maximum token lifetime | `168h` |

### Logging

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_LOGGING_OUTPUT` | Log destination: `stdout` or `file` | `stdout` |
| `GHP_LOGGING_LEVEL` | Log level: `debug`, `info`, `warn`, `error` | `info` |
| `GHP_LOGGING_FILE_PATH` | Path to log file (when output is `file`) | |

### Metrics

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_METRICS_ENABLED` | Enable the dedicated Prometheus metrics server | `true` |
| `GHP_METRICS_LISTEN` | Listen address for the metrics server | `:9136` |

### OpenTelemetry

OpenTelemetry tracing is experimental and subject to change.

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_OTEL_ENABLED` | Enable OpenTelemetry tracing | `false` |
| `GHP_OTEL_ENDPOINT` | OTLP exporter endpoint (e.g. `http://localhost:4317`) | |
| `GHP_OTEL_PROTOCOL` | OTLP transport protocol: `grpc` or `http` | `grpc` |

### OAuth Broker

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_AUTH_JWT_PRIVATE_KEY` | PEM-encoded RSA private key for signing broker JWTs (enables broker) | |
| `GHP_AUTH_JWT_PRIVATE_KEY_FILE` | Path to RSA private key PEM file for broker JWTs | |
| `GHP_AUTH_ALLOWED_REDIRECTS` | Comma-separated list of permitted OAuth redirect URIs | |

See [OAuth Broker](../features/oauth-broker.md) for integration details.

### Border Policy

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_BLOCK_GHP` | Block GitHub personal access tokens (`ghp_`) | `false` |
| `GHP_BLOCK_GHO` | Block GitHub OAuth access tokens (`gho_`) | `false` |
| `GHP_BLOCK_GHU` | Block GitHub user-to-server tokens (`ghu_`) | `false` |
| `GHP_BLOCK_GHS` | Block GitHub server-to-server tokens (`ghs_`) | `false` |
| `GHP_BLOCK_GHR` | Block GitHub refresh tokens (`ghr_`) | `false` |
| `GHP_BLOCK_ANONYMOUS_GIT` | Block unauthenticated git smart HTTP requests | `false` |

See [Token Type Border Policy](../features/border-policy.md) for details.

### Release Controls

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_RELEASES_MODE` | Release download policy: `block`, `redirect`, or empty (disabled) | |
| `GHP_RELEASES_REDIRECT_TO` | Base URL for redirect mode (must be absolute) | |
| `GHP_RELEASES_REDIRECT_HEAD_CHECK` | Issue a HEAD request to the redirect target before redirecting; if the target returns 404, serve a friendly error page instead | `false` |
| `GHP_RELEASES_REDIRECT_NOT_FOUND_TEMPLATE` | Path to a custom HTML template for the 404 page (see [HEAD Check](../features/release-controls.md#head-check)) | |
| `GHP_RELEASES_ALLOW` | Comma-separated org or org/repo entries exempt from the policy | |
| `GHP_RELEASES_ALLOW_COUNT` | Number of indexed allow entries (use with `GHP_RELEASES_ALLOW_0`, `GHP_RELEASES_ALLOW_1`, ...) | |

See [Release Download Controls](../features/release-controls.md) for details.

## Full YAML Reference

```yaml
# encryption_key: ""            # WARNING: prefer GHP_ENCRYPTION_KEY env var; never commit this to version control

github:
  client_id: ""
  client_secret: ""
  app_id: 0                    # GitHub App ID (enables gha_ agent tokens)
  private_key_file: ""         # path to PEM file for GitHub App authentication
  # private_key: ""            # or inline PEM content (useful in containers)
  enterprise_slug: ""
  # base_url: ""               # (reserved) intended GHES API base URL override; currently ignored

database:
  driver: "sqlite"             # "sqlite" or "postgres"
  dsn: "ghp.db"

server:
  listen: ":8080"              # plain HTTP mode (development or behind reverse proxy)
  https_listen: ":443"         # TLS mode (recommended for production)
  http_listen: ":80"           # HTTP-to-HTTPS redirect server
  management_host: ""          # hostname for management UI (e.g. ghp.example.com)
  base_url: ""                 # public base URL (e.g. https://ghp.example.com)
  # systemd_socket_activation: false  # accept sockets from systemd

tls:
  certificates:
    - cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"
  min_version: "1.2"           # minimum TLS version: "1.2" (default) or "1.3"

tokens:
  default_duration: "24h"
  max_duration: "168h"         # 7 days

logging:
  output: "stdout"             # "stdout" or "file"
  level: "info"                # "debug", "info", "warn", "error"
  file:
    path: "/var/log/ghp/ghp.log"

metrics:
  enabled: true                # set to false to disable
  listen: ":9136"              # dedicated metrics server port

# otel:                        # OpenTelemetry tracing (experimental)
#   enabled: false
#   endpoint: ""               # OTLP exporter endpoint (e.g. http://localhost:4317)
#   protocol: "grpc"           # "grpc" or "http"

auth:
  jwt_private_key_file: ""     # RSA private key for OAuth broker JWT signing (RS256)
  # jwt_private_key: ""        # or inline PEM content
  allowed_redirects:            # permitted redirect_uri values for broker flow
    - "https://app.example.com/auth/callback"
    - "*.internal.example.com"  # wildcard domain patterns supported

block:
  ghp: false                   # block GitHub personal access tokens (ghp_)
  gho: false                   # block GitHub OAuth access tokens (gho_)
  ghu: false                   # block GitHub user-to-server tokens (ghu_)
  ghs: false                   # block GitHub server-to-server tokens (ghs_)
  ghr: false                   # block GitHub refresh tokens (ghr_)
  anonymous_git: false         # block unauthenticated git smart HTTP traffic

releases:
  mode: ""                     # "block", "redirect", or "" (disabled)
  redirect_to: ""              # absolute URL base for redirect mode
  redirect_head_check: false   # HEAD-check redirect target; serve 404 page if target returns 404
  redirect_not_found_template: ""  # path to custom 404 HTML template (optional)
  allow:                       # org or org/repo entries exempt from policy
    - "myorg"
    - "trusted/tool"

admins:
  - "alice"
  - "bob"

dev_mode: false                # enable test endpoints (never use in production)
```

## Encryption Key

Generate an encryption key:

```bash
export GHP_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

This key encrypts GitHub tokens at rest. Store it securely — if lost, stored
tokens cannot be decrypted. Use an environment variable or secrets manager
rather than putting it in the config file.

## Hot Reloading

The following settings can be changed without restarting the server by sending
`SIGUSR1` to the ghp process:

- `admins` — admin user list (roles are re-synced immediately)
- `tokens.default_duration` — default token lifetime applied to new tokens
- `auth.allowed_redirects` — OAuth broker allowed redirects
- `block` — border policy settings (anonymous git, token type blocking)
- `releases` — release download policy and allow list

Settings that require a restart: database driver/DSN, server listen addresses,
TLS certificates, the encryption key, logging configuration, metrics
enable/disable, OAuth broker enable/disable and signing key
(`auth.jwt_private_key` / `auth.jwt_private_key_file`), and `tokens.max_duration`
(captured at server startup).

```bash
# Reload configuration
kill -USR1 $(pidof ghp)
```

!!! note "Admin role is re-evaluated on login and reload"
    The `admins` list is the source of truth for admin privileges. When the
    configuration is reloaded, admin roles are immediately re-synced with the
    database. Users also have their role re-evaluated each time they log in
    via GitHub OAuth.
