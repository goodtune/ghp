# Configuration

Server configuration is loaded from a YAML file (via `--config` flag or
`GHP_CONFIG` env var). Environment variables override config file values using
the `GHP_` prefix.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_ENCRYPTION_KEY` | AES-256-GCM key for encrypting GitHub tokens at rest | (required) |
| `GHP_DATABASE_DRIVER` | `sqlite` or `postgres` | `sqlite` |
| `GHP_DATABASE_DSN` | Database connection string | `ghp.db` |
| `GHP_SERVER_LISTEN` | Listen address for legacy plain HTTP mode | `:8080` |
| `GHP_SERVER_HTTPS_LISTEN` | HTTPS listen address (enables TLS mode) | |
| `GHP_SERVER_HTTP_LISTEN` | HTTP listen address for HTTPS redirects | |
| `GHP_SERVER_MANAGEMENT_HOST` | Hostname for management UI/API | |
| `GHP_SERVER_BASE_URL` | Base URL for OAuth callbacks and links | |
| `GHP_GITHUB_CLIENT_ID` | GitHub App client ID (OAuth) | |
| `GHP_GITHUB_CLIENT_SECRET` | GitHub App client secret (OAuth) | |
| `GHP_GITHUB_APP_ID` | GitHub App ID (for `gha_` agent tokens) | |
| `GHP_GITHUB_PRIVATE_KEY` | PEM-encoded private key content (for `gha_` agent tokens) | |
| `GHP_GITHUB_PRIVATE_KEY_FILE` | Path to PEM private key file (for `gha_` agent tokens) | |
| `GHP_GITHUB_ENTERPRISE_SLUG` | Enterprise slug for access restriction header | |
| `GHP_TOKENS_DEFAULT_DURATION` | Default token lifetime | `24h` |
| `GHP_TOKENS_MAX_DURATION` | Maximum token lifetime | `168h` |
| `GHP_METRICS_ENABLED` | Enable Prometheus `/metrics` endpoint on management host | `false` |
| `GHP_DEV_MODE` | Enable test endpoints (never use in production) | `false` |

## Full YAML Reference

```yaml
github:
  client_id: ""
  client_secret: ""
  app_id: 0                    # GitHub App ID (enables gha_ agent tokens)
  private_key_file: ""         # path to PEM file for GitHub App authentication
  # private_key: ""            # or inline PEM content (useful in containers)
  enterprise_slug: ""

database:
  driver: "sqlite"
  dsn: "ghp.db"

server:
  listen: ":8080"              # legacy plain HTTP mode
  https_listen: ":443"         # TLS mode (overrides listen)
  http_listen: ":80"           # HTTP-to-HTTPS redirect
  management_host: ""          # management UI hostname
  base_url: ""                 # e.g. https://ghp.example.com

tls:
  certificates:
    - cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"

tokens:
  default_duration: "24h"
  max_duration: "168h"

logging:
  output: "stdout"             # "stdout" or "file"
  level: "info"                # "debug", "info", "warn", "error"
  file:
    path: "/var/log/ghp/ghp.log"

metrics:
  enabled: false               # serves /metrics on the management host

admins:
  - "alice"
  - "bob"
```

## Encryption Key

Generate an encryption key:

    export GHP_ENCRYPTION_KEY=$(openssl rand -hex 32)

This key encrypts GitHub tokens at rest. Store it securely — if lost, stored
tokens cannot be decrypted. Do not put it in the config file; use an
environment variable or secrets manager.
