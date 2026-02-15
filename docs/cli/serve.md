# ghp serve

Run the ghp server (proxy + web UI + API).

    ghp serve [--config path/to/config.yaml]

## Description

Starts the ghp server, which includes:

- GitHub API proxy with scope enforcement and credential injection
- Passthrough handlers for `github.com` and `*.githubcopilot.com`
- Management web UI and API
- Optional Prometheus metrics endpoint

The server runs until interrupted (SIGINT/SIGTERM).

## Modes

**TLS mode** (recommended for production): Set `server.https_listen` and
provide TLS certificates. Optionally set `server.http_listen` for HTTP-to-HTTPS
redirects.

**Plain HTTP mode** (development or behind reverse proxy): Set `server.listen`
only. No TLS certificates needed.

## Systemd Integration

The server supports systemd readiness notification (`Type=notify`) and watchdog.
See [Deployment](../admin/deployment.md) for a complete systemd unit file.

## Examples

Development:

    GHP_DEV_MODE=true GHP_DATABASE_DRIVER=sqlite GHP_DATABASE_DSN=ghp.db \
      GHP_ENCRYPTION_KEY=$(openssl rand -hex 32) \
      ghp serve

Production:

    ghp serve --config /etc/ghp/server.yaml
