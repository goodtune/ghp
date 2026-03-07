# ghp serve

Start the ghp server.

    ghp serve [--config path/to/config.yaml] [--migrate]

## Description

Starts the ghp server, which provides:

- GitHub API proxy with scope enforcement and credential injection
- Transparent passthrough for `github.com` and `*.githubcopilot.com` traffic
- Management web UI and token API
- Prometheus metrics on a dedicated port
- Built-in documentation at `/docs/` on the management host

The server runs until interrupted (`SIGINT`/`SIGTERM`). Configuration can be
reloaded without a restart by sending `SIGUSR1` — see
[Hot Reloading](../admin/configuration.md#hot-reloading).

## Flags

| Flag | Description |
|------|-------------|
| `--config` | Path to server configuration file (or set `GHP_CONFIG`) |
| `--migrate` | Automatically apply pending database migrations before starting |

## Server Modes

**TLS mode** (recommended for production): Set `server.https_listen` and
provide TLS certificates. Optionally set `server.http_listen` to run an
HTTP-to-HTTPS redirect server.

**Plain HTTP mode** (development or behind reverse proxy): Set `server.listen`
only. No TLS certificates needed.

**Systemd socket activation**: Set `server.systemd_socket_activation` to accept
file descriptors from systemd socket units instead of binding addresses directly.
In TLS mode, one socket provides HTTPS; two sockets provide HTTP (fd 3) and
HTTPS (fd 4).

## Systemd Integration

The server supports systemd readiness notification (`Type=notify`) and watchdog.
See [Deployment](../admin/deployment.md) for a complete systemd unit file.

## Examples

Development:

    GHP_DEV_MODE=true GHP_DATABASE_DRIVER=sqlite GHP_DATABASE_DSN=ghp.db \
      GHP_ENCRYPTION_KEY=$(openssl rand -hex 32) \
      ghp serve --migrate

Production:

    ghp serve --config /etc/ghp/server.yaml
