# CLI Reference

ghp provides a command-line interface for server management and token
operations. Use `--help` on any command for full details.

    ghp --help

## Commands

| Command | Description |
|---------|-------------|
| [`ghp serve`](serve.md) | Run the server (proxy + web UI + API) |
| [`ghp migrate`](migrate.md) | Run database migrations |
| [`ghp auth`](auth.md) | Authenticate with the ghp server |
| [`ghp token`](token.md) | Create, list, and revoke proxy tokens |
| [`ghp apptoken`](apptoken.md) | Generate a GitHub App installation access token |
| `ghp version` | Print version information |

## Global Flags

| Flag | Description |
|------|-------------|
| `--config` | Path to server configuration file (or set `GHP_CONFIG`) |

## Client Configuration

The CLI reads client settings from a YAML config:

```yaml
server_url: "https://ghp.example.com"
user_token: "your-session-token"
```

### Config sources and precedence

Settings are merged from several sources. Later sources override earlier ones,
field by field:

1. **System config** — a fleet-wide file resolved per platform (mirroring
   dotvault's convention):
    - Linux: `/etc/xdg/ghp/config.yaml` (honouring `XDG_CONFIG_DIRS`)
    - macOS: `/Library/Application Support/ghp/config.yaml`
    - Windows: `%ProgramData%\ghp\config.yaml`
2. **User config** — `~/.config/ghp/config.yaml`. Overloads the system config.
3. **Environment variables** — `GHP_SERVER_URL`, `GHP_USER_TOKEN`.
4. **dotvault** — when a `dotvault:` stanza is configured (see below), the
   fields it resolves take the highest precedence.

| Variable | Description |
|----------|-------------|
| `GHP_SERVER_URL` | URL of the ghp management server |
| `GHP_USER_TOKEN` | Session token from `ghp auth login` |

This lets an operator deploy a single system config to a fleet (with
`server_url` and a `dotvault:` stanza) and have every user inherit it with
zero per-user configuration, while still allowing an individual user to
overload any field in `~/.config/ghp/config.yaml`.

`ghp auth login` and `ghp auth set-token` always write to the **user** config
(`~/.config/ghp/config.yaml`), never the system file.

### Sourcing the token from Vault with dotvault

Rather than storing `user_token` on disk, the CLI can fetch it just-in-time
from HashiCorp Vault via the [dotvault](https://github.com/goodtune/dotvault)
client. Add a `dotvault:` stanza:

```yaml
server_url: "https://ghp.example.com"

dotvault:
  service: ghp          # reads kv/users/<identity>/ghp (may contain slashes)
  # config: /etc/xdg/dotvault/config.yaml  # optional; defaults to dotvault's own config path
  fields:
    user_token: token   # set the CLI's user_token from the dotvault field "token"
```

dotvault itself owns Vault connectivity (address, CA, TLS), authentication,
cached-token resolution (including the peer-socket **token borrow** when its
config sets `vault.token_socket`), the KV mount, and the per-user path
convention — all read from dotvault's own config file. The ghp stanza only
declares **which** secret under the user root to read and which fields it maps
onto.

- `service` is the path segment under the per-user root
  (`kv/users/<identity>/<service>`); it may include slashes for a nested
  layout (e.g. `vendor/tool-name`).
- `fields` maps ghp CLI config keys to the dotvault secret field that supplies
  them. Supported keys: `user_token` and `server_url`.
- `config` optionally points at a specific dotvault config file; when omitted,
  dotvault's platform default is used.

When configured, the CLI calls dotvault's `Authenticate` flow (cached token →
token file → token borrow → interactive login as a last resort, suitable for a
human-run CLI) and reads the mapped fields. Resolution fails loudly: an
authentication error or a missing field is surfaced rather than silently
falling back. Combined with the system config above, a fleet can be deployed
with **no per-user token on disk at all**.

!!! note "Identity is the OS user"
    dotvault derives `<identity>` from the OS account the CLI runs as. Each
    user reads their own `kv/users/<their-username>/<service>` secret.
