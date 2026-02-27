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

The CLI reads client settings from `~/.config/ghp/config.yaml`:

```yaml
server_url: "https://ghp.example.com"
user_token: "your-session-token"
```

These can also be set via environment variables:

| Variable | Description |
|----------|-------------|
| `GHP_SERVER_URL` | URL of the ghp management server |
| `GHP_USER_TOKEN` | Session token from `ghp auth login` |
