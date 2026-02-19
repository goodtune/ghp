# ghp token

Create, list, and revoke proxy tokens.

## Subcommands

### ghp token create

    ghp token create --repo owner/repo --scope contents:read,pulls:write [flags]

Create a new scoped `ghx_` proxy token for an agent.

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--repo` | Yes | | Target repository (`owner/repo`) |
| `--scope` | Yes | | Comma-separated permissions (e.g. `contents:read,pulls:write`) |
| `--duration` | No | `24h` | Token lifetime (max: server-configured, default max 7 days) |
| `--session` | No | | Session identifier for audit tracking |

Example:

    ghp token create \
      --repo goodtune/myproject \
      --scope contents:read,pulls:write,issues:write \
      --duration 48h \
      --session "claude-code-feature-123"

### ghp token list

    ghp token list

List your active tokens with repository, scopes, session, expiry, and request
count.

### ghp token revoke

    ghp token revoke <token-id>

Revoke a token immediately. The token ID is shown by `ghp token list`.

## Authentication

All token commands require authentication. Set `GHP_SERVER_URL` and
`GHP_USER_TOKEN`, or run `ghp auth login` first.
