# ghp token

Create, list, and revoke proxy tokens.

## Subcommands

### ghp token create

    ghp token create --scope contents:read,pulls:write [flags]

Create a new scoped token for an agent. There are two token types:

**Proxy tokens (`ghx_`)** — user-scoped, backed by your OAuth credential:

    ghp token create \
      --repo goodtune/myproject \
      --scope contents:read,pulls:write,issues:write \
      --duration 48h \
      --session "claude-code-feature-123"

**Agent tokens (`gha_`)** — app-scoped, backed by a GitHub App installation
(admin only, requires GitHub App configuration on the server):

    ghp token create \
      --type agent \
      --installation-id 12345678 \
      --repos owner/repo1,owner/repo2 \
      --scope contents:read,pulls:write \
      --session "ci-agent-run-42"

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--type` | No | `proxy` | Token type: `proxy` or `agent` |
| `--repo` | Proxy only | | Target repository (`owner/repo`) |
| `--repos` | Agent only | | Comma-separated repositories |
| `--installation-id` | Agent only | | GitHub App installation ID |
| `--scope` | Yes | | Comma-separated permissions (e.g. `contents:read,pulls:write`) |
| `--duration` | No | `24h` | Token lifetime (max: server-configured, default max 7 days) |
| `--session` | No | | Session identifier for audit tracking |

### ghp token list

    ghp token list

List your active tokens with type, repositories, scopes, session, expiry, and
request count.

### ghp token revoke

    ghp token revoke <token-id>

Revoke a token immediately. The token ID is shown by `ghp token list`.

## Authentication

All token commands require authentication. Set `GHP_SERVER_URL` and
`GHP_USER_TOKEN`, or run `ghp auth login` first.
