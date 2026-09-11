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

    # By name (recommended) — resolves app and installation automatically:
    ghp token create \
      --app mybot \
      --installation myorg \
      --scope contents:read,pulls:write \
      --session "ci-agent-run-42"

    # By numeric ID (advanced):
    ghp token create \
      --type agent \
      --installation-id 12345678 \
      --repos owner/repo1,owner/repo2 \
      --scope contents:read,pulls:write

    # Open-scoped, no expiry (requires server allow_no_expiry):
    ghp token create \
      --app mybot \
      --installation myorg \
      --duration never

When `--app` or `--installation` is used, `--type agent` is inferred
automatically. If only one app is configured (or a default is set), `--app`
can be omitted and the installation will be resolved against the default app.

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--type` | No | `proxy` | Token type: `proxy` or `agent`. Inferred as `agent` when `--app` or `--installation` is used |
| `--app` | No | | App name — resolves to app record ID via the server. Alternative to `--app-id` |
| `--app-id` | No | | Database app record UUID — selects which GitHub App to use in multi-app mode. Alternative to `--app` |
| `--repo` | No | | Target repository (`owner/repo`) for proxy tokens |
| `--repos` | No | | Comma-separated repositories |
| `--installation` | No | | Installation account login (e.g., org name) — resolves to installation ID via the server. Alternative to `--installation-id` |
| `--installation-id` | No | | GitHub App installation ID (numeric). Alternative to `--installation` |
| `--scope` | No | | Comma-separated permissions (e.g. `contents:read,pulls:write`). Omit for open-scoped |
| `--duration` | No | `24h` | Token lifetime (e.g. `48h`, `168h`; max: server-configured, default max 7 days). Use `never` to create a token with no expiry (requires `tokens.allow_no_expiry` in server config) |
| `--session` | No | | Session identifier for audit tracking |


### ghp token list

    ghp token list

List your active tokens with ID, type, repositories, scopes, session, and
expiry.

### ghp token revoke

    ghp token revoke <token-id>

Revoke a token immediately. The token ID is shown by `ghp token list`.

## Authentication

All token commands require authentication. Set `GHP_SERVER_URL` and
`GHP_USER_TOKEN`, or run `ghp auth login` first.
