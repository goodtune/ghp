<p align="center">
  <img src="assets/octobear.png" width="300" alt="ghp logo">
</p>

# ghp

**GitHub Proxy for Autonomous Coding Agents**

Issue scoped, auditable tokens to coding agents. Agents interact with GitHub
through the proxy using opaque `ghx_`-prefixed tokens — they never see real
GitHub credentials.

- Agents use standard `gh` CLI, GitHub SDKs, or raw HTTP — no custom clients
- Repository and permission scopes enforced at the proxy
- Full audit trail of every proxied request
- Single static Go binary, self-hosted for your team

## Quick Start

Your administrator has already deployed ghp and configured DNS so that
`api.github.com` and `github.com` resolve to the proxy on your network.
You just need a token.

### Option A: Web UI

1. Open your team's ghp dashboard (e.g. `https://ghp.example.com`)
2. Sign in with GitHub
3. Click **Create Token**, choose a repository and scopes
4. Copy the `ghx_`-prefixed token

### Option B: CLI

```bash
ghp auth login
ghp token create --repo owner/repo --scope contents:read,pulls:write
```

### Give the token to your agent

```bash
export GH_TOKEN=ghx_...
```

The agent now uses GitHub through the proxy with scoped permissions. No other
configuration is needed — standard `gh` CLI, GitHub SDKs, and raw HTTP all
work transparently.

## Documentation

| Topic | Link |
|-------|------|
| How it works | [Architecture & virtualhost routing](docs/how-it-works.md) |
| Server setup | [Installation & deployment](docs/admin/deployment.md) |
| Configuration | [Full reference](docs/admin/configuration.md) |
| CLI reference | [All commands](docs/cli/index.md) |
| Web UI | [Dashboard & admin panel](docs/web-ui.md) |
| Development | [Contributing & dev mode](docs/development.md) |

> **Tip:** Run `mkdocs serve` from the repository root to browse the full
> documentation site locally.
