# ghp

**GitHub Proxy for Autonomous Coding Agents**

ghp is a transparent reverse proxy that sits between your coding agents and
GitHub. Agents use standard GitHub tooling — they set `GH_TOKEN` to a ghp
token and everything works. No custom clients, SDKs, or agent modifications
required.

- **Scoped tokens** — each agent gets only the repository and permission access it needs
- **Audit trail** — every proxied request is logged with user, token, and repository
- **Border policy** — block specific GitHub token types from passing through
- **Release controls** — block or redirect binary downloads from GitHub Releases
- **OAuth broker** — centralise GitHub authentication for other services on your network
- **Self-hosted** — single static Go binary, deploy with systemd or containers

## For Users

- [Getting Started](getting-started.md) — create your first token and configure your agent
- [Token Scoping](features/token-scoping.md) — understand repository and permission restrictions
- [Web UI](web-ui.md) — manage tokens from the dashboard

## For Administrators

- [Installation](admin/installation.md) — build and install ghp
- [Configuration](admin/configuration.md) — full reference for all settings
- [Deployment](admin/deployment.md) — TLS, DNS, systemd, and reverse proxy setup
- [GitHub App Setup](admin/github-app.md) — enable OAuth login and agent tokens
- [Monitoring](admin/monitoring.md) — Prometheus metrics and access logs
- [CLI Reference](cli/index.md) — all commands
