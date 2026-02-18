# ghp

**GitHub Proxy for Autonomous Coding Agents**

ghp is a transparent reverse proxy that sits between your coding agents and
GitHub. Agents use standard GitHub tooling — they just set `GH_TOKEN` to a
scoped `ghp_`-prefixed token and everything works.

- **Scoped tokens** — each agent gets only the repository and permission access it needs
- **Audit trail** — every proxied request is logged
- **Transparent** — no custom clients, SDKs, or agent modifications required
- **Self-hosted** — single static Go binary for your team

## Next Steps

- [Getting Started](getting-started.md) — create your first token
- [How It Works](how-it-works.md) — architecture and virtualhost routing
- [Administration](admin/installation.md) — install and deploy ghp
- [CLI Reference](cli/index.md) — all commands
