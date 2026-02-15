# Documentation Restructure Design

Date: 2025-02-15

## Goal

Transform ghp documentation from a single monolithic README into three tiers:

1. **README.md** — slim landing page focused on users (not admins)
2. **mkdocs site** (`docs/`) — comprehensive admin and reference docs
3. **Man pages** — auto-generated from cobra command tree

## Assumptions

- A running ghp instance already exists; users need to know how to get a token
- DNS is already configured so `api.github.com` and `github.com` resolve to ghp
- Agents only need `GH_TOKEN` — no `GH_HOST` or other client-side config

## README.md

Slim, user-focused:

- Logo + one-liner
- What ghp does (3-4 bullets)
- Quick Start showing both CLI and Web UI paths briefly
- Links to full documentation site for everything else

No server setup, no configuration tables, no production deployment in the README.

## mkdocs Site

Theme: mkdocs-material (local build only, no CI deploy yet).

```
docs/
  index.md              # mirrors README intro, links to sections
  getting-started.md    # user quick start (expanded CLI + Web UI)
  how-it-works.md       # architecture, virtualhost routing, mermaid diagrams
  admin/
    installation.md     # building from source, requirements
    configuration.md    # full config reference (YAML + env vars table)
    deployment.md       # TLS certs, DNS, systemd, reverse proxy mode
    github-app.md       # creating the GitHub App for production
  cli/
    index.md            # overview of all commands
    serve.md            # ghp serve
    migrate.md          # ghp migrate
    auth.md             # ghp auth login/status
    token.md            # ghp token create/list/revoke
  web-ui.md             # dashboard, admin panel
  development.md        # contributing, running tests, dev mode setup
mkdocs.yml
```

## Man Pages

Use `github.com/spf13/cobra/doc` to auto-generate man pages from the cobra
command tree. Add:

- `cmd/ghp/doc.go` — hidden `ghp doc` subcommand (or build-time generator)
- `make man` target in Makefile

## Bug Fix

Remove `GH_HOST` output from `cmd/ghp/token.go:96` — agents connect
transparently via DNS and only need `GH_TOKEN`.
