# README Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Write a comprehensive README.md covering quick start and production deployment for ghp.

**Architecture:** Single README.md file with 7 sections. Content derived from SPEC.md, existing CLI commands, and CI workflow. No code changes — documentation only.

**Tech Stack:** Markdown

---

### Task 1: Write the README

**Files:**
- Modify: `README.md`
- Reference: `SPEC.md` (full spec), `.github/workflows/test.yml` (CI config), `cmd/ghp/*.go` (CLI commands), `internal/config/config.go` (config structure)

**Step 1: Write `README.md`**

The README has 7 sections per the design doc at `docs/plans/2026-02-13-readme-design.md`. Key content notes:

**Section 1 — Header:**
- Centered logo: `<p align="center"><img src="assets/octobear.png" width="200"></p>`
- Title: `# ghp`
- Subtitle: GitHub Proxy for Autonomous Coding Agents
- One-liner about scoped auditable tokens
- 4 key bullets: standard tooling, scope enforcement, audit trail, single binary

**Section 2 — Quick Start:**
- Prerequisites: Go 1.24+
- Build: `CGO_ENABLED=0 go build -o ghp ./cmd/ghp`
- Generate encryption key: `openssl rand -hex 32`
- Env vars block setting: `GHP_DEV_MODE=true`, `GHP_ENCRYPTION_KEY`, `GHP_DATABASE_DRIVER=sqlite`, `GHP_DATABASE_DSN=ghp.db`, `GHP_SERVER_LISTEN=:8080`, plus dummy GitHub App values
- Run: `./ghp migrate && ./ghp serve`
- Create test session via `curl -X POST localhost:8080/auth/test-login`
- Create token via `curl -H "Authorization: Bearer ..." localhost:8080/api/tokens`
- Configure agent: `export GH_HOST=localhost:8080` and `export GH_TOKEN=ghp_...`

**Section 3 — How It Works:**
- Short paragraph: agents set `GH_HOST` + `GH_TOKEN`, proxy validates scope, injects real credentials, forwards to GitHub
- Simplified ASCII flow: Agent -> ghp (scope check) -> GitHub API

**Section 4 — Production Deployment:**
6 subsections:
1. **Create a GitHub App** — go to Settings > Developer Settings > GitHub Apps, configure OAuth callback URL, note client ID + secret
2. **Configure** — example `/etc/ghp/server.yaml` with github, database (postgres), server (unix socket), tokens, metrics, admins sections. Encryption key via `GHP_ENCRYPTION_KEY` env var.
3. **Run Migrations** — `ghp migrate --config /etc/ghp/server.yaml`
4. **Systemd** — service unit (Type=notify, hardened with `ProtectSystem=strict` etc.) and socket unit (Unix socket at `/run/ghp/ghp.sock`)
5. **Reverse Proxy** — Caddyfile: `ghp.example.com { reverse_proxy unix//run/ghp/ghp.sock }`
6. **Start** — `systemctl enable --now ghp.socket`

**Section 5 — CLI:**
Table format with all commands:
- `ghp serve`, `ghp migrate`, `ghp auth login`, `ghp auth status`
- `ghp token create` with `--repo`, `--scope`, `--duration`, `--session` flags
- `ghp token list`, `ghp token revoke <id>`, `ghp version`

**Section 6 — Configuration:**
- Brief: YAML via `--config` or `GHP_CONFIG`, env vars override with `GHP_` prefix
- Table of key env vars: `GHP_DATABASE_DRIVER`, `GHP_DATABASE_DSN`, `GHP_SERVER_LISTEN`, `GHP_ENCRYPTION_KEY`, `GHP_GITHUB_CLIENT_ID`, `GHP_GITHUB_CLIENT_SECRET`, `GHP_TOKENS_DEFAULT_DURATION`, `GHP_TOKENS_MAX_DURATION`, `GHP_METRICS_ENABLED`, `GHP_METRICS_LISTEN`, `GHP_DEV_MODE`
- Link to SPEC.md for full reference

**Section 7 — Development:**
- `go test ./...` for unit tests
- `cd e2e && npm ci && npx playwright install --with-deps chromium && npx playwright test` for E2E
- Note about dev mode enabling `/auth/test-login`

**Step 2: Review the README**

Read through the full README and verify:
- All commands are accurate against the actual codebase
- Config examples match `internal/config/config.go` defaults
- CLI flags match `cmd/ghp/*.go`
- No broken markdown formatting

**Step 3: Commit**

```bash
git add README.md docs/plans/
git commit -m "Write README with quick start and production deployment guide"
```
