# README Design

## Approach

Single comprehensive README.md with table of contents. Covers both deployment operators and agent users.

## Structure

1. **Header**: Centered octobear.png logo, title, one-liner, 4 key bullets
2. **Quick Start**: Build, dev mode with SQLite, test session, create token, point agent — under 2 minutes, no GitHub App needed
3. **How It Works**: Short explanation + simplified flow diagram
4. **Production Deployment**: GitHub App setup, YAML config, migrations, systemd units, Caddy reverse proxy
5. **CLI**: Compact reference of all subcommands with flags
6. **Configuration**: Key env vars table, link to SPEC.md for full reference
7. **Development**: Test commands, dev mode note

## Decisions

- Audience: both deployers and agent operators
- Logo: included at top
- Reverse proxy example: Caddy (automatic TLS, matches simple/self-hosted philosophy)
- Single file: everything in README.md, no separate docs files
- Quick start uses dev mode + SQLite to avoid GitHub App prerequisite
- Production section covers the real deployment with PostgreSQL + systemd + Caddy
- ~250-300 lines total
