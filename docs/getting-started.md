# Getting Started

This guide is for users who need to create tokens and configure agents. It
assumes your administrator has already deployed ghp and configured DNS so that
`api.github.com` and `github.com` resolve to the proxy on your network.

## Create a Token

### Web UI

1. Open your team's ghp dashboard (e.g. `https://ghp.example.com`)
2. Sign in with GitHub
3. Click **Create Token**
4. Select the target repository (or leave blank for an open-scoped token)
5. Choose permission scopes (e.g. `contents:read`, `pull_requests:write`)
6. Set a duration (default: 24 hours)
7. Click **Create** and copy the `ghx_`-prefixed token

### CLI

First, authenticate with the ghp server:

    ghp auth login

Then create a scoped proxy token:

    ghp token create \
      --repo owner/repo \
      --scope contents:read,pull_requests:write \
      --duration 48h \
      --session "my-coding-session"

Administrators can also create agent tokens backed by a GitHub App installation
(see [GitHub App Setup](admin/github-app.md) for server configuration):

    ghp token create \
      --type agent \
      --installation-id 12345678 \
      --repos owner/repo1,owner/repo2 \
      --scope contents:read,pull_requests:write

When multiple GitHub Apps are configured, use the `--app-id` flag to specify
which app the agent token should use. If omitted, the default app is used.

See [Token Scoping](features/token-scoping.md) for a full explanation of
repository restrictions, permission scopes, and open-scoped tokens.

## Configure Your Agent

Set the token as `GH_TOKEN` in the agent's environment:

    export GH_TOKEN=ghx_xxxxxxxxxxxxxxxx

That's it. The agent now uses GitHub through the proxy with scoped permissions.
Standard `gh` CLI, GitHub SDKs, and raw HTTP all work transparently.

## Manage Tokens

List your active tokens:

    ghp token list

Revoke a token immediately:

    ghp token revoke <token-id>

Or use the [web dashboard](web-ui.md) to view and revoke tokens.

## Scopes Reference

Scopes follow the GitHub API permission model:

| Scope | Description |
|-------|-------------|
| `contents:read` | Read repository contents (files, commits) |
| `contents:write` | Push commits, create/update files |
| `pull_requests:read` | Read pull requests |
| `pull_requests:write` | Create and update pull requests |
| `issues:read` | Read issues |
| `issues:write` | Create and update issues |
| `metadata:read` | Read repository metadata (always permitted) |

When no scopes are specified, the token inherits the full permissions of the
underlying credential. See [Token Scoping](features/token-scoping.md) for
details on how scoping works.
