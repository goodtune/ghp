# Getting Started

This guide assumes your administrator has already deployed ghp and configured
DNS so that `api.github.com` and `github.com` resolve to the proxy on your
network. You just need a token.

## Create a Token

### Web UI

1. Open your team's ghp dashboard (e.g. `https://ghp.example.com`)
2. Sign in with GitHub
3. Click **Create Token**
4. Select the target repository
5. Choose permission scopes (e.g. `contents:read`, `pulls:write`)
6. Set a duration (default: 24 hours)
7. Click **Create** and copy the `ghx_`-prefixed token

### CLI

First, authenticate with the ghp server:

    ghp auth login

Then create a scoped proxy token:

    ghp token create \
      --repo owner/repo \
      --scope contents:read,pulls:write \
      --duration 48h \
      --session "my-coding-session"

Admins can also create agent tokens backed by a GitHub App installation
(see [GitHub App Setup](admin/github-app.md) for server configuration):

    ghp token create \
      --type agent \
      --installation-id 12345678 \
      --repos owner/repo1,owner/repo2 \
      --scope contents:read,pulls:write

## Configure Your Agent

Set the token as `GH_TOKEN` in the agent's environment:

    export GH_TOKEN=ghx_xxxxxxxxxxxxxxxx

That's it. The agent now uses GitHub through the proxy with scoped permissions.
Standard `gh` CLI, GitHub SDKs, and raw HTTP all work transparently.

## Manage Tokens

List your active tokens:

    ghp token list

Revoke a token:

    ghp token revoke <token-id>

Or use the web dashboard to view and revoke tokens.

## Scopes

Scopes follow the GitHub API permission model. Common scopes:

| Scope | Description |
|-------|-------------|
| `contents:read` | Read repository contents (files, commits) |
| `contents:write` | Push commits, create/update files |
| `pulls:read` | Read pull requests |
| `pulls:write` | Create and update pull requests |
| `issues:read` | Read issues |
| `issues:write` | Create and update issues |
| `metadata:read` | Read repository metadata (always included) |
