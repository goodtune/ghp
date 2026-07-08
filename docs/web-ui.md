# Web UI

ghp includes a built-in web dashboard for managing tokens. Access it at the
management host (e.g. `https://ghp.example.com`).

## Authentication

Users authenticate via GitHub OAuth. Click **Sign in with GitHub** to start the
OAuth flow.

In dev mode, the login page shows a test-login form that creates a session
directly — no GitHub OAuth required.

## Dashboard

After signing in, the dashboard shows:

- **Your Tokens** — active tokens with repository, scopes, and expiry
- **Create Token** — form to create a new scoped `ghx_` token
- **Revoke** — revoke any of your tokens immediately

## Admin Panel

The `/admin` page is available to users with the `admin` role. Admins are
configured via the `admins` list in the server config file (GitHub usernames).

The admin panel provides:

- **Apps** — manage GitHub App registrations:
    - View all configured apps (record ID, name, GitHub App ID, client ID, base URL, default status)
    - **Add App** — register a new GitHub App with its credentials (name, GitHub App ID, client ID, client secret, private key PEM, base URL, default flag)
    - **Edit** — update any app field inline, including rotating private keys
    - **Delete** — remove an app (tokens referencing it will no longer resolve)
    - One app must be marked as the default; changing the default is handled automatically
- **Agent Tokens** — create `gha_`-prefixed agent tokens backed by a GitHub App installation:
    - Select an app from the dropdown (only shown when apps are configured)
    - Choose an installation and target repositories
    - The section is hidden when no apps exist in the store
- **Users** — list all registered users with their GitHub ID, role, and creation date
- **All Tokens** — view and revoke tokens across all users

In dev mode, navigating to `/admin` without a session shows a test-login form
that authenticates directly as an admin.
