# Web UI

ghp includes a built-in web dashboard for managing tokens and viewing audit
logs. Access it at the management host (e.g. `https://ghp.example.com`).

## Authentication

Users authenticate via GitHub OAuth. Click **Sign in with GitHub** to start the
OAuth flow.

In dev mode, the login page shows a test-login form that creates a session
directly — no GitHub OAuth required.

## Dashboard

After signing in, the dashboard shows:

- **Your Tokens** — active tokens with repository, scopes, expiry, and request count
- **Create Token** — form to create a new scoped `ghp_` token
- **Revoke** — revoke any of your tokens immediately

## Admin Panel

The `/admin` page is available to users with the `admin` role. Admins are
configured via the `admins` list in the server config file (GitHub usernames).

The admin panel provides:

- **Users** — list all registered users with their GitHub ID, role, and creation date
- **All Tokens** — view and revoke tokens across all users
- **Audit Log** — browse the full audit trail of proxied requests

In dev mode, navigating to `/admin` without a session shows a test-login form
that authenticates directly as an admin.
