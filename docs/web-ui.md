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
    - View all configured apps (record ID, name, GitHub App ID, client ID, base URL, default status, whether a webhook secret is set)
    - **Add App** — register a new GitHub App with its credentials (name, GitHub App ID, client ID, client secret, webhook secret, private key PEM, base URL, default flag)
    - **Edit** — update any app field inline, including rotating private keys and setting or removing the webhook secret
    - **Delete** — remove an app (tokens referencing it will no longer resolve)
    - One app must be marked as the default; changing the default is handled automatically
- **Agent Tokens** — create `gha_`-prefixed agent tokens backed by a GitHub App installation:
    - Select an app from the dropdown (only shown when apps are configured)
    - Choose an installation and target repositories
    - The section is hidden when no apps exist in the store
- **Webhooks** (shown only when `webhooks.enabled` is set) — the ingress URL
  to register with GitHub (with a copy button), ngrok tunnel and NATS listener
  state, stream size and retention, how many apps have a secret, and the most
  recent deliveries with a button that loads each payload. See
  [Webhooks](features/webhooks.md).
- **Users** — list all registered users with their GitHub ID, role, and creation date
- **All Tokens** — view, edit and revoke tokens across all users:
    - **Edit** — change a token's repositories and permissions inline. The
      permissions use the same selector as the create form. It offers every
      canonical permission name with `read` and `read and write` levels,
      because the admin page has no grant data for the token's owner. The
      server still checks each entry. Leave every permission at
      **No access** to make the token open-scoped.
    - The form checks the scopes with the server's rules before it sends
      them. If the server rejects the update, its message shows in the form.
    - **Show current scopes as JSON** shows the stored scopes as text.
    - The form sends scopes only when you change the permissions. An edit
      that changes only the repositories leaves the stored scopes as they
      are.
    - A stored entry that is not a valid scope (for example `pulls`, from a
      token created before validation) is listed in a warning. It stays
      stored until you change the permissions, which replaces the stored
      scopes with your selection.
    - If the stored scopes hold only invalid entries, the token denies every
      permission check. Saving without a change keeps it that way; the form
      does not send empty scopes.
    - The form does not let an edit remove every scope by accident: empty
      scopes make the token open-scoped. To do that, tick
      **Clear all scopes (make the token open-scoped)**.

In dev mode, navigating to `/admin` without a session shows a test-login form
that authenticates directly as an admin.
