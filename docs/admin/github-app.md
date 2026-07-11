# GitHub App Setup

ghp authenticates users via GitHub OAuth and uses a GitHub App for API access.

## Create the App

1. Go to **Settings > Developer Settings > GitHub Apps > New GitHub App**
2. Set the **Homepage URL** to your ghp management host (e.g. `https://ghp.example.com`)
3. Set the **Callback URL** to `https://ghp.example.com/auth/github/callback`
4. Under **Permissions**, enable the permissions your agents will need
5. Enable **User-to-server tokens** under the OAuth section
6. Note the **Client ID** and generate a **Client Secret**

## Configure ghp

Add the credentials to your server configuration:

```yaml
github:
  client_id: "Iv1.abc123"
  client_secret: "your-client-secret"
```

Or via environment variables:

    export GHP_GITHUB_CLIENT_ID=Iv1.abc123
    export GHP_GITHUB_CLIENT_SECRET=your-client-secret

## Agent Tokens (gha_)

To enable agent tokens (`gha_` prefix), ghp needs the App ID and private key
so it can generate GitHub App installation tokens on demand. These are separate
from the OAuth credentials above — the App ID and private key allow ghp to
authenticate as the GitHub App itself.

1. On the GitHub App settings page, note the **App ID**
2. Under **Private keys**, click **Generate a private key** and save the `.pem` file

Add to your server configuration:

```yaml
github:
  app_id: 123456
  private_key_file: "/etc/ghp/github-app.pem"
```

Or provide the PEM content directly (useful for container deployments):

```yaml
github:
  app_id: 123456
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
```

Or via environment variables:

    export GHP_GITHUB_APP_ID=123456
    export GHP_GITHUB_PRIVATE_KEY_FILE=/etc/ghp/github-app.pem

To find the **installation ID** for your organisation, install the App on the
target organisation and note the installation ID from the URL
(`https://github.com/settings/installations/<id>`), or use the GitHub API:

    gh api /orgs/<org>/installation --jq '.id'

Admins can then create agent tokens via the CLI:

    ghp token create \
      --type agent \
      --installation-id 12345678 \
      --repos owner/repo1,owner/repo2 \
      --scope contents:read,pulls:write


## Enterprise Restriction

If your organisation uses GitHub Enterprise Cloud, set the enterprise slug to
restrict API access to members of your enterprise:

```yaml
github:
  enterprise_slug: "my-enterprise"
```

This injects the `sec-GitHub-allowed-enterprise` header on all proxied API
requests (api.github.com REST and GraphQL, github.com git smart HTTP, and
Copilot traffic). GitHub rejects requests carrying this header when they are
authenticated by an account outside the enterprise, effectively blocking
interaction with off-enterprise repositories.

### Exceptions

GitHub itself provides no per-repository exception mechanism for this feature —
its documentation directs proxy operators to inject the header only for the
traffic they intend to restrict. GHP implements exactly that: the
`github.enterprise_exceptions` list names owners and repositories for which
the header is omitted, so the enterprise can deliberately allow contributions
to specific external projects while keeping the restriction everywhere else.

```yaml
github:
  enterprise_slug: "my-enterprise"
  enterprise_exceptions:
    # Allow everything owned by these accounts (users or orgs), and one
    # specific repository. Matching is case-insensitive.
    - match:
        - torvalds
        - kubernetes/website

    # Gate an exception on team membership: only active members of
    # my-org/oss-contributors may reach this repository. The requesting
    # user's identity is resolved from their credential; anyone else (or a
    # request whose identity cannot be resolved) is treated as if the
    # exception did not exist.
    - match:
        - external-org/shared-sdk
      teams:
        - my-org/oss-contributors

    # Substitute a managed identity: requests to this repository are
    # performed with an installation token minted from the referenced
    # GitHub App (registered via the admin UI), so e.g. pushes are made by
    # the integration's bot account rather than the user's own credential.
    - match:
        - partner-org/integration
      teams:
        - my-org/partner-integrators
      identity:
        app_record_id: "9f3c2a1e-…"   # database record ID from the admin UI
```

How each request is evaluated:

1. The request target (owner, and repository where present) is derived from
   the path: `/repos/{owner}/{repo}/...`, `/users/{username}/...`, and
   `/orgs/{org}/...` on api.github.com, and `/{owner}/{repo}[.git]/...` on
   github.com.
2. If no exception matches, the header is injected as usual.
3. If an exception with `teams` matches, the caller must be an active member
   of at least one listed team, otherwise the header stays on. Membership is
   checked with an installation token from the **default** GitHub App, which
   must be installed on the team's organization with the `members: read`
   permission. Verdicts are cached for five minutes.
4. If the exception has an `identity`, an installation token is minted from
   that app's installation on the target owner (scoped to the target
   repository where known) and silently replaces the caller's credential.
   The referenced app must be installed on the external account. If minting
   fails, the exception **fails closed**: the restriction header stays on.
5. Otherwise the header is simply omitted and the caller's own credential is
   forwarded.

Known limitations:

- **GraphQL requests are never exempted.** The API target cannot be derived
  from the URL path, so `/graphql` always carries the restriction header.
  Use the REST API for excepted repositories.
- **Copilot traffic is never exempted** for the same reason.
- Team gating identifies callers via their GitHub credential. Requests
  authenticated by `gha_` agent tokens resolve to the App's bot account,
  which will not be a team member — team-gated exceptions are therefore
  effectively human-only.
- Exceptions are static configuration: changes require a restart.
- The enterprise accepts data exfiltration risk for excepted targets; audit
  usage via the `ghp_enterprise_exception_total` metric and access logs.
