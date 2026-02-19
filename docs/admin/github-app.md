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
requests.
