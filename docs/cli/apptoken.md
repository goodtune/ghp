# ghp apptoken

Generate a GitHub App installation access token directly from the CLI.

Uses the configured App ID and private key to authenticate with GitHub
and issue an open-scoped installation token. Useful for local development,
CI scripts, or any context where you need a raw GitHub token from your
App's installation.

## Usage

    ghp apptoken [installation-name]

| Argument | Required | Description |
|----------|----------|-------------|
| `installation-name` | No | GitHub account login (org or user) the App is installed on |

If `installation-name` is omitted and only one installation exists, it is
used automatically. If multiple installations exist, the command lists them
and exits with an error.

## Examples

With a single installation (auto-detected):

    ghp apptoken --config ghp.yaml

By name:

    ghp apptoken --config ghp.yaml myorg

Pipe-friendly:

    export GH_TOKEN=$(ghp apptoken myorg)

## Configuration

This command requires server-side configuration (`--config` or `GHP_CONFIG`)
with the GitHub App credentials:

```yaml
github:
  app_id: 12345
  private_key_file: /path/to/private-key.pem
```

The private key can also be provided inline via `github.private_key` or the
`GHP_GITHUB_PRIVATE_KEY` environment variable.
