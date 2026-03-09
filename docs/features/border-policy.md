# Token Type Border Policy

ghp can block specific types of GitHub tokens from passing through the proxy.
This prevents agents from bypassing ghp's scoping model by using real GitHub
tokens directly.

## How It Works

When a request arrives with a token that is not a ghp-managed token (`ghx_` or
`gha_`), ghp inspects the token's prefix to determine its type. If that type
is blocked in the configuration, the request is rejected with `403 Forbidden`
before it reaches GitHub.

GitHub uses these token prefixes:

| Prefix | Token Type | Config Key |
|--------|------------|------------|
| `ghp_` | Personal access tokens (classic) | `block.ghp` |
| `gho_` | OAuth access tokens | `block.gho` |
| `ghu_` | User-to-server tokens | `block.ghu` |
| `ghs_` | Server-to-server tokens | `block.ghs` |
| `ghr_` | Refresh tokens | `block.ghr` |

## Configuration

Enable blocking for specific token types:

=== "YAML"

    ```yaml
    block:
      ghp: true    # block personal access tokens
      gho: true    # block OAuth tokens
      ghu: true    # block user-to-server tokens
      ghs: false   # allow server-to-server tokens
      ghr: true    # block refresh tokens
    ```

=== "Environment Variables"

    ```bash
    GHP_BLOCK_GHP=true
    GHP_BLOCK_GHO=true
    GHP_BLOCK_GHU=true
    GHP_BLOCK_GHS=false
    GHP_BLOCK_GHR=true
    ```

## Typical Usage

A common configuration blocks all external GitHub token types so that only
ghp-managed tokens can reach GitHub through the proxy:

```yaml
block:
  ghp: true
  gho: true
  ghu: true
  ghs: true
  ghr: true
  anonymous_git: true
```

This ensures all agent traffic is subject to ghp's scoping, auditing, and
expiration controls.

## Hot Reloading

Border policy settings can be reloaded without restarting the server. After
updating the configuration file, send `SIGUSR1` to the ghp process to reload
it — the new settings take effect on the next request after the signal is
received.

See [Configuration — Hot Reloading](../admin/configuration.md#hot-reloading) for
details.

!!! note "ghp's own tokens are not affected"
    Blocking only applies to GitHub's own token types. ghp's managed tokens
    (`ghx_`, `gha_`) are always accepted — they are resolved and replaced with
    real credentials as part of normal proxy operation.
