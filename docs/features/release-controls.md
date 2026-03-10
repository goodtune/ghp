# Release Download Controls

## The Problem

GitHub Releases are a popular distribution mechanism for pre-built binaries,
installers, and archives. When autonomous coding agents have access to
`github.com` through ghp, they can download arbitrary release assets — pulling
in unvetted binaries from any public repository. This is a supply chain risk:
an agent instructed (or tricked) into downloading and executing a release
binary could compromise the host environment.

Unlike source code fetched via `git clone` (which is scoped to specific
repositories by ghp's token system), release downloads are simple HTTPS GETs
against `github.com` that bypass the API scope model entirely. The release
controls feature closes this gap.

## How It Works

The releases handler intercepts requests matching the GitHub release download
path pattern:

```
/{owner}/{repo}/releases/download/{tag}/{asset}
```

When a matching request arrives, ghp evaluates it against the configured
policy **before** the request reaches GitHub. Two modes are available:

### Block Mode

Returns `403 Forbidden` immediately. The request never leaves your network.

```yaml
releases:
  mode: block
```

This is the simplest and most restrictive option. Use it when agents should
never download release assets (the common case for coding agents that only
need source access).

### Redirect Mode

Returns a `302 Found` redirect to an alternative download server. The full
original path and query string are preserved.

```yaml
releases:
  mode: redirect
  redirect_to: "https://releases.internal.example.com/"
```

A request for `/cli/cli/releases/download/v2.50.0/gh_linux_amd64.tar.gz`
would redirect to
`https://releases.internal.example.com/cli/cli/releases/download/v2.50.0/gh_linux_amd64.tar.gz`.

This mode is useful when your organization mirrors approved release assets on
an internal server — agents are steered to the vetted copies rather than
downloading directly from GitHub. The `redirect_to` value must be an absolute
URL (scheme + host); relative paths are rejected at runtime.

#### HEAD Check

When the redirect target is a selective mirror that only hosts a subset of
releases, agents following the redirect may receive an unfriendly error from
the mirror for assets it doesn't carry. Enable `redirect_head_check` to have
ghp issue a `HEAD` request to the redirect target URL before sending the 302.
If the mirror returns **404**, ghp serves a user-friendly HTML error page
instead of redirecting.

```yaml
releases:
  mode: redirect
  redirect_to: "https://releases.internal.example.com/"
  redirect_head_check: true
```

For any response other than 404 (including network errors), ghp proceeds with
the redirect as normal — the HEAD check is purely an optimistic availability
probe.

##### Custom 404 Template

The built-in 404 page is clean and informative, but you can replace it with
your own HTML by setting `redirect_not_found_template` to the path of an
[html/template](https://pkg.go.dev/html/template) file on disk:

```yaml
releases:
  mode: redirect
  redirect_to: "https://releases.internal.example.com/"
  redirect_head_check: true
  redirect_not_found_template: "/etc/ghp/404.html"
```

The template receives the following data:

| Field   | Description                                      | Example                    |
|---------|--------------------------------------------------|----------------------------|
| `Owner` | Repository owner / organisation                  | `cli`                      |
| `Repo`  | Repository name                                  | `cli`                      |
| `Tag`   | Release tag                                      | `v2.50.0`                  |
| `Asset` | Asset filename                                   | `gh_linux_amd64.tar.gz`    |
| `URL`   | Full redirect target URL that returned 404       | `https://mirror.example.com/cli/cli/releases/download/v2.50.0/gh_linux_amd64.tar.gz` |

If the custom template cannot be loaded (missing file, parse error), ghp logs
an error and falls back to the built-in default.

### Allow List

Both modes support an allow list of organisations or specific repositories
that are exempt from the policy. Allowed entries pass through to GitHub
unmodified.

```yaml
releases:
  mode: block
  allow:
    - "myorg"              # all repos under this org are allowed
    - "external/approved"  # only this specific repo is allowed
```

Matching is case-insensitive. An org-level entry (e.g. `myorg`) allows all
repositories under that organisation. An org/repo entry (e.g. `external/approved`)
allows only that specific repository.

## Non-release Traffic

Only paths matching `/{owner}/{repo}/releases/download/` are affected. All
other traffic — API calls, git operations, archive downloads, repository
browsing — passes through completely unchanged regardless of the releases
policy.

## Configuration

See the [Configuration Reference](../admin/configuration.md) for the full list
of environment variables and YAML fields.

=== "YAML"

    ```yaml
    releases:
      mode: "block"                    # "block", "redirect", or "" (disabled)
      redirect_to: ""                  # base URL for redirect mode
      redirect_head_check: false       # HEAD-check target before redirecting
      redirect_not_found_template: ""  # custom 404 HTML template path
      allow:
        - "myorg"
        - "trusted/tool"
    ```

=== "Environment Variables"

    ```bash
    GHP_RELEASES_MODE=block
    GHP_RELEASES_REDIRECT_TO=https://releases.internal.example.com/
    GHP_RELEASES_REDIRECT_HEAD_CHECK=true
    GHP_RELEASES_REDIRECT_NOT_FOUND_TEMPLATE=/etc/ghp/404.html
    GHP_RELEASES_ALLOW=myorg,trusted/tool
    ```

=== "Indexed Allow List"

    For container orchestrators that cannot pass comma-separated values
    reliably, use indexed environment variables:

    ```bash
    GHP_RELEASES_MODE=block
    GHP_RELEASES_ALLOW_COUNT=2
    GHP_RELEASES_ALLOW_0=myorg
    GHP_RELEASES_ALLOW_1=trusted/tool
    ```

    Indexed entries replace the comma-separated `GHP_RELEASES_ALLOW` value
    entirely when `GHP_RELEASES_ALLOW_COUNT` is set.

## Monitoring

When `redirect_head_check` is enabled, ghp records two metrics:

- **`ghp_releases_redirect_head_check_total`** — a counter labeled by `result`
  (`found`, `not_found`, `error`) that tracks how often the mirror has the
  requested asset, is missing it, or is unreachable.
- **`ghp_proxy_decision_duration_seconds`** with `stage="redirect_head_check"` —
  a histogram recording the latency of each HEAD probe, so you can monitor the
  overhead the availability check adds.

Use these to tune your mirror coverage and set alerts for elevated `not_found`
or `error` rates. See [Monitoring](../admin/monitoring.md) for the full metrics
reference.

## Limitations

- **Release pages and metadata are not blocked.** Only the binary download
  path (`/releases/download/`) is intercepted. Agents can still view release
  pages and list releases via the API — they just cannot fetch the assets.

- **Detection is path-based.** The handler matches the URL pattern used by
  GitHub's release download mechanism. If GitHub changes its URL structure in
  future, the pattern would need updating.

- **HEAD check adds latency.** When `redirect_head_check` is enabled, each
  redirected request incurs an extra round-trip to the mirror before the client
  receives a response. This is typically fast for local mirrors but should be
  considered in latency-sensitive environments.
