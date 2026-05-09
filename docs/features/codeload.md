# Codeload Redirect

## The Problem

GitHub serves repository archive downloads (the `tar.gz` and `zip` snapshots
that workflows like `actions/checkout` resolve to) from a separate host:
`codeload.github.com`. A request looks like

```
GET https://codeload.github.com/actions/checkout/tar.gz/34e114876b0b11c390a56381ad16ebd13914f8d5
```

For a CI pipeline that runs the same `actions/checkout@v4` reference thousands
of times a day, every job ends up pulling the same tarball — keyed by an
immutable commit SHA — across the corporate network egress. When that egress
is constrained (proxy outages, bandwidth caps, rate limiting) builds either
slow down or fail outright with errors like:

```
Failed to download action 'https://codeload.github.com/actions/checkout/tar.gz/<sha>'.
Error: The proxy tunnel request to proxy 'http://proxy.example.com:3128/' failed
with status code '503'.
```

Because the archive content for a given `(owner, repo, sha)` triple never
changes, this traffic is highly cacheable. ghp can steer codeload requests to
an internal caching mirror so the first request fetches once from GitHub and
every subsequent request hits the mirror.

## How It Works

When `codeload.github.com` resolves to ghp (typically via DNS or an HTTP proxy
configured to forward this host), ghp inspects each request:

```
/{owner}/{repo}/{format}/{ref}
```

where `format` is one of `tar.gz`, `zip`, `legacy.tar.gz`, or `legacy.zip`,
and `ref` is a commit SHA, branch, or tag.

When `codeload.redirect_to` is configured, a matching request is answered
immediately with `302 Found` to `redirect_to + path`, preserving the original
query string. Non-matching paths and requests for orgs or org/repo pairs in
the allow list are forwarded transparently to upstream `codeload.github.com`
so other tooling continues to work.

ghp does **not** cache anything itself — it offloads the cache to a mirror you
already operate on the corporate network. The expected mirror behaviour is
straightforward:

- On first request for `(owner, repo, ref)`, fetch the archive from
  `codeload.github.com` and store it.
- On subsequent requests for the same `(owner, repo, ref)`, serve from
  storage.

Cacheability depends on what `ref` resolves to. When `ref` is a **commit
SHA** (the common case for `actions/checkout@<sha>` and any pinned action
reference) the `(owner, repo, sha)` tuple identifies an immutable archive
and the mirror can cache it indefinitely. When `ref` is a **branch or tag
name**, GitHub resolves it on each fetch and the underlying commit can move
— mirrors should treat those entries as mutable (e.g. apply a short TTL,
revalidate against `codeload.github.com`, or serve only SHA refs from
cache). The redirect itself is opaque to ghp; the cache policy is the
mirror's responsibility.

## Configuration

```yaml
codeload:
  redirect_to: "https://codeload.cache.example.com/"
  allow:
    - "myorg"              # all repos under this org bypass the redirect
    - "external/tool"      # only this specific repo bypasses
```

Or via environment variables:

```bash
GHP_CODELOAD_REDIRECT_TO=https://codeload.cache.example.com/
GHP_CODELOAD_ALLOW=myorg,external/tool
```

Indexed allow lists are supported for orchestrators that cannot pass
comma-separated values reliably:

```bash
GHP_CODELOAD_REDIRECT_TO=https://codeload.cache.example.com/
GHP_CODELOAD_ALLOW_COUNT=2
GHP_CODELOAD_ALLOW_0=myorg
GHP_CODELOAD_ALLOW_1=external/tool
```

When `redirect_to` is empty the codeload handler is effectively a transparent
proxy — every request is forwarded to upstream `codeload.github.com`. This
means simply pointing `codeload.github.com` at ghp does not break anything
even before the redirect is configured.

The `redirect_to` value must be an absolute URL (scheme + host); a relative
path causes ghp to log an error and fall back to passthrough. `redirect_to`
and the allow list are reloaded on `SIGUSR1` along with the rest of the
hot-reloadable configuration.

## Monitoring

Each archive request handled by the codeload handler increments the counter:

- **`ghp_codeload_redirect_total`** — labeled by `owner`, `repo`, `archive`
  (one of `tar.gz`, `zip`, `legacy.tar.gz`, `legacy.zip`), and `result`
  (`redirect` or `passthrough`).

The full `ref` (SHA, branch, or tag) is intentionally **not** a metric label:
including a SHA would create unbounded label cardinality. The full request URL
— and therefore the `ref` — is recorded in the JSON access log alongside the
backend (`codeload.github.com`), so per-SHA analysis is still possible via log
queries.

Use this metric to validate cache hit rates against your mirror's own counters
and to spot which `(owner, repo)` pairs dominate egress.

## Limitations

- **Detection is path-based.** The handler matches the URL pattern used by
  GitHub's archive download mechanism. If GitHub changes its URL structure in
  future, the regex would need updating.

- **Authentication is not forwarded on redirect.** A 302 strips the
  `Authorization` header in most clients, so private-repo archives served by
  the mirror require the mirror to handle authentication itself or be on a
  trusted internal network. The transparent passthrough path (allow list and
  no `redirect_to`) preserves the original request, including its
  Authorization header.

- **No HEAD availability check.** Unlike the [release redirect feature](release-controls.md#head-check),
  the codeload handler does not probe the mirror before redirecting. The
  expected mirror is a transparent caching proxy — fetching from upstream on
  cache miss — so a pre-flight check would always succeed and just add
  latency. If you operate a selective mirror that only stores a curated subset
  of archives, file an issue describing the use case.
