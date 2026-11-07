# #330: `vhost` label on `ghp_proxy_decision_duration_seconds`

## Problem

The API host, the `github.com` passthrough, the `codeload.github.com` handler
and the management host all emit the same `stage` values. Operators cannot
split per-stage latency by host. There are about 86 `ObserveDecision` call
sites, and most of them do not know which host they serve.

## Decision

The host is decided once, in `newHostDispatch` (`internal/server/server.go`).
The dispatcher stores a fixed vhost value on the request context with
`metrics.WithVhost(ctx, v)` before it calls the backend handler.

`ObserveDecision` takes the context as its first argument:

    func ObserveDecision(ctx context.Context, stage, tokenType string, dur time.Duration)

It reads the value with `metrics.VhostFromContext(ctx)`. Call sites pass the
context they already hold (`r.Context()`, or `req.Context()` for the outbound
request in the forward proxy `Proxy` function). Outbound requests are built
from the inbound context, so `forward_proxy_selection` and
`redirect_head_check` inherit the inbound vhost.

We chose a context value over a vhost parameter or a per-vhost handler struct:

- The vhost is set in one place. No handler constructor changes.
- The new `ctx` parameter makes the compiler find every call site, so no call
  site can be missed silently.
- The value set is closed: `WithVhost` takes only the exported constants.

## Label values

| Value        | Host                                   |
|--------------|----------------------------------------|
| `api`        | `api.github.com`                       |
| `web`        | `github.com`                           |
| `codeload`   | `codeload.github.com`                  |
| `management` | the management host (UI, `/api/v3/`)   |
| `copilot`    | `*.githubcopilot.com`                  |
| `unknown`    | no inbound request                     |

`copilot` is a fifth value. The Copilot passthrough records no pipeline stage
of its own, but its outbound requests go through forward proxy selection. To
label them `api` or `web` would be wrong, and `unknown` would hide them.

`unknown` is not avoidable: control-plane calls with no inbound request (for
example background OAuth refresh or App token minting at startup) run forward
proxy selection with a bare context. These are the only samples with
`vhost="unknown"`.

## Compatibility

Adding a label is a breaking change for queries that match exact label sets.
Queries that aggregate with `sum by (...)` or `histogram_quantile(...,
sum by (le, stage) (...))` are unaffected. Queries or recording rules that
match an exact series must add `vhost`.
