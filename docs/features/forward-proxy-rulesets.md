# Forward Proxy Rulesets

By default, ghp's outbound GitHub traffic honours the process environment
(`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`) — a good default for most
deployments. Forward proxy rulesets let you go further and deliberately steer
GitHub-destined traffic out through specific egress paths at runtime.

The motivating case is CI: continuous heavy API and clone traffic from CI
fleets concentrated on a single egress IP has been known to trigger IP-level
throttling or banning by GitHub. Splitting that traffic across multiple egress
proxies — or pinning CI subnets to their own path while interactive users ride
the default — contains the blast radius when an egress IP gets blocked.

Rulesets are **runtime configuration**: they live in the database and are
managed through the admin API, not the config file or environment. Changes
take effect immediately on the instance that served the API call and propagate
to other instances within a minute via a periodic route-table refresh — no
restart required.

## Concepts

A **ruleset** groups:

- one or more **proxy targets** — forward proxy URLs (`http`, `https`,
  `socks5`, or `socks5h` schemes), each with an optional weight;
- a **routing algorithm** that picks a target per request;
- one or more **rules** that select which traffic the ruleset applies to.

### Rule types

| Type | Value | Matches |
|---|---|---|
| `token` | proxy token UUID | Requests authenticated by that specific ghx_/gha_ token |
| `app` | app record UUID | Requests from agent tokens minted against that GitHub App |
| `net` | CIDR (e.g. `10.42.0.0/16`) | Requests whose client source IP falls in the network — cheap to evaluate and not tied to tokens, ideal when CI runners live in known subnets |
| `system` | *(empty)* | All proxied traffic not matched by a more specific rule |
| `control` | *(empty)* | ghp's own control-plane traffic: OAuth login flows and token refresh, App installation token minting, username resolution lookups. Set `include_non_github: true` on the rule to also cover control calls to non-GitHub hosts (release redirect HEAD probes), which otherwise go direct |

### Layering

Selection is most-specific-first. The first layer with a matching rule wins:

1. **Token-specific** rules
2. **App-aligned** rules
3. **Net (CIDR)** rules — when multiple CIDRs match, the longest prefix wins
4. **System-wide** rules
5. **None** — fall back to the ambient environment (`HTTPS_PROXY` et al.)

Token and app rules only apply on paths where ghp resolves the client token
(the API proxy and git smart-HTTP passthrough). Traffic carrying raw GitHub
credentials or no credentials is still covered by net and system rules.

**Control traffic is layered separately.** ghp's own outbound calls are some
of the most important traffic it emits — losing OAuth refresh or installation
token minting to a banned egress IP takes down every client behind the proxy.
Control traffic resolves `control` rule → `system` rule → ambient; token,
app, and net layers never apply to it (it is not attributable to a client).
A dedicated control ruleset lets you pin this traffic to its own tightly
controlled egress path, isolated from the heavy proxied load:

```json
{
  "name": "control-plane",
  "algorithm": "round_robin",
  "proxies": [{"url": "http://egress-quiet.internal:3128"}],
  "rules": [{"type": "control"}]
}
```

**Non-GitHub control destinations go direct by default.** Release redirect
HEAD probes target your configured redirect mirror, not GitHub — and mirrors
are typically internal, so those probes are sent with no forward proxy at all
(not even the ambient environment). To give non-GitHub control calls the same
treatment as GitHub-destined control traffic, set `include_non_github` on the
control rule:

```json
{"rules": [{"type": "control", "include_non_github": true}]}
```

### Routing algorithms

| Algorithm | Behaviour |
|---|---|
| `round_robin` | Cycle through targets in order — simple even spread |
| `weighted` | Random pick proportional to weight — e.g. run 80/20 so a blocked egress never burns both paths simultaneously |
| `sticky` | Hash the client source IP onto the (weighted) target list, keeping each client's load on one path |

Weights default to 1 and are ignored by `round_robin`.

## Managing rulesets

All endpoints require an admin session.

```
GET    /api/forward-proxy-rulesets        # list
POST   /api/forward-proxy-rulesets        # create
GET    /api/forward-proxy-rulesets/{id}   # fetch
PATCH  /api/forward-proxy-rulesets/{id}   # partial update
DELETE /api/forward-proxy-rulesets/{id}   # delete
```

Create a weighted CI egress split for a runner subnet:

```bash
curl -X POST https://ghp.example.com/api/forward-proxy-rulesets \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-egress",
    "description": "CI runners split 80/20 across egress proxies",
    "algorithm": "weighted",
    "proxies": [
      {"url": "http://egress-a.internal:3128", "weight": 80},
      {"url": "http://egress-b.internal:3128", "weight": 20}
    ],
    "rules": [
      {"type": "net", "value": "10.42.0.0/16"}
    ]
  }'
```

`PATCH` uses partial-update semantics: omitted fields are untouched; pass
`"rules": []` to clear the rule list, `"enabled": false` to park a ruleset
without deleting it.

### Validation

- `name` — unique; alphanumerics, dots, hyphens, underscores (max 128 chars).
- `algorithm` — `round_robin`, `weighted`, or `sticky`.
- `proxies` — 1–32 targets; `http`/`https`/`socks5`/`socks5h` URLs (userinfo
  credentials allowed, query strings and fragments rejected); weight 0–10000
  (0 normalizes to 1).
- `rules` — up to 128; `app`/`token` values must be well-formed UUIDs, `net`
  values valid CIDRs, `system` and `control` rules carry no value.

## Per-request client selection

Sometimes a client knows something the operator's rules can't express — a
team with its own egress path (IP allow-listing on the far side, say) that
only needs it on particular requests. With the feature enabled, a client may
select the forward proxy for a single request via headers:

| Header | Accepted schemes |
|---|---|
| `X-GitHub-Proxy-Forward-HTTP` / `X-GitHub-Proxy-Forward-HTTPS` | `http`, `https` |
| `X-GitHub-Proxy-Forward-SOCKS` | `socks5`, `socks5h` |

```bash
curl -H "Authorization: Bearer ghx_..." \
  -H "X-GitHub-Proxy-Forward-HTTPS: http://team-egress.internal:3128" \
  https://ghp.example.com/api/v3/user
```

Rules of engagement:

- **Off by default.** Honouring the headers lets a client direct ghp to
  open connections to an arbitrary proxy endpoint, so the feature is gated
  behind `forward_proxy.allow_request_header: true`
  (`GHP_FORWARD_PROXY_ALLOW_REQUEST_HEADER`). When disabled, the headers
  are stripped and ignored.
- **Authenticated requests only.** The header is honoured only after a
  ghx_/gha_ token has been resolved for the request; anonymous traffic and
  raw GitHub credentials on the passthrough path fall through to normal
  ruleset selection. This keeps every client-directed egress attributable
  to a token identity and closes the unauthenticated SSRF vector.
- A client-specified proxy **beats every ruleset layer** — the request still
  flows through ghp, so token scoping, audit logging, and metrics all apply
  as usual.
- At most one proxy may be specified per request; conflicting headers or
  invalid values are rejected with 400. Credentials in the proxy URL
  (`http://user:pass@host:port`) are allowed; query strings and fragments
  are not.
- The headers are always stripped before the request is forwarded upstream —
  they never reach GitHub.
- Each use is counted in
  `ghp_forward_proxy_client_specified_total{scheme, token_type}` and shows
  as `layer="header"` in `ghp_forward_proxy_select_total`. The proxy URL is
  deliberately never used as a metric label (client-controlled, unbounded).

## Behaviour and failure modes

- **Fail-open to ambient.** A disabled ruleset, an invalid proxy URL, a
  malformed CIDR, or a route-table load failure never blocks egress: affected
  rules are skipped with a warning and unmatched traffic uses the environment
  default.
- **Conflicts resolve deterministically.** When two rulesets bind the same
  token, app, or the system layer, the first by name wins and a warning is
  logged.
- **Connection pooling is preserved.** All outbound GitHub backends (API
  proxy, github.com passthrough, codeload, Copilot) share one transport;
  Go's HTTP transport pools connections per selected proxy.
- **Client IP attribution** honours `server.client_ip_header`, the same
  setting used for metrics and access logs. If ghp sits behind a load
  balancer, configure it so `net` and `sticky` see real client addresses.

## Observability

- `ghp_forward_proxy_select_total{ruleset, layer}` — routing decisions
  (`layer` ∈ `header`, `token`, `app`, `net`, `system`, `control`,
  `ambient`, `direct`); `ambient` counts requests that fell through to the
  environment, `direct` counts non-GitHub control calls sent with no proxy.
- `ghp_forward_proxy_client_specified_total{scheme, token_type}` — requests
  routed through a client-specified proxy header.
- `ghp_forward_proxy_rulesets_active` — enabled rulesets currently compiled
  into the route table.
- `ghp_proxy_decision_duration_seconds{stage="forward_proxy_selection"}` —
  selection overhead per request.

## Known limitations

- Round-robin counters and sticky hashing are per-instance: in HA
  deployments each instance cycles independently, and rule changes made on
  one instance take up to a minute to reach the others.
- Token- and app-layer rules require ghp to resolve the client token, so they
  do not apply to passthrough traffic bearing raw GitHub credentials — use
  `net` rules for that traffic.
- Admin-UI convenience lookups that list installations/repositories through
  the GitHub SDK use the ambient environment; the request-path control calls
  (token minting, OAuth exchange/refresh, username resolution) all follow
  control-layer routing, and release HEAD probes follow it only with
  `include_non_github`.
- `token` and `app` rule values are stored as opaque references: deleting
  the referenced token or app leaves the rule in place, silently matching
  nothing. Prune stale rules when retiring tokens or apps.
- On the Vault backend, ruleset create/rename name-uniqueness is
  check-then-write without compare-and-set: concurrent creates of the same
  name can race. Ruleset administration is a low-frequency operator action,
  so this is accepted; SQL backends enforce uniqueness with a database
  constraint.
