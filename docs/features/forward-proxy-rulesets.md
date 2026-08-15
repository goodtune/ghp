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
  values valid CIDRs, `system` rules carry no value.

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

- `ghp_forward_proxy_select_total{ruleset, layer}` — routing decisions;
  `layer="ambient"` counts requests that fell through to the environment.
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
- Internal calls that are not tied to a proxied request (OAuth token refresh,
  GitHub App installation token minting, release redirect HEAD checks) use
  the ambient environment.
