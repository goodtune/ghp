# Webhook Ingress: Multi-Instance and Multi-Region Operation

**Date:** 2026-10-25
**Status:** Proposed (deferred; to be implemented after `feat/webhook-ingress` merges)
**Builds on:** [2026-10-24 Webhook Ingress design](2026-10-24-webhook-ingress-design.md)

## Intent

The webhook ingress shipped in `feat/webhook-ingress` assumes one ghp
process: one embedded NATS server with a local file store, one ngrok agent,
one secret cache. A fleet of ghp instances behind a load balancer (the
normal shape for a regional Kubernetes deployment) partly works by accident
and partly breaks:

- Each instance stores the deliveries it happened to receive. Subscribers
  on another instance never see them and the deliveries API shows a
  different history per instance.
- GitHub redeliveries routed to a different instance are stored twice,
  because JetStream deduplicates per stream and each instance has its own.
- Durable consumers do not follow the client. An SSE subscriber that
  reconnects through the load balancer to another instance starts over.
- Every instance starts its own ngrok agent. With a reserved domain the
  second agent is rejected and retries forever; without one there are N
  public URLs and GitHub can be told about only one.
- Rotating an app's webhook secret on one instance is seen by the others
  only after the 30 s cache expiry.

This document describes how a set of ghp instances learns about each other,
shares one durable delivery log, keeps GitHub's single webhook URL
reachable while instances come and go, and extends across regions joined by
WAN links.

The deployment this is designed for: ghp runs inside a corporate network
with no inbound internet path. GitHub reaches it only through ngrok. Admin
users, subscribers and the GitHub API egress path are on the corporate
network.

## Goals

- Any instance can receive a delivery; every instance can serve it. One
  logical delivery stream per region, replicated across instances, so that
  dedupe, replay, the deliveries API and durable consumers behave
  identically regardless of which instance a client reaches.
- GitHub's single webhook URL keeps working while instances are added,
  removed, rescheduled or rolled. Failover must not depend on an operator
  copying a new URL into GitHub.
- An instance that cannot store a delivery must stop receiving deliveries,
  because GitHub does not retry failed deliveries on its own.
- Regions connected by WAN links each keep working during a partition,
  with each region's subscribers seeing every region's deliveries once
  connectivity is restored.
- Secret rotations and app changes take effect on every instance within
  a second, not after a cache timeout.
- Instances discover each other from configuration that is natural in
  Kubernetes (stable pod names, a headless Service) and workable on
  plain hosts (a static seed list).
- No new infrastructure. Coordination uses the embedded NATS and ngrok that
  the feature already depends on. ghp stays a single static binary.
- The single-instance configuration from the first design keeps working
  unchanged.

## Non-goals

- A general leader-election primitive for arbitrary singleton jobs. With
  endpoint pooling nothing in the ingress needs a singleton. JetStream's
  own RAFT elects stream and meta leaders internally; the operator never
  sees or manages that. If a true singleton job appears later, a JetStream
  KV lease (per-key TTL, create-if-absent, revision-checked refresh) is the
  intended pattern. It is not built here.
- Exactly-once delivery across regions beyond the dedupe window. Within
  a region dedupe is exact. Across regions a redelivery is also collapsed,
  but only when both copies reach a region's aggregate within its dedupe
  window; outside it delivery is at-least-once and the delivery GUID is
  the consumer's dedupe key.
- A stretched NATS cluster spanning a WAN. NATS advises against it and the
  write latency would be paid by every delivery. Regions are separate
  clusters joined by gateways.
- Subscriber session migration between regions. A subscriber pins to a
  region; its durable consumer and sequence numbers are regional.
- Managed Kubernetes manifests or a Helm chart. An example StatefulSet is
  documented; packaging it is separate work.
- Hot-reload of cluster membership. Routes, gateways and pooling are bound
  at startup. NATS gossip handles peers that appear after start.

## Anti-goals

- Split-brain ingestion: two instances both believing they own the only
  copy of a delivery, so that a later reconciliation has to pick one.
  Replication is synchronous within a region (RAFT quorum) so this cannot
  occur there, and cross-region copies are explicit sources, never merges.
- Silent data loss on reschedule. A pod rescheduled onto a fresh disk must
  rejoin and catch up from its peers, never start an empty stream that
  masks the loss.
- Accepting a delivery (202) that was not durably stored on a quorum.
- Tying ghp to Kubernetes APIs. The design works on plain hosts; Kubernetes
  just makes the configuration mechanical.

## Topologies

Three shapes, each a superset of the previous. All three use the same
code paths; the first two differ only by configuration.

| Shape | NATS | Stream layout | ngrok |
|---|---|---|---|
| **Single instance** (today) | one embedded server, `DontListen` or local listener | `GITHUB_WEBHOOKS`, R1 | one agent, reserved or random URL |
| **Regional cluster** | N embedded servers in one NATS cluster (routes, full mesh) | `GITHUB_WEBHOOKS_INGRESS` (writes, R3) and `GITHUB_WEBHOOKS` (aggregate sourcing it, R3) | one agent per instance, all pooled on the same reserved URL |
| **Multi-region** | one cluster per region, clusters joined by gateways, one JetStream domain per region | as the regional cluster; each region's aggregate additionally sources every other region's ingress stream | as above; the pool spans regions |

The two-stream layout is used whenever `cluster.enabled` is true, not only
when gateways are configured. nats-server refuses two streams with
overlapping subjects, so converting a single-stream cluster to the
two-stream layout later would mean dropping the aggregate's subjects
before the ingress stream can exist, with a gap in which publishes have
no stream and GitHub (which does not retry) loses deliveries. Adopting the
layout at the single-instance to cluster boundary, where a store
migration is already required, means adding a region later is only adding
sources to an existing aggregate.

## Design

### Ingress fan-in: ngrok endpoint pooling

Every instance runs its own ngrok agent session and listens on the **same**
reserved URL with `ngrok.WithPoolingEnabled(true)`. ngrok's edge
load-balances incoming requests across all agents in the pool and removes
an agent the moment its session drops. This replaces leader election for
the tunnel:

- Failover is ngrok's session timeout, not a lease TTL plus a reconnect.
- There is nothing to fence. ngrok refuses a non-pooled endpoint on a URL
  that already has a pooled one and vice versa, so a misconfigured instance
  fails loudly at `Listen` rather than stealing traffic.
- Adding capacity is starting another instance.

Consequences the design accepts:

- Pooling requires a fixed URL. `webhooks.ngrok.domain` becomes mandatory
  when `webhooks.ngrok.pooling` is true. A random URL per agent cannot be
  pooled.
- All instances share one ngrok authtoken and one account.
- ngrok's balancing strategy is ngrok's. Treat it as arbitrary: a GitHub
  redelivery can land in a different region from the original. This is
  why cross-region dedupe relies on the aggregate's dedupe window rather
  than on the ingress stream alone.
- Each pooled agent is a separate outbound session. In a corporate network
  that egress normally goes through a proxy. `webhooks.ngrok.proxy_url`
  is passed to `ngrok.WithProxyURL`. When unset, the builder should reuse
  ghp's `forward_proxy` system-layer proxy if one is configured, and
  otherwise fall back to the standard `HTTPS_PROXY` environment variables.

**Pool membership follows readiness.** An instance opens its ngrok listener
only once its JetStream view is current and the streams exist, and closes
the listener (leaving the pool) when it has been unready for more than a
short grace period (default 5 s). It rejoins after it has been continuously
ready for the same period, so a brief RAFT leader change does not churn
the pool. Only the listener closes; the agent session stays connected so
that rejoining is a single `Listen` call rather than a new session
handshake through the corporate proxy. `ghp_webhook_ngrok_tunnel_up` thus
means "session connected" and `ghp_webhook_ngrok_pool_member` means
"listening in the pool". The existing `Tunnel` type couples the two and
needs splitting. While out of the pool the instance still serves the
ingress path on the management host for health checks and local testing,
answering 503 if its local JetStream is not current.
This matters because GitHub does not retry: a 503 from an instance that
has lost quorum is a lost delivery until an operator redelivers it. Keeping
such an instance out of the pool means GitHub's request goes to one that
can store it.

**Shutdown order.** On SIGTERM: close the ngrok listener first (ngrok drops
the agent from the pool), drain in-flight HTTP requests, then close the
NATS connection and server. The existing 15 s tunnel wait and the HTTP
server's graceful shutdown already provide the hooks; only the order
changes. Kubernetes deployments should set `terminationGracePeriodSeconds`
to at least 30.

### Regional cluster: embedded NATS routes

The embedded server gains cluster options. With `webhooks.nats.cluster`
enabled, each instance:

- Has a stable, unique `server_name` (default: the OS hostname, which is
  the pod name in Kubernetes) and a shared `cluster.name`.
- Listens for routes on `cluster.listen` (conventionally port 6222) and
  solicits routes to the configured seeds. NATS routes are a full mesh and
  a server that reaches any one peer learns the rest by gossip, so the
  seed list need not be complete. Routes authenticate with a shared
  username and password and may use mutual TLS: the instance presents the
  top-level `tls` certificate and verifies peers against `cluster.tls_ca`.
  Gateways use the same scheme with `gateway.tls_ca`, and there mutual TLS
  is mandatory, because `reject_unknown` only limits which cluster names
  are accepted and a WAN peer must prove its identity, not just its name.
- May name a headless Service as a single seed route. nats-server
  resolves a route hostname on every connect attempt and picks one of the
  returned addresses at random (`server/route.go`, `routeResolver`), and
  gossip then discovers the remaining peers, so no separate DNS discovery
  mechanism is needed. Listing every ordinal explicitly also works and
  makes bring-up slightly faster.
- Runs JetStream clustered. The meta layer and each stream are RAFT groups
  across the instances. `webhooks.nats.cluster.replicas` (default 3) sets
  the stream's replica count.

Startup waits for the JetStream meta layer to report current
(`Server.JetStreamIsCurrent()`, which also returns true in standalone
mode, or `Healthz` with JetStream checks) before calling
`CreateOrUpdateStream`. Creating an R3 stream on a cluster that does not
yet have three members fails with the placement error "no suitable peers
for placement" (`JSClusterNoPeersErr`); the builder retries that error
code with backoff rather than failing the process, logging at warning
level, because in a rolling bring-up the peers are seconds away. All
instances call `CreateOrUpdateStream` with identical configuration; the
call is idempotent and concurrent callers are safe.

The store directory must be a per-instance persistent volume. A replica
that restarts with an empty directory rejoins its RAFT groups and catches
up from peers, which is correct but slow for a large stream; a replica
that restarts with its data is current almost immediately. Both work. What
does not work is two instances sharing one directory.

Scaling an existing single-instance stream from R1 to R3 is a supported
stream update. However, a store directory written by a **standalone**
(non-clustered) server cannot simply be reused by a clustered one. The
builder must verify nats-server 2.15 behaviour here; the conservative
operator path is to back up the stream (`nats stream backup`), start the
cluster with fresh directories, and restore. This is called out in the
upgrade docs as a one-time step.

### Multi-region: gateways, domains and sourcing

Regions are separate NATS clusters. Each has its own JetStream **domain**
(`JetStreamDomain` = the region's cluster name), so each region's meta
layer is independent: no RAFT vote ever crosses the WAN, and a region
with quorum stays fully writable when the WAN is down.

Clusters are joined by NATS **gateways** (`webhooks.nats.gateway`). Each
region advertises one reachable gateway address (conventionally port 7222)
and lists every other region's gateway URL. Gateways form a full mesh
between clusters and forward only subjects for which the remote side has
interest. Over a WAN, TLS is required and `reject_unknown_cluster` is on.

Stream layout per region (the same layout as a regional cluster, plus
remote sources):

- `GITHUB_WEBHOOKS_INGRESS` (name: `<stream>_INGRESS`) captures
  `<prefix>.>`, R3. The ingress handler publishes here, and the 202
  response's `stream` and `sequence` fields name this stream, so the
  number GitHub shows in its delivery log is unambiguous. Its dedupe
  window is `dedupe_window`; its retention is `ingress_max_age` (default
  72 h, sized to the longest WAN partition a region should be able to
  catch up from), bounded by the shared `max_bytes`.
- `GITHUB_WEBHOOKS` (name: `<stream>`) has no subjects of its own. It
  sources the local ingress stream and every remote region's ingress
  stream, the remote ones via `StreamSource{Domain: "<remote-domain>"}`
  (nats.go fills in the external API prefix). The configured `max_age`,
  `max_bytes` and `dedupe_window` apply to this stream, since it is the
  one subscribers and the retention promise are about. Sourced messages
  keep their subject and headers, so subject filters and the `GitHub-*` /
  `GHP-*` headers behave as before. Subscribers, the SSE endpoint, the
  deliveries API and the CLI all read from this stream, so nothing in the
  subscriber surface changes between the regional and multi-region
  shapes. `Last-Event-ID` and the deliveries API use this stream's
  sequence numbers, which differ from the ingress sequence in the 202
  response; the two are never compared.

Local deliveries are therefore stored twice per region, once in each
stream. Volume sizing is `max_bytes` plus the ingress stream's share, or
simply twice `max_bytes` as a safe upper bound.

Sourcing is pull-based and resumes from the last sequence it saw, so a WAN
partition simply pauses the remote source; the aggregate catches up when
the link returns. `StreamSourceInfo.Lag` exposes how far behind each
source is and is exported as a metric.

Sourced messages keep their `Nats-Msg-Id` header and the aggregate applies
its own dedupe window to them (nats-server strips only the
`Nats-Stream-Source` and expectation headers when ingesting a source, and
the message-ID check runs for sourced messages too). A redelivery that
reached region B when the original reached region A is therefore stored
once in every aggregate, provided both copies arrive within
`dedupe_window` of each other. Copies separated by more than the window,
for example by a long WAN partition, appear twice. Consumers that need
exactly-once beyond that dedupe on the `GitHub-Delivery` header, which
the SSE envelope already carries.

Remote regions are configured explicitly (`gateway.peers[].name` doubles as
the remote domain name) rather than discovered, because adding a region is
a deliberate network change and because the aggregate stream's source list
must be known to create it.

### Cross-instance cache invalidation

App create, update and delete publish an empty message on
`<prefix-root>.control.apps.changed` (for the default prefix
`github.webhooks` this is `github.control.apps.changed`; the builder picks
the exact subject, keeping it outside the delivery subject space so stream
and subscriber filters never see it). Every instance subscribes with a
plain core-NATS subscription and calls `StoreSecretSource.Invalidate()` on
receipt. Core NATS subjects cross routes and gateways by interest, so the
message reaches every region. The subject is denied to the `subscriber`
user; only the internal user may publish or subscribe to it. The 30 s TTL
remains as the backstop for a lost message.

### Readiness

ghp has no health endpoint today. This design adds two on the management
host, unauthenticated, suitable for Kubernetes probes:

- `GET /livez` returns 200 while the process is serving HTTP.
- `GET /readyz` returns 200 when the database is reachable and, if webhooks
  are enabled, the JetStream view is current and the subscriber stream
  exists. Otherwise 503 with a JSON body naming the failing check.

The verdict is computed by a background loop, once a second, from
in-process signals (`JetStreamIsCurrent`, a cached stream lookup, a
database ping no more often than every 5 s) and cached. `/readyz` returns
the cached verdict, so probing it is free and three consumers can poll it
without adding load: the Kubernetes readiness gate (so the service load
balancer stops sending subscribers and admin traffic to an instance
without quorum), ngrok pool membership as described above, and the
`ghp_webhook_ready` gauge.

### Subscriber surfaces

Unchanged in API shape. Because consumers are cluster-wide:

- SSE durable consumers survive reconnecting to any instance in the same
  region. `Last-Event-ID` resumes by stream sequence of the regional
  aggregate.
- The native NATS listener can sit behind the same load balancer.
  Clients connect to any instance; the `subscriber` user's permissions are
  cluster-wide.
- `GET /api/webhooks/status` gains a `cluster` object: cluster name,
  domain, this server's name, connected cluster peers by server name
  (distinct remote servers from `Routez`, not route connections, since
  nats-server opens a pool of connections per peer), gateway peers with
  connection state, JetStream current flag, stream replicas and the
  current stream leader, source lag per origin, and whether this instance
  is in the ngrok pool. `ghp webhooks status` renders it.

### Configuration

```yaml
webhooks:
  nats:
    cluster:
      enabled: true
      name: syd                     # shared by all instances in the region; doubles as the JetStream domain when gateways are enabled
      server_name: ""               # default: OS hostname (pod name)
      listen: "0.0.0.0:6222"
      advertise: ""                 # host:port peers should dial, when it differs from listen
      routes:                       # seeds, nats-route://host:6222; a headless Service name is enough
        - nats-route://ghp-hl.ghp.svc:6222
      username: ghp-route
      password: ${GHP_ROUTE_PASSWORD}
      tls: false                    # mutual TLS on routes using the top-level tls certificate
      tls_ca: ""                    # CA bundle peers are verified against; required when tls is true
      replicas: 3
    ingress_max_age: 72h            # retention of the per-region ingress stream (cluster mode only)
    gateway:
      enabled: false
      listen: "0.0.0.0:7222"
      advertise: "ghp-syd-gw.corp.example:7222"
      username: ghp-gateway
      password: ${GHP_GATEWAY_PASSWORD}
      tls: true                     # mutual TLS; required when enabled
      tls_ca: /etc/ghp/gateway-ca.pem
      reject_unknown: true
      peers:
        - name: iad                 # remote cluster name and JetStream domain
          urls: ["nats://ghp-iad-gw.corp.example:7222"]
  ngrok:
    enabled: true
    domain: hooks.example.ngrok.app # required when pooling is true
    pooling: true                   # default true
    proxy_url: ""                   # default: forward_proxy system layer, then HTTPS_PROXY
```

Environment variables follow the existing nesting:
`GHP_WEBHOOKS_NATS_CLUSTER_NAME`, `GHP_WEBHOOKS_NATS_CLUSTER_ROUTES`
(comma-separated), `GHP_WEBHOOKS_NATS_GATEWAY_PEERS` (comma-separated
`name=url` pairs), `GHP_WEBHOOKS_NGROK_POOLING`, and so on. The env mapper
in `internal/config` currently splits one nested level under `nats_` and
`ngrok_`; it needs a second level for `cluster_` and `gateway_`.

Validation at startup:

- `cluster.enabled` requires `name`, `listen`, credentials, and at least
  one route. `replicas` must be odd and between 1 and 5. `tls: true`
  requires `tls_ca`.
- `gateway.enabled` requires `cluster.enabled`, `advertise`, `tls: true`
  with `tls_ca`, credentials, and at least one peer. Peer names must be
  unique and differ from the local cluster name.
- `ngrok.pooling` requires `ngrok.domain`.
- `server_name` must be unique per instance; this cannot be validated
  statically, so a duplicate is surfaced by nats-server refusing the route
  and by a startup error after the first failed solicitation.

An external NATS deployment (`webhooks.nats.url`) is an escape hatch for
operators who already run NATS. It bypasses the embedded server and all
cluster options; ghp then only manages streams and consumers. It is
cheap to add once the bus code takes a connection rather than building
one, and is in scope here but not required for the Kubernetes story.

### Metrics

New, all tested in `internal/metrics/metrics_test.go` and documented in
`docs/admin/monitoring.md`:

- `ghp_webhook_ready` (gauge, 0/1): the `/readyz` verdict.
- `ghp_webhook_cluster_peers` (gauge): distinct connected cluster peers
  (servers, not route connections).
- `ghp_webhook_gateway_connected{peer}` (gauge, 0/1): per remote region.
- `ghp_webhook_jetstream_current` (gauge, 0/1).
- `ghp_webhook_source_lag_messages{origin}` (gauge): aggregate stream lag
  behind each origin region's ingress stream.
- `ghp_webhook_ngrok_pool_member` (gauge, 0/1): whether this instance's
  endpoint is currently listening in the pool. Summed across instances it
  is the pool size. `ghp_webhook_ngrok_tunnel_up` keeps meaning "agent
  session connected".

Changed: `ghp_webhook_stream_messages` and `ghp_webhook_stream_bytes` gain
a `stream` label (`ingress` or `aggregate`; single-region deployments only
emit `aggregate`).

### Kubernetes deployment shape

Documented as an example in `docs/admin/deployment.md`; not shipped as
manifests.

- A **StatefulSet**, not a Deployment: stable names for `server_name` and
  routes, and a PersistentVolumeClaim per pod for the JetStream store.
- `podManagementPolicy: Parallel`. With the default `OrderedReady`, pod 1
  waits for pod 0 to become ready, but pod 0's readiness requires a
  JetStream quorum that needs pod 1. Parallel avoids the deadlock.
- A headless Service for routes (6222); `routes` names it, or lists the
  ordinals. The client-facing Service fronts the
  management port and, if enabled, the native NATS port.
- Gateways need a per-region address reachable from the other regions over
  the corporate WAN: a LoadBalancer Service, a NodePort behind a VPN, or an
  internal ingress with TCP passthrough. `gateway.advertise` is that
  address.
- `readinessProbe` on `/readyz`, `livenessProbe` on `/livez`,
  `terminationGracePeriodSeconds: 30` or more, a PodDisruptionBudget with
  `minAvailable: 2` for R3, and pod anti-affinity across nodes (and zones
  where available).
- Egress: ngrok (`connect.ngrok-agent.com:443`, via the corporate proxy),
  GitHub API, the database, and 7222 between regions. No inbound internet
  path is needed anywhere.
- `GHP_WEBHOOKS_NATS_CLUSTER_SERVER_NAME` from the downward API
  (`metadata.name`) if the hostname is not the pod name in the image.

### Failure modes

| Event | Ingress | Stored deliveries | Subscribers |
|---|---|---|---|
| One of three instances dies | ngrok drops it from the pool within its session timeout; others keep receiving | R3 keeps quorum; no loss | SSE clients reconnect via the LB to another instance; durable state intact; `Last-Event-ID` resumes |
| Instance rescheduled to a new disk | Rejoins the pool once `/readyz` passes | Catches up from peers | Unaffected |
| Rolling restart | Pool shrinks by one at a time; each pod leaves the pool before draining | Quorum maintained with PDB `minAvailable: 2` | Brief reconnects |
| Region loses quorum (two of three instances) | Remaining instance leaves the pool; GitHub traffic goes to other regions | Nothing lost; writes blocked locally until quorum returns | Local subscribers see 503 from `/readyz`-gated LB; data served again on recovery |
| WAN partition between regions | Unaffected; each region ingests what ngrok sends it | Each region's ingress stream is complete for what it received | Aggregates lag for remote origins; catch up automatically |
| ngrok outage or egress proxy failure | No deliveries arrive; `ngrok_tunnel_up` and `ngrok_pool_member` drop to 0 on every instance | Unaffected | Unaffected |
| GitHub redelivery hits a different region | Accepted and stored in that region's ingress stream | Collapsed by each aggregate's dedupe window if both copies arrive within it; otherwise a duplicate | Dedupe on `GitHub-Delivery` if exactly-once matters beyond the window |
| Whole region down | Pool continues from other regions | That region's ingress stream is unavailable until it returns; its deliveries were already sourced by others up to the lag at failure | Other regions unaffected |

### Testing

- **Cluster tests** in `internal/webhook`: start three embedded servers in
  one test process on ephemeral loopback ports with routes between them,
  create the R3 stream, publish through one, consume through another,
  kill one, confirm publish and durable resume continue, restart it with
  an empty store and confirm catch-up. Table-driven over replica counts 1
  and 3.
- **Gateway tests**: two single-node clusters with different domains
  joined by a gateway over loopback; verify the aggregate sources the
  remote ingress stream, that subjects and headers survive, that a
  redelivery to both regions within the dedupe window appears once in
  each aggregate and one outside the window appears twice, and that
  source lag reports and clears across a simulated partition (close the
  gateway listener, publish, reopen).
- **Control subject**: an app update on one instance invalidates the cache
  on another.
- **Readiness**: `/readyz` is 503 before quorum and 200 after; the ngrok
  listener opens and closes with it (driven through the existing
  `TunnelOptions` seam with a fake agent).
- **Config**: env mapping for the new nested levels; every validation rule
  above has a negative test.
- **ngrok pooling cannot be exercised offline.** A unit test asserts the
  option is passed; a documented runbook verifies pooling manually with
  two local processes against a real reserved domain before release.
- CI's e2e job stays single-instance. A follow-up may add a three-replica
  kind cluster job once the manifests exist.

### Rollout

1. **Regional cluster**: cluster config, the two-stream layout with a
   local-only source, readiness endpoints, shutdown order, the
   agent/listener split in `Tunnel`, ngrok pooling with readiness-gated
   membership, new metrics, docs. This is the bulk of the value and is
   independently shippable.
2. **Control subject** for cache invalidation.
3. **Multi-region**: gateway config, domains, the two-stream layout and
   sourcing, source-lag metric, status API additions.
4. **Deployment docs**: StatefulSet example, upgrade note for existing
   single-instance stores, runbooks for adding a region and rotating route
   or gateway credentials.

## Alternatives considered

- **Leader-elected single tunnel** (one instance holds the ngrok endpoint;
  a JetStream KV lease picks it). Works, and ngrok's reserved-domain
  exclusivity makes a passable fence, but failover is lease TTL plus
  reconnect, the pool shape gives capacity as well as availability, and
  pooling needs no new coordination code. Rejected in favour of pooling.
- **One stretched NATS cluster across regions.** Every write would wait on
  a cross-WAN RAFT round trip and a WAN partition would stall the minority
  side entirely. Rejected; gateways with per-region domains instead.
- **Leafnodes to a central hub.** Simpler than gateways when a hub already
  exists, but introduces a hub as a dependency and an asymmetry between
  regions. Gateways are symmetric. Can be revisited if the corporate
  network already has a NATS hub.
- **Kubernetes Lease objects for coordination.** Ties ghp to Kubernetes
  and still leaves the data-sharing problem unsolved. Rejected.
- **External NATS only.** The cleanest HA story if an operator already runs
  NATS, but not the "embedded, no new infrastructure" goal. Supported as
  an escape hatch rather than the primary path.

## Decisions left to the builder

- Exact control subject name and whether it carries the app record ID (so
  a future per-app invalidation is possible) or stays empty.
- Route and gateway credential sourcing beyond config values (file,
  environment), matching whatever `tls` and `database` already do.
- Retry and backoff parameters for stream creation during cluster
  bring-up, and the unready grace period before leaving the ngrok pool.
- Verification of nats-server 2.15 behaviour when a standalone store
  directory is started in clustered mode, and the resulting wording of the
  upgrade note.
- Exact stream-creation sequencing on a fresh cluster: the ingress stream
  must exist before the aggregate that sources it, and both before the
  instance reports ready.

## Known limitations

- Cross-region dedupe holds only within the aggregate's dedupe window.
  Copies of a redelivery separated by longer than that (a long WAN
  partition) are stored twice. Consumers that need exactly-once dedupe on
  the delivery GUID.
- Subscribers pin to a region. Durable consumer names and `Last-Event-ID`
  sequences are per regional aggregate; a client that fails over between
  regions cannot resume by sequence. Resuming by delivery GUID is a
  possible future extension.
- Stream retention limits apply per stream. In multi-region each region's
  aggregate holds every region's deliveries, so `max_bytes` must be sized
  for the whole fleet, not the local share, and local deliveries are held
  twice (ingress and aggregate) for `ingress_max_age`.
- Moving an existing single-instance store into a cluster is a backup and
  restore step, not an in-place upgrade (pending builder verification).
- Pooling depends on an ngrok plan that includes endpoint pooling and on a
  reserved domain. Without either, the design degrades to today's
  behaviour: one instance holds the tunnel and the rest log a bind failure
  and retry.
- Cluster membership is bound at startup. Changing route credentials or
  adding a gateway peer is a rolling restart.
