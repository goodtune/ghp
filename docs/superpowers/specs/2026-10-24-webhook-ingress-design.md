# GitHub Webhook Ingress with Embedded NATS JetStream and ngrok

**Date:** 2026-10-24
**Status:** Implemented on `feat/webhook-ingress`

## Intent

ghp already holds the credentials for every GitHub App an operator has
registered. Agents that work through ghp have no way to *react* to GitHub
events (a review comment, a CI failure, a new issue) other than polling the
API through the proxy. This feature makes ghp the single receiving point for
GitHub webhooks across all installed apps and fans the payloads out to any
number of subscribers, durably, with replay.

Two embedded services make that possible without new infrastructure:

- **NATS JetStream**, run in-process, is the durable, replayable event log.
- **ngrok** (via `ngrok-go`), optionally run in-process, gives a self-hosted
  ghp instance behind NAT a public HTTPS endpoint GitHub can reach.

Both are optional and off by default. ghp remains a single static binary.

## Goals

- Receive every webhook format GitHub can send (JSON and form-encoded bodies,
  every event type, ping, app/installation lifecycle, repository and
  organisation hooks) at one ingress path.
- Verify `X-Hub-Signature-256` against the secret of the app the delivery
  targets. Unverifiable deliveries are rejected; nothing unsigned is ever
  published.
- Publish each delivery to a JetStream stream with a subject hierarchy that
  subscribers can filter by app, event, action, owner and repository.
- Deduplicate GitHub redeliveries by delivery GUID.
- Let subscribers consume via native NATS clients (optional TCP listener),
  via an authenticated server-sent-events stream on the admin API, and via
  the `ghp webhooks tail` CLI.
- Expose the public ingress URL (ngrok or configured base URL) so operators
  can paste it into the GitHub App settings.
- Instrument every decision (signature result, app resolution, publish
  latency, tunnel state, stream size).

## Non-goals

- Transforming or enriching payloads. The stored body is GitHub's JSON,
  byte-for-byte (form-encoded deliveries are unwrapped to the JSON inside
  the `payload` parameter).
- Per-token scoping of the subscriber stream. Subscribing is an admin
  capability in this release; scoping webhook visibility to `ghx_`/`gha_`
  token repositories is future work.
- Clustered JetStream. One ghp instance owns the stream. HA deployments
  should point ngrok/GitHub at one instance or front an external NATS
  cluster (not covered here).
- Registering webhooks on GitHub on the operator's behalf.

## Anti-goals

- Exposing anything other than the webhook path through the ngrok tunnel.
  The tunnel serves a dedicated mux with only `POST {path}`.
- Accepting a delivery with a missing or SHA-1-only signature, or one that
  matches no configured secret, even in dev mode.
- Hot-reloading infrastructure settings. The webhook section is bound at
  startup like `server` and `database`.

## Design

### Configuration (`webhooks:` section)

```yaml
webhooks:
  enabled: false
  path: /webhooks/github         # ingress path on the management host
  secret: ""                     # optional global fallback secret
  max_payload_bytes: 26214400    # 25 MiB (GitHub's maximum)
  nats:
    listen: ""                   # host:port for native NATS clients; empty = in-process only
    auth_token: ""               # required by clients when listen is set (recommended)
    tls: false                   # reuse the tls.certificates for the NATS listener
    store_dir: nats              # JetStream file store
    stream: GITHUB_WEBHOOKS
    subject_prefix: github.webhooks
    max_age: 168h
    max_bytes: 1073741824
    dedupe_window: 10m
  ngrok:
    enabled: false
    authtoken: ""                # or NGROK_AUTHTOKEN
    domain: ""                   # reserved ngrok domain; empty = random
```

Environment variables follow the existing scheme with two nested prefixes:
`GHP_WEBHOOKS_NATS_*` and `GHP_WEBHOOKS_NGROK_*`.

### App model

`apps` gains `webhook_secret TEXT NOT NULL DEFAULT ''` (migration 012, both
backends). The value is encrypted with the same encryptor as `client_secret`.
The admin API accepts `webhook_secret` on create and update; responses carry
`has_webhook_secret` and never the value.

### Ingress handler (`internal/webhook`)

1. `POST` only, body capped at `max_payload_bytes`.
2. Read `X-GitHub-Delivery`, `X-GitHub-Event`, `X-Hub-Signature-256`,
   `X-GitHub-Hook-ID`, `X-GitHub-Hook-Installation-Target-Type/ID`.
3. Candidate secrets, in order: the app whose GitHub App ID matches the
   installation target (when the target type is `integration`); the global
   `webhooks.secret`; then, for non-integration targets, every app with a
   secret. The first HMAC match wins. No match → 401.
4. Unwrap `application/x-www-form-urlencoded` bodies (`payload=`).
5. Extract `action`, `repository.owner.login`, `repository.name`,
   `installation.id`, `sender.login` with a minimal decoder; failures leave
   the fields empty but do not reject.
6. Publish to `{prefix}.{app_record_id|_}.{event}.{action|_}.{owner|_}.{repo|_}`
   with `Nats-Msg-Id = delivery GUID` and descriptive headers
   (`GitHub-*`, `GHP-*`).
7. Respond `202` with `{delivery, stream, sequence, duplicate, subject}`;
   `503` if the publish fails so the operator can redeliver from GitHub.

Subject tokens are sanitised to `[A-Za-z0-9_-]`; anything else becomes `_`.

### Embedded NATS (`internal/webhook/bus.go`)

`server.NewServer` with `JetStream: true`, `StoreDir`, `MaxPayload`, and
either `DontListen: true` or the configured host/port, optional token auth
and TLS. ghp connects in-process (`nats.InProcessServer`). The stream is
created or updated at startup with limits retention, file storage, the
configured age/bytes limits and dedupe window.

### ngrok (`internal/webhook/ngrok.go`)

`ngrok.NewAgent(WithAuthtoken, WithLogger, WithEventHandler)` then
`agent.Listen(ctx, WithURL(https://domain))`. An `http.Server` serving the
webhook-only mux runs on the returned listener. Connect/disconnect events
drive the `ghp_webhook_ngrok_tunnel_up` gauge. The endpoint URL is logged and
exposed via the status API.

### Subscriber surfaces

- Native NATS clients on `webhooks.nats.listen` (durable consumers, full
  JetStream semantics).
- `GET /api/webhooks/stream` (admin): server-sent events. Query parameters:
  `filter` (subject filter, default `{prefix}.>`), `from` (`new`, `all`, or
  a sequence number), `durable` (named pull consumer with explicit ack after
  the event is flushed; omit for an ephemeral ordered consumer).
  `Last-Event-ID` resumes after a sequence.
- `GET /api/webhooks/status`, `GET /api/webhooks/deliveries?limit=N`,
  `GET /api/webhooks/deliveries/{seq}` (admin).
- `ghp webhooks status|tail` CLI commands over the SSE endpoint.
- Admin web UI: webhook secret field on the app form, a webhook column in
  the apps table, and a Webhooks panel (public URL, stream statistics,
  recent deliveries) shown only when the feature is enabled.

### Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `ghp_webhook_received_total` | `event`, `result` | `published`, `duplicate`, `invalid_signature`, `unknown_app`, `bad_request`, `publish_error` |
| `ghp_webhook_publish_duration_seconds` | — | JetStream publish + ack latency |
| `ghp_webhook_ngrok_tunnel_up` | — | 1 while the ngrok agent session is connected |
| `ghp_webhook_stream_messages` / `ghp_webhook_stream_bytes` | — | Current stream size, refreshed every 30 s |
| `ghp_webhook_subscribers_active` | `kind` | Open SSE subscriptions (`sse`) and native NATS clients (`nats`) |

## Decisions left to the builder

- Exact SSE envelope field names (kept stable and documented in
  `docs/features/webhooks.md`).
- Cache TTL for app secrets (30 s, invalidated on app mutations through the
  admin API).

## Known limitations

- Signature verification requires SHA-256; GitHub's legacy `X-Hub-Signature`
  (SHA-1) alone is rejected.
- The NATS listener has no per-subject authorisation: anyone holding the
  auth token can read the whole stream. Bind it to a private interface.
- Stream state is local to one instance.
