# ghp webhooks

Inspect the server's GitHub webhook ingress and subscribe to stored
deliveries. Both subcommands need an admin session (`ghp auth login`) and a
server with `webhooks.enabled` set. See [Webhooks](../features/webhooks.md).

## Subcommands

### ghp webhooks status

    ghp webhooks status [--json]

Prints the ingress URL to register with GitHub, the ngrok tunnel state, the
NATS listener (if any), stream statistics, and which apps have a webhook
secret. `--json` prints the raw `GET /api/webhooks/status` response.

### ghp webhooks tail

    ghp webhooks tail [flags]

Streams deliveries over the admin server-sent-events endpoint and prints one
line per delivery:

    2026-10-24T10:15:02+11:00 seq=42 pull_request/opened  goodtune/ghp  app=Review Bot sender=octocat delivery=7c1d…

| Flag | Description |
|------|-------------|
| `--filter` | NATS subject filter under the server's prefix, e.g. `github.webhooks.*.pull_request.>` (default: everything) |
| `--from` | `new` (default), `all` to replay everything retained, or a stream sequence number |
| `--durable NAME` | Named server-side consumer; a restarted tail with the same name resumes after the last delivery it printed |
| `--json` | Print the full delivery envelope (metadata, headers, payload) as one JSON object per line |
| `--payload` | Print only the GitHub payload JSON per delivery |
| `--count N` | Exit after N deliveries (default 0: run until interrupted); with `--relay`, after N successful relays |
| `--relay URL` | POST each delivery to `URL` exactly as GitHub sent it (see below). Requires `--durable`; cannot be combined with `--json` or `--payload` |
| `--relay-timeout` | Timeout for each relay attempt (default `10s`, GitHub's own receiver timeout) |

The connection is retried on network errors, resuming after the last
sequence seen. Examples:

    # Every pull request event, as JSON lines for jq
    ghp webhooks tail --filter 'github.webhooks.*.pull_request.>' --json | jq -r '.payload.pull_request.html_url'

    # Replay everything retained for one app
    ghp webhooks tail --from all --filter 'github.webhooks.<app-record-id>.>'

    # A worker that must not miss deliveries across restarts
    ghp webhooks tail --durable review-agent --payload | my-agent

## Relaying to a receiver

    ghp webhooks tail --durable skipper --relay http://127.0.0.1:3000/github/webhook

`--relay` replays each delivery to an existing GitHub webhook receiver as if
GitHub had sent it directly:

- **Body:** the exact bytes GitHub signed (fetched with the stream's
  `raw=1` option).
- **Headers:** `X-GitHub-Event`, `X-GitHub-Delivery`, `X-GitHub-Hook-ID`,
  `X-GitHub-Hook-Installation-Target-Type`, `X-GitHub-Hook-Installation-Target-ID`,
  `X-Hub-Signature-256`, `X-Hub-Signature` (when GitHub sent it), and
  GitHub's original `Content-Type` and `User-Agent`.
- **Nothing of ghp's:** the target never receives your ghp session token or
  any cookie. Redirects are not followed.

Configure the receiver with the GitHub App's webhook secret: the signature
is GitHub's own.

`URL` must be an `http` or `https` URL with a host and no userinfo or
fragment. Any host is accepted, including loopback and private addresses:
the relay runs on the machine where you run the command. If the URL has a
query string (for example a receiver token), the relay prints it as
`?REDACTED` in every log line and error.

**Delivery guarantee.** The relay uses the stream's client-acknowledgement
mode on the `--durable` consumer. A delivery is acknowledged only after the
target answers 2xx. Any other status, a redirect, a timeout or a connection
error is retried with exponential backoff (1 s doubling to 60 s, with
jitter) until it succeeds, so nothing is lost while the receiver restarts.
A target that keeps rejecting stalls the relay by design: later deliveries
wait behind it. On Ctrl-C the relay stops at once; the in-flight delivery
stays unacknowledged and is redelivered when a relay with the same
`--durable` name starts again. Delivery is at-least-once, so a receiver
should deduplicate on `X-GitHub-Delivery`.

If the target accepts a delivery but the acknowledgement to ghp fails
(network error or a 5xx), the relay retries the acknowledgement a few times
with a short backoff. If it still fails, or ghp no longer knows the stream
session (404), the relay drops the stream and reconnects. ghp then
redelivers the delivery, and the target receives it again. Some answers are
not retried, and the relay keeps reading the stream:

- a 409 with `"code": "acked"`: ghp already recorded the acknowledgement
  (only the answer was lost). The relay counts the delivery as relayed.
- a 409 with `"code": "released"`, or a 502 with `"code": "ack_error"`:
  ghp did not record the acknowledgement and returned the delivery to the
  durable. The relay does not count it, prints that the server will
  redeliver it, and the target receives it again.

Before each stream connection, including every reconnect, the relay checks
that the server supports client acknowledgement. It sends an invalid
acknowledgement, which a current server answers with 400 and the header
`GHP-Webhook-Client-Ack: 1`; each check counts once as `bad_request` in
`ghp_webhook_stream_ack_total`. A 400, 404 or 405 without that header (an
older server, or a proxy in front of one) stops the relay with an "upgrade
the server" error. The stream response must carry the same header too; if
it does not, the relay closes the stream before it reads an event and stops
with the same error. An older server acknowledges deliveries on the durable
as soon as it sends them, so the relay must never read from one, also not
after the server is downgraded while the relay runs.

If the relay receives a delivery event it cannot decode (or one without a
sequence number), it prints the event ID to stderr and drops the stream.
The server returns the pending delivery to the durable, and the relay
reconnects. It never skips such an event silently.

The stream connection is retried on network errors and on 5xx or 429
answers, with backoff from 2 s to 30 s. Other 4xx answers (for example a
bad `--filter`) stop the relay. A stream that sends nothing for 45 seconds
is treated as dead and reconnected; the server pings every 15 seconds. The
relay sizes its reader from the server's `max_payload_bytes`, so it reads
the largest delivery the server accepts. If the server's status cannot be
read at startup, the relay retries a few times and then prints a warning and
assumes 25 MiB. If an event is still too large, the relay reads the status
again: when the server now allows more, the relay reconnects with a larger
reader; otherwise it stops with an error naming the sequence and delivery.

`--durable` is required rather than defaulted so that the consumer's name
(and therefore its position) is always chosen explicitly. As with any
durable, `--filter` and `--from` take effect only when the consumer is
first created; use a new name to change them.

**Do not share the durable.** Run one relay per durable name. A second
relay with the same name takes over: the first relay stops with "durable
NAME was taken over by another relay (opened by LOGIN)", where LOGIN is the
GitHub login of the admin who started the second relay, and does not
reconnect. Durable names are not kept per user: any admin can take over
another admin's relay by reusing its name, and the evicted relay names
who did. A delivery the first relay was posting at that moment can reach
the target twice. Under a supervisor that restarts the relay (for example
systemd `Restart=always`), two relays on one durable do not settle: each
restart takes the durable back, so they alternate at the restart interval.
Stop one of them, or give it a different `--durable` name. Do not use the
name for a plain `ghp webhooks tail --durable` or a native NATS consumer: it
would take deliveries away from the relay.

**Retention limits the guarantee.** The relay loses nothing that is still
in the stream, but the stream does not keep deliveries forever:

- `webhooks.nats.max_age` (default 168h) and `webhooks.nats.max_bytes`
  (default 1 GiB) discard the oldest deliveries, also ones that a stalled
  or stopped relay has not yet relayed.
- A durable that has no subscriber for 7 days is deleted. A relay started
  later with the same name creates a new durable at its `--from` position
  (default `new`), so it silently skips the backlog.

Keep relays running under a supervisor and alert when one stalls (the
`retrying` lines on stderr, or `ghp_webhook_stream_messages` growing). Set
`max_age` and `max_bytes` to cover the longest outage you must survive. To
restart a relay after its durable may have expired, start it with
`--from SEQ` (the sequence after the last `relayed` line) or `--from all`;
the receiver deduplicates on `X-GitHub-Delivery`.

**Skipped deliveries.** Two kinds of delivery cannot be replayed with a
valid signature. The relay prints a warning naming the delivery and
acknowledges it so the stream moves on:

- deliveries stored before ghp kept the original signature headers;
- form-encoded deliveries: ghp stores the unwrapped JSON payload, not the
  signed form body. GitHub App webhooks are always JSON.

Each outcome is one line on stderr:

    relaying webhook deliveries to http://127.0.0.1:3000/github/webhook (durable skipper)
    retrying seq=12 delivery=7c1d…: status 500 (attempt 1); next attempt in 712ms
    relayed seq=12 delivery=7c1d… event=pull_request: status 200 after 2 attempt(s)
    skipped seq=13 delivery=9e2a… event=push: no stored signature (delivery stored before ghp kept signatures)
