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
| `--count N` | Exit after N deliveries (default 0: run until interrupted) |

The connection is retried on network errors, resuming after the last
sequence seen. Examples:

    # Every pull request event, as JSON lines for jq
    ghp webhooks tail --filter 'github.webhooks.*.pull_request.>' --json | jq -r '.payload.pull_request.html_url'

    # Replay everything retained for one app
    ghp webhooks tail --from all --filter 'github.webhooks.<app-record-id>.>'

    # A worker that must not miss deliveries across restarts
    ghp webhooks tail --durable review-agent --payload | my-agent
