# Upstream transport tuning and metrics (part of #329)

## Problem

An operator saw upstream throughput rise from about 100 to about 460 Mbit/s
with `GODEBUG=http2client=0`. `routingTransport.transportFor` cloned
`http.DefaultTransport` once per egress path with no tuning and no
configuration. The metrics could not show upstream throughput, the negotiated
protocol, or connection reuse.

## Which transports share this path

All outbound GitHub traffic goes through a `routingTransport`, built in
`internal/server/server.go`:

| Transport | Users |
|---|---|
| `NewForwardProxyTransport` | API proxy (`proxy.go`), `github.com` passthrough (`passthrough.go`), codeload (`codeload.go`), Copilot passthrough, git cache upstream ls-refs/fetch (`gitcache/handler.go` via `SetTransport`) |
| `NewForwardProxyControlTransport` | App installation token minting, username resolution, OAuth flows and refresh, enterprise team checks |
| `NewForwardProxyNonGitHubControlTransport` | Release redirect HEAD probes |

Not on this path: the git cache's background `FetchUpstream`
(`gitcache/repository.go`) uses go-git's own HTTP client. Neither the new
settings nor the new metrics apply to it.

## Benchmark

### Synthetic: `BenchmarkUpstreamThroughput`

`internal/proxy/upstream_bench_test.go` (test file, not in the binary).
It downloads 32 MiB per stream through `routingTransport` from a local TLS
server (HTTP/2 enabled), through a userspace relay that adds one-way delay,
bounds bytes in flight per connection and direction to 4 MiB (a model of a
TCP window), and can hold a chunk for one RTO with every later chunk on that
connection queued behind it (a model of loss plus TCP head-of-line blocking).
The pool is warmed with one request first, as in a long-running ghp.

```
go test ./internal/proxy -run '^$' -bench BenchmarkUpstreamThroughput -benchtime 1x
# GHP_BENCH_RTTS, GHP_BENCH_STREAMS, GHP_BENCH_MB, GHP_BENCH_TCP_WINDOW,
# GHP_BENCH_LOSS, GHP_BENCH_PROFILES tune it.
```

Aggregate Mbit/s, one run each (loss runs are noisy), Apple M1, Go 1.27.3.
Profiles: `h2-stock` is the pre-change transport; `h1-stock` is what
`GODEBUG=http2client=0` gave; `h2-win16m` raises the HTTP/2 receive windows
to 16 MiB per stream and 64 MiB per connection; `h2-frame16k` sets the
minimum 16 KiB read frame size; `h1-idle32` is HTTP/1.1 with 32 idle
connections per host.

| RTT | loss | streams | h2-stock | h2-win16m | h2-frame16k | h1-stock | h1-idle32 |
|---|---|---|---|---|---|---|---|
| 0 | 0 | 1 | 8501 | 8225 | 5439 | 13784 | 13697 |
| 0 | 0 | 4 | 8145 | 8586 | 5420 | 22266 | 22602 |
| 0 | 0 | 8 | 8224 | 8063 | 5307 | 23794 | 24214 |
| 50 ms | 0 | 1 | 579 | 999 | 591 | 1003 | 1001 |
| 50 ms | 0 | 4 | 1169 | 1172 | 1174 | 3361 | 3174 |
| 50 ms | 0 | 8 | 1204 | 1201 | 1199 | 6618 | 6620 |
| 200 ms | 0 | 1 | 155 | 261 | 155 | 264 | 264 |
| 200 ms | 0 | 4 | 308 | 309 | 310 | 879 | 878 |
| 200 ms | 0 | 8 | 319 | 319 | 319 | 1745 | 1762 |
| 50 ms | 0.002 | 1 | 306 | 990 | 227 | 1002 | 608 |
| 50 ms | 0.002 | 4 | 529 | 580 | 440 | 1535 | 2164 |
| 50 ms | 0.002 | 8 | 939 | 565 | 610 | 3082 | 3018 |
| 200 ms | 0.002 | 1 | 88 | 140 | 95 | 202 | 264 |
| 200 ms | 0.002 | 4 | 196 | 195 | 156 | 421 | 456 |
| 200 ms | 0.002 | 8 | 225 | 232 | 178 | 814 | 1057 |

Idle pool, 5 bursts of 8 streams at 200 ms RTT, 8 MiB per stream:
`h1-stock` dialled 32 connections at 857 Mbit/s, `h1-idle32` dialled 8 at
1160 Mbit/s. With the Go default of 2 idle connections per host, every burst
above 2 redials (TLS handshake plus TCP slow start).

### Real: clone through a local ghp

`tools/upstreambench/clone-bench.sh` clones a public repository N times at
once through ghp on loopback (`http.curloptResolve` maps `github.com` to it).
Full bare clone of a ~310 MB repository; RTT to github.com from the test site
was about 6 ms.

| clones | HTTP/2 on | HTTP/2 off | direct, no ghp |
|---|---|---|---|
| 1 | 136 | 130 | 130 |
| 4 | 246 | 284 | — |
| 8 | 282 | 291 | — |

### What the numbers support

- **HTTP/2 flow control window: supported for one stream.** A single HTTP/2
  stream is capped near 4 MiB / RTT (155 Mbit/s at 200 ms, 168 predicted).
  Raising the stream window to 16 MiB brings one stream level with HTTP/1.1.
- **Single-connection multiplexing: supported for concurrency.** With 4 or 8
  streams, HTTP/2 stays at about one connection's worth (310 Mbit/s at
  200 ms) whatever the stream window, because every stream shares one TCP
  connection. HTTP/1.1 scales with the number of connections (5.5x at 8
  streams). Loss stalls make it worse for HTTP/2, since one stall holds every
  stream.
- **Frame size and write lock: not supported at WAN rates.** HTTP/2 costs CPU
  only at loopback speeds (8 vs 14-24 Gbit/s). The 16 KiB frame profile is
  slower, not faster, so the 1 MiB default stays.
- **Real clone: inconclusive.** At 6 ms RTT no window binds, and each clone
  ran at the rate GitHub served it (130 Mbit/s, the same as a direct clone).
  HTTP/1.1 was not slower (-5%, +15%, +3%, within noise). The relay models
  the TCP window and loss but not real congestion control or a shared
  bottleneck, so it shows the mechanism, not the operator's exact numbers.

## Design

### Config: `upstream` block

`config.UpstreamConfig` (koanf `upstream`, env `GHP_UPSTREAM_*`), validated
in `Load` (ghp refuses to start on a bad value; a bad value on SIGUSR1 reload
fails the reload). Startup only; not hot-reloadable.

| Key | Default | Range |
|---|---|---|
| `http2` | `false` | bool |
| `max_idle_conns_per_host` | `32` | >= 0, 0 = Go default 2, <= `max_conns_per_host` when that is set |
| `max_conns_per_host` | `0` | >= 0, 0 = no limit |
| `idle_conn_timeout` | `90s` | >= 0, 0 = Go default 90s |
| `http2_max_read_frame_size` | `0` | 0 or 16384..16777215 |
| `http2_max_receive_buffer_per_connection` | `0` | 0 or 65536..2147483647 |
| `http2_max_receive_buffer_per_stream` | `0` | 0 or 65536..2147483647 |

The HTTP/2 bounds follow RFC 9113 and the bundled transport's own clamps
(`net/http/internal/http2/config.go`: windows up to `math.MaxInt32`); the
documentation's "less than 4MiB" wording does not match the code.

`newUpstreamTransport(cfg)` builds every transport `routingTransport`
creates, and `transportFor` still makes one per egress proxy, so per-request
proxy routing is unchanged. Protocols are set with `Transport.Protocols`
and HTTP/2 settings with `Transport.HTTP2` (Go 1.24+; go.mod is 1.26). No
GODEBUG.

The base transport is built from scratch, not cloned from
`http.DefaultTransport`. Once the default transport has set up HTTP/2, a
clone carries a TLS config whose ALPN list already offers `h2`. With
`Protocols` set to HTTP/1.1 only, GitHub then picks h2 and the request fails
with EOF. The first real clone with HTTP/2 off found this; a unit test now
covers it.

### Defaults and reasons

- `http2: false`. HTTP/1.1 matched or beat HTTP/2 in every synthetic case,
  by 2-5x with 4 or more concurrent streams at 50-200 ms. It was not slower
  in the real clone. It is what the operator's workaround already ran. Go's
  HTTP/2 client has no setting to spread streams over more connections
  (`MaxConcurrentStreams` is server-only; `StrictMaxConcurrentRequests` opens
  a new connection only past the server's stream limit), so window tuning
  alone cannot fix concurrent throughput.
- `max_idle_conns_per_host: 32`. Removes the redial on every burst above 2
  (32 vs 8 dials and 857 vs 1160 Mbit/s above). The total idle pool is raised
  to match when needed.
- `max_conns_per_host: 0` and `idle_conn_timeout: 90s`. Go defaults; the
  benchmark gives no reason to change them.
- HTTP/2 frame and window sizes: Go defaults. They only apply with HTTP/2
  on. A 16 MiB stream window helped one stream, but a large window lets one
  slow client hold more buffered data, so it is documented as a
  recommendation, not a default.

### Metrics

`roundTripInstrumented` wraps each `routingTransport.RoundTrip` (all three
transports) with `httptrace`:

- `ghp_upstream_connections_total{protocol,vhost,result}`: `GotConn`,
  `result` = `opened` or `reused`.
- `ghp_upstream_first_byte_seconds{protocol,vhost}`: from the start of the
  round trip (after proxy selection) to `GotFirstResponseByte`; decision
  buckets (10us-10s). `upstream_roundtrip` minus this is the transfer time.
- `ghp_upstream_sent_bytes_total{protocol,vhost}` and
  `ghp_upstream_received_bytes_total{protocol,vhost}`: body bytes, added per
  `Read` so `rate()` shows long transfers while they run.

`protocol` comes from the connection's ALPN (`h2`, `http/1.1`, `unknown`);
`vhost` from the request context (`metrics.VhostFromContext`). No hosts,
paths or proxy URLs. Nothing is recorded with a hard-coded value: no
connection, no sample.

## Limitations

- Body bytes only: no headers, HTTP/2 framing or TLS overhead.
- A request body that the transport replays (via `GetBody`) after a retry is
  not counted again.
- `101 Switching Protocols` response bodies are not wrapped (ReverseProxy
  needs the raw `io.ReadWriteCloser`), so upgraded connections are not counted.
- go-git `FetchUpstream` is outside these transports.
- The synthetic relay models delay, a TCP window and HOL stalls, not real
  congestion control or a shared bottleneck. The real clone ran at low RTT,
  where the protocols tie.
- Follow-up from the issue: an advisory throughput section in the scope rig
  report, using these metrics.
