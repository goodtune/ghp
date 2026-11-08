# #355: decision total p99 gap

## Problem

`ghp_proxy_decision_duration_seconds{stage="total"}` p99 is 38 to 42 ms on
about 200 samples per rig run. p95 is under 5 ms and no timed stage has a p99
above 4.1 ms. The slow samples spend their time outside every timed stage.

## Request path, arrival to forward (API vhost, `ghx_`/`gha_` token)

`start` is taken at the top of `proxy.Handler.ServeHTTP`. Middleware that runs
before it (vhost dispatch, access log, cache middleware `cache_lookup`) is not
part of `total`.

| # | Span | Timed today |
|---|------|-------------|
| 1 | API path normalisation (`/api/v3`, `/api/graphql`) | no (string ops, sub-µs) |
| 2 | `extractClientToken` | `token_extraction` |
| 3 | Border policy (non-GHP credentials only) | `border_policy_check` |
| 4 | Unsafe path segment check | `scope_enforcement` |
| 5 | `tokenService.Resolve` (hash, DB, expiry) | `token_resolution` |
| 6 | Context slot writes (`SetForwardProxyIdentity`, `SetUserID`) | no (pointer writes) |
| 7 | `parseScopeInfo` | `scope_parsing` |
| 8 | REST: `decideREST` | `scope_enforcement` |
| 9 | GraphQL: `io.ReadAll` of the client request body | **no** |
| 10 | GraphQL: `graphQLVerdict` | `graphql_analysis` + `scope_enforcement` |
| 11 | `getGitHubToken` | `github_token_resolution` |
| 12 | `resolveTokenUsername` (cache hit or async spawn) | `username_resolution` |
| 13 | `rewriteAuth`, `syntheticOAuthScopes` | no (string ops) |
| 14 | `forwardRequest`: `http.NewRequestWithContext`, header copy | **no** |
| 15 | `forwardRequest`: enterprise policy `Apply` | `enterprise_exception` (only when a policy is configured) |

Span 9 is the only untimed span that does I/O: it waits for the client to
upload the GraphQL body. A client that sends headers first and the body in a
later TCP segment (HTTP/1.1 with `Expect: 100-continue`, slow TLS writes,
Nagle/delayed-ACK interaction) makes that wait tens of ms. It is the prime
suspect for the 40 ms tail: the rig sends about 75 GraphQL requests per run,
and 2 or 3 slow ones are the p99 of 211 samples.

Other causes of an untimed gap: Go scheduler preemption or a GC pause between
stages. Those are not tied to a span and only a remainder sample shows them.

## Instrumentation

1. New stage `request_body_read`: the GraphQL body buffering (span 9).
2. New stage `request_build`: span 14, from `forwardRequest` entry to just
   before the enterprise call (which keeps its own stage). Span 13 and the
   Authorization substitution after the enterprise call are string work and
   fall into `pipeline_other`.
3. Derived stage `pipeline_other`: per request, `total` minus the sum of the
   stages observed for that request before `total`. A per-request trace is
   put in the context at the top of `ServeHTTP`; `ObserveDecision` adds each
   stage to it. When `total` is observed, `pipeline_other` is computed and
   observed (clamped at 0). Stages observed after `total`
   (`upstream_roundtrip`, `forward_proxy_selection`) are not summed. Requests
   with no trace (other handlers) record no `pipeline_other`.
4. Slow decision log: when `total` is at or above
   `metrics.slow_decision_threshold` (default 10ms, `0` disables,
   `GHP_METRICS_SLOW_DECISION_THRESHOLD`), one warn line `slow_decision` with
   `total`, `pipeline_other`, each stage duration, `token_type`, `vhost`,
   `method` and `path`. The token is never logged.

Label cardinality: two new fixed stage values plus `pipeline_other`.

## After deployment

If the tail is span 9, `request_body_read` p99 matches the `total` p99 and the
slow log shows it. If `pipeline_other` carries the tail, the gap is runtime
(GC or scheduling) and not a code span; the log line gives the time of each
sample to correlate with `go_gc_duration_seconds`.
