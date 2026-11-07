# Scope rig hardening batch 2 (#309, #308, #304, #307, #305, #303)

Operator tool only (`tools/scoperig`, `rig/`, scope-rig skills and docs). No product code changes.

## Order

One commit per issue: #309, #308, #304, #307, #305, transport-error retry, user agent, then #303 last so that the probe table covers every new validator rule.

## Decisions

- #309: `tokens.Pace` clamps with `max(rate, 1)`; the default rate (20/min) lives only in config. "Positional fixture arguments" is read as gh positionals built from fixture templates (`{{.Fixture.W.PRNumber}}`): they carry no `/` and are not repository references, while slash-bearing positionals still resolve and must be W for writes.
- #304: both options. (A) `ghcheck` rejects any raw gh arg that contains the literal placeholder host. (B) `runRig` re-runs `scenario.Validate` with the real Vars after config load and before the first request; a failure exits 3.
- #307: `expect`/`observed` are expanded before the executor runs with the Vars known at that point; templates that need step captures are expanded again after the run. A template error is a validation-time failure, not an ERROR after a live request. The `token_api` poll expands its request templates.
- #305: `expires_within: {field, min, max}`, relative to the request time recorded by the executor. Durations are validated in `scenario.Validate` (positive, min <= max).
- Transport errors: a request that fails with a transport error (connection reset, HTTP/2 GOAWAY, unexpected EOF, including through a forward proxy) is retried twice with backoff; if it still fails, the scenario is ERROR (exit 2), never FAIL or KNOWN-CHANGED. Only idempotent replays are retried: the request had no response, so nothing was classified.
- User agent: every rig HTTP request (management API, proxy, preflight, fixtures) carries `ghp-scoperig/<version> (run=<run-id>)`, set by an `http.RoundTripper` wrapper so no call site can miss it. gh subprocesses keep gh's own user agent.
- #303: `scenario/probe_test.go`, each hostile shape asserts the named rule in the error text. A fuzz target over load + Validate asserts no accepted write targets a repo other than W.
