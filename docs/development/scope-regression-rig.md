# Scope Regression Rig

## What it is

GHP makes one promise: a `ghx_` or `gha_` token can do what its profile allows and nothing more.
`scoperig` is a periodic, deterministic, live check of that promise against a real deployment.
It creates tokens with known profiles, sends real REST, GraphQL and `gh` requests through the instance, compares each result with the documented claim, and reports a status per claim.

It is an operator tool. It is not shipped in the `ghp` binary and it does not run in CI (CI runs only the offline `validate` step and the corpus test).

What iteration 1 does not cover:

- Git smart-HTTP, border-policy reload, audit logs, hard delete. Enterprise exceptions (ENT-C50) and anonymous git (BORDER-C46) are covered only when the operator declares them; see [Enterprise deployment runbook](scope-regression-rig-enterprise.md).
- Load or performance testing. The optional latency section (see [Latency](#latency)) measures the run's own requests only.
- Fixing product defects. The rig finds them; fixes are separate pull requests.

## Requirements

- Go 1.24.
- `gh` on `PATH`, or set `GHP_RIG_GH` to its path.
- `git` on `PATH`. The `gh` working directory is an empty git checkout on the fixture branch (`gh pr status` needs a current branch).
- An admin session token (`ghpr_`) for the instance. It is the `user_token` of the `ghp` CLI config (`~/.config/ghp/config.yaml`, written by `ghp auth login` or `ghp auth set-token`). When that config has a `dotvault:` stanza, the token is the Vault field that `dotvault.fields.user_token` names, read with the dotvault client config `dotvault.config` (or its default path) and service `dotvault.service`. Export it as `GHP_USER_TOKEN` without printing it.
- The three fixture repositories A, B and W (see [Fixtures](#fixtures)). Usually you create them by hand first: see below.
- For `oracle` only: your own `gh` login, stored in `hosts.yml` or the macOS keychain. The Linux Secret Service (DBUS) is not passed through. `run` does not need it; it gives `gh` the minted token in `GH_ENTERPRISE_TOKEN`.
- The instance's TLS certificate must be trusted by the system trust store. `GHP_RIG_CA_FILE` adds a CA bundle for the rig's own HTTP client. The rig passes `SSL_CERT_FILE` through to `gh` when you set it, but Go ignores `SSL_CERT_FILE` on macOS, so on macOS `gh` relies on the system keychain.

## Configuration

### Environment

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GHP_SERVER_URL` | yes | none | Instance base URL; must use `https`, for example `https://ghp.example.com` |
| `GHP_USER_TOKEN` | yes | none | `ghpr_` session token for `/api/tokens` |
| `GHP_RIG_REPO_A` | no | `fixtures.repo_a` in `rig/config.yaml` | Read fixture A |
| `GHP_RIG_REPO_B` | no | `fixtures.repo_b` | Read fixture B (the "other" repository) |
| `GHP_RIG_REPO_W` | no | `fixtures.repo_w` | Write sandbox; the only repository the rig changes |
| `GHP_RIG_GH` | no | `gh` on `PATH` | Path to the `gh` binary |
| `GHP_RIG_GHP` | no | `ghp` on `PATH` | Path to the `ghp` CLI for `kind: git_credential` (build it with `make build`) |
| `GHP_RIG_SCENARIOS` | no | `rig` | Root of claims, profiles and scenarios |
| `GHP_RIG_INSTALLATION_ID` | no | `instance.agent_installation.installation_id` | Positive integer; overrides the agent installation (see [Agent tokens](#agent-tokens)) |
| `GHP_RIG_CA_FILE` | no | system pool | Extra PEM CA bundle |

`gh` runs with an environment built from scratch: a fresh `GH_CONFIG_DIR`, a fresh `XDG_CACHE_HOME`, a fresh working directory that is an empty git repository on the fixture branch (no remotes; `GH_REPO` names the base repository), and the token in `GH_ENTERPRISE_TOKEN` only. No inherited `GH_*` or `GITHUB_*` variable reaches it.

### `rig/config.yaml`

The repository holds `rig/config.example.yaml`. `rig/config.yaml` is operator-local and git-ignored. Before the first live run, copy the example and set the fixture repositories:

```bash
cp rig/config.example.yaml rig/config.yaml
# edit rig/config.yaml: replace OWNER in fixtures.repo_a, repo_b and repo_w
```

Select another file with the global `--config FILE` flag (default `rig/config.yaml`). If the default file does not exist, the rig loads `rig/config.example.yaml`, so `validate` works in a clean checkout. An explicit `--config` never falls back. `run` and `fixtures ensure` stop with exit 3 if a fixture repository owner is still the placeholder `OWNER` (the `GHP_RIG_REPO_A/B/W` variables also replace it).

The file holds the proxy API host (`host`), token durations, the token-create rate limit (the token manager paces at 75% of it), and the default fixture repositories. When `host` is empty, the rig uses the host of `GHP_SERVER_URL`. Management calls (token create, revoke and sweep) always use `GHP_SERVER_URL`.

`instance.border_block` lists the token prefixes that the instance's border policy blocks, for example `[ghp_, gho_, github_pat_]`. The rig does not probe this value. It must match the border policy of the instance. If a prefix is missing from the list, the BORDER-C43 scenarios for that prefix are GAP.

Fixture repositories are normalised when the config loads: spaces and a trailing `.git` are removed. `repo_a`, `repo_b` and `repo_w` must all differ (compared ASCII case-insensitively); the rig refuses to start when W equals A or B, or A equals B, because W receives every write and A and B must stay read-only.

`instance.allow_no_expiry` declares the instance's `tokens.allow_no_expiry`. The instance does not expose it, so the rig never probes it. Set it to `false` (the server default) to run LIFE-C39; leave it unset and LIFE-C39 is GAP.

`instance.agent_installation` names the GitHub App installation that agent (`gha_`) profiles use. See [Agent tokens](#agent-tokens).

### Agent tokens

The agent profiles (`agent-open`, `agent-repo-A`, `agent-repo-W`, `agent-perm-ro`) and the scenarios in `rig/scenarios/agent.yaml` need a GitHub App installation that the rig may use:

1. Create a GitHub App and install it on the three fixture repositories A, B and W (one installation; "Only select repositories" is enough). Give it at least these repository permissions: contents write, issues write, pull requests write, metadata read, actions read, checks read and statuses read.
2. Register the App in the GHP instance (admin UI or `POST /api/apps`). Do not make it the default app.
3. Put its app record UUID (the `id` from `GET /api/apps`, not the GitHub App ID) and the installation ID in `rig/config.yaml`:

```yaml
instance:
  agent_installation:
    app_record_id: 00000000-0000-0000-0000-000000000000
    installation_id: 12345678
```

The rig rejects an `app_record_id` that is not a UUID and an `installation_id` that is not a positive integer. The `agent_installation` capability is true when both values are set and `GET /api/apps/{app_record_id}` answers 200 with that ID. The rig checks this before it mints profile tokens: when it is false, the agent profiles are not minted and their scenarios are GAP. The check does not call GitHub, so it does not prove that the installation covers the fixtures. Every agent token the rig creates names this app explicitly. A token created without `app_record_id` is pinned to the instance's default app, so the rig never omits it.

A profile may set `requires: [agent_installation]` (`type: agent` must). Every scenario that uses the profile must list the same capability. The token manager mints and revokes agent tokens like proxy tokens and never prints their values.

What the agent scenarios cover:

- AGENT-C49: GHP enforces the repository allowlist (A allowed, B and W denied) and the permission levels (reads allowed, writes denied before GitHub) of an agent token.
- TOK-C02: the admin session creates an agent token. The non-admin half needs a second, non-admin session. The rig has only the admin session, so that scenario requires `non_admin_session`, which is never set, and reports GAP.
- TOK-C03 and TOK-C04: `ghp token create` resolves `--app` and `--installation` in the CLI, through `GET /api/apps` and `GET /api/apps/{id}/installations`. The rig checks the data those endpoints return (the app name with its record ID, the installation ID with the account login, a default app marked; that last check requires the `default_app` capability). It does not run the CLI binary. The server-side default for a token created without `app_record_id` is not exercised, because it would use the default app.
- REPO-C08: the API keeps the single `repository` field of a proxy token and the `repositories` list of an agent token.

#### The #294 probe

GHP sends an agent token's repositories to GitHub's installation `access_tokens` API when it first needs an installation token. Before 0.27.0 (#358, the fix for #294) it sent `owner/repo`. GitHub rejected that form with 422 ("There is at least one repository that does not exist or is not accessible to the parent installation"), so a repository-scoped agent token failed on every request; it was not widened. Since 0.27.0 GHP sends bare names.

- `GAP-A6.repo-a-reads-a` and `AGENT-C49.repo-w-reads-w` send a request with a token scoped to one repository. A 200 proves that GitHub accepted the mint body. They carried `known_issue` #294 with the observed 422 until 0.27.0; both pass on 0.27.0.
- `AGENT-C49.repo-a-denies-b` and `AGENT-C49.repo-a-denies-w` show that GHP denies B and W to a token scoped to A, although the installation covers both.

What the probe does not prove: that GitHub narrows the installation token. That needs the raw installation token, which never leaves GHP, and GHP denies the request before it reaches GitHub. The W probe tests the GHP layer only.

### Capabilities

The preflight step sets these capabilities. A scenario that needs a capability that is false is GAP.

| Capability | True when |
|---|---|
| `repo_w_push` | The user can push to fixture repository W. |
| `repo_create` | The credential has the `repo` or `public_repo` OAuth scope and W's owner is the probed login. |
| `github_vhost` | The instance answers a TLS request with SNI `github.com`. |
| `codeload_vhost` | The instance answers a TLS request with SNI `codeload.github.com`. |
| `agent_installation` | `instance.agent_installation` is set and `GET /api/apps/{app_record_id}` answers 200 with that ID (checked before profile tokens are minted). |
| `default_app` | `GET /api/apps` lists exactly one app with `is_default` true (TOK-C04). |
| `non_admin_session` | Never set. Reserved for the non-admin half of TOK-C02; the rig has only the admin session. |
| `border_block_ghp` | `ghp_` is in `instance.border_block`. |
| `border_block_gho` | `gho_` is in `instance.border_block`. |
| `border_block_github_pat` | `github_pat_` is in `instance.border_block`. |
| `no_expiry_disallowed` | `instance.allow_no_expiry` is declared `false`. |
| `ghp_cli` | The `ghp` binary (`GHP_RIG_GHP`, else `ghp` on `PATH`) exits 0 for `auth git-credential --help`. |
| `anonymous_git` | `instance.anonymous_git` is true (declared, not probed). |
| `ghp_metrics` | `instance.metrics_url` is set. Needed by every scenario with `metric_delta`. |
| `enterprise_restriction` | `instance.metrics_url` and `instance.enterprise_restriction.restricted_repo` are set. |
| `enterprise_exception_omit`, `_team_denied`, `_identity`, `_unauthenticated` | `enterprise_restriction`, and the matching `instance.enterprise_restriction.*_repo` is set. |

### Global flags

- `--config FILE` — rig config file.
- `--verbose` — print redacted request and response exchanges.

## Fixtures

The `repo_create` capability is usually false: the GitHub credential behind GHP normally lacks the `repo` OAuth scope. So create the three private repositories by hand first, under your own login, then let the rig seed them:

```bash
gh repo create --private OWNER/ghp-scoperig-a
gh repo create --private OWNER/ghp-scoperig-b
gh repo create --private OWNER/ghp-scoperig-w
./scoperig fixtures ensure
```

`fixtures ensure` finds and seeds repositories A, B and W through GHP with a temporary `open` token, which it creates and revokes. It creates and revokes this one token on every call, even when it only reports what it would do (missing repositories and no `--create-fixtures`); this is by design, because it needs the token to probe the capabilities and read the repositories. It seeds, idempotently: a `scoperig` label, an open issue, a `scoperig-fixture` branch with one commit, an open PR from it, and a `scoperig-fixture-v0` release. It then prints the discovered values.

If a repository is missing, it prints what it would create and exits 3. To create them:

```bash
./scoperig fixtures ensure --create-fixtures
```

`--create-fixtures` creates **private** repositories named `ghp-scoperig-a`, `ghp-scoperig-b` and `ghp-scoperig-w` under the operator's own GitHub login. It needs the `repo_create` capability; without it the command refuses and tells you to create them by hand (`gh repo create --private ...`) and re-run. This is the only rig command that creates repositories, and the only side effect you opt into.

## Running

Validate offline first. This needs no network and no environment:

```bash
make scoperig-validate
```

A rest request may set `vhost: github.com` (needs `requires: [github_vhost]`) or `vhost: codeload.github.com` (needs `requires: [codeload_vhost]`); the request goes to the instance with that TLS SNI and Host header and no `/api/v3` prefix, and must be a GET or HEAD. A graphql scenario may set `operation_name`, sent as the request's `operationName`. Templates have the functions `add` (duration arithmetic), `upper` and `base64` (standard encoding, for a Basic credential). `{{.Agent.AppRecordID}}` and `{{.Agent.InstallationID}}` hold the configured agent installation; in a request body, `"$int:InstallationID"` sends the installation ID as a JSON number.

A token_api scenario may also GET `/api/github/permissions` (session token, exact path, no query): the permission list the web UI offers, used by PERM-C18 because the CLI embeds no list.

A `kind: git` scenario runs the system `git` through the instance's `github.com` virtual host. `git_op` is `clone` or `push`, and `repo` is `A`, `B` or `W`. Every git scenario needs `requires: [github_vhost]`. The rig resolves `github.com` to the instance with `http.curloptResolve`, so TLS SNI and Host are `github.com`. Each run has a throwaway `HOME`, no system config, no credential helper and no prompt. The token is an `http.extraHeader` Basic credential (`x-access-token`) in a 0600 gitconfig file in that `HOME` (`GIT_CONFIG_GLOBAL`), never on the command line or in the environment; `http.followRedirects=false` keeps it from following a redirect. `GHP_RIG_CA_FILE` is passed as `GIT_SSL_CAINFO`. The observation is git's exit code, redacted output, and `status` parsed from git's `The requested URL returned error: NNN` line (0 when absent). A clone is retried on a transport error; a push never is. A push goes only to W, on a `branch` that contains `{{.RunID}}`, needs `requires: [github_vhost, repo_w_push]` and a cleanup `DELETE /repos/{{.RepoW}}/git/refs/heads/<branch>`; validation and the executor both refuse a push to A or B.

A `kind: git_credential` scenario (CRED-C55) runs `ghp auth git-credential` from `GHP_RIG_GHP` with a throwaway `HOME`, `--cache-backend file`, `--type agent` and `--app <instance.agent_installation app record ID>` (never the default app), and the rig's own `GHP_SERVER_URL` and `GHP_USER_TOKEN` in the environment (no config file, so no dotvault). It needs `repo: W`, `requires: [agent_installation, ghp_cli]`, no profile and no cleanup. For W it runs `get`, `get` again, uses the token on W and A, `erase`, `get`, `clear`, and returns a JSON summary as the body: `get_exit`, `first_minted`, `token_prefix` (`gha_`, never more), `username`, `token_type`, `repositories`, `second_get_exit`, `second_get_same_token` (false when either password is empty), `second_get_minted`, `w_status`, `a_status`, `erase_exit`, `erase_revoked`, `third_get_minted`, `clear_exit`, `clear_output`, `clear_revoked`, `foreign_new_tokens` and `stopped` (when the flow ended early). The helper's tokens carry the session `git-credential:<hostname>`, the same as the operator's own helper, so the rig attributes a new token by value: its `token_prefix` must be a prefix of the password the helper printed, its repositories exactly `[W]` and its `app_id` the agent app. Only attributed tokens are counted and revoked. Any other new `git-credential:` token is counted in `foreign_new_tokens` and never revoked.

A `kind: corpus` entry replays a `gh` query corpus live. `Load` replaces it with one graphql scenario per corpus query and corpus profile, with the ID `<id>.<file>.<operation>.<corpus profile>`; `validate` then checks each generated scenario like any other. `corpus` is the corpus directory relative to the rig root, and `corpus_profiles` maps every corpus profile (`open`, `perm-ro`, `repo`) to a rig profile; an unmapped profile is a load error. The corpus placeholders `OWNER`, `REPO` and `NODE_ID` in variables become fixture A's owner, name and node ID. A `verdict: allow` expects 200 and no GHP denial (GitHub may still report a GraphQL error for the placeholder numbers); a `deny:*` verdict expects 403, a GHP denial and the message for that reason. An entry with `known_issue` gets `observed:` from its `current` verdict. Run one command's queries with `--only 'GAP-A9.gh-2.102.0.pr_view.*'`.

Validation rejects, among other things, any non-GET request whose path does not target `/repos/<W>/...` (the exceptions are the GAP-A1 probe and `token_api` scenarios, which must target `/api/tokens`; a `token_api` scenario may also GET `/api/apps`, `/api/apps/{uuid}` and `/api/apps/{uuid}/installations`, and GET under `/api/v3/`; a `token_api` agent token body must set `app_record_id: "{{.Agent.AppRecordID}}"` and `installation_id: "$int:InstallationID"` and require `agent_installation`), and paths with `..`, dot segments or encoded dots. A `gh` argument that contains the literal placeholder host `ghp.example` is rejected; use `{{.Host}}`.

`tools/scoperig/scenario/probe_test.go` holds a standing table of adversarial scenario shapes (host, path, cleanup, empty-matcher and `gh` parser tricks). Each must be rejected by a named rule, and CI runs it with the unit tests. When you find a new way past the validator, add a row there with the fix. A fuzz target (`go test -fuzz FuzzLoadValidate ./tools/scoperig/scenario`) searches for accepted REST writes that leave W.

Offline validation uses placeholder values for the host and the fixture repositories. `run` validates the tree again with the configured host and fixture repositories after it loads the config and before it sends any request, and exits 3 if that fails. So a scenario that hardcodes a placeholder value (for example the placeholder W repository) cannot pass offline and then reach a different repository at run time.

Live run:

```bash
export GHP_SERVER_URL=https://ghp.example.com
export GHP_USER_TOKEN=...   # from 'ghp auth login'; never paste it into issues or logs
make scoperig
./scoperig run --out /tmp/ghp-rig/reports/run.json
```

`run` flags:

- `--out FILE` — write the JSON report. Write reports under `/tmp/ghp-rig/reports/`; reports are never checked in.
- `--only GLOB` — run only scenario IDs that match. A comma-separated list matches any of its globs. The run still sweeps and cleans up.
- `--claims ID,ID` — run only the scenarios of these claims, show only these claims in the table and JSON report, and print a one-line `scoperig-result: {...}` JSON summary (no host, no token) to paste into an issue. An unknown claim ID exits 3.
- `--skip-known` — skip scenarios that have a `known_issue`. By default KNOWN scenarios run, so they can report KNOWN-FIXED or KNOWN-CHANGED.
- `--keep-going` — continue after a FAIL or ERROR (default true).

Every HTTP request the rig itself sends (preflight, token management, proxied REST and GraphQL, fixture discovery and seeding, the `github.com` virtual-host probe) carries the User-Agent `ghp-scoperig/<version> (run=<run-id>)`. `<version>` is the first 12 characters of the commit that `make scoperig` stamps into the binary (with `-dirty` for a modified tree); a binary built another way falls back to the module version, then the first 12 characters of the Go VCS revision, then `dev`; `<run-id>` is the run id printed in the report (for `sweep` and `fixtures ensure`, the id of their own token session). Filter the instance's access logs on it to isolate one run. `gh` runs keep the GitHub CLI's own User-Agent: `gh` has no setting to change it.

A run starts by sweeping: it revokes every unrevoked token whose session id starts with `scoperig-`. Because of this, **concurrent runs against one instance are not supported** — a second run revokes the first run's tokens.

A rest or graphql request header with an empty value is removed, so `headers: {Authorization: ""}` sends an anonymous request.

A scenario may add `metric_delta`, a list of `{name, labels, min, max}` checks on GHP's own Prometheus metrics. The rig reads `instance.metrics_url` before and after the scenario, sums every sample of `name` whose labels include `labels` (a histogram's sample count is `<name>_count`), and turns a PASS into FAIL when the change is below `min` or above `max`. With `interference: true` (needs `max`), a change above `max` is taken as other traffic on the instance and the scenario is ERROR, never PASS or FAIL. A failed read is ERROR. The scenario must require `ghp_metrics`. Report lines drop the `ghp_` prefix from metric names, because report text is redacted and `ghp_` followed by eight word characters looks like a token.

## Matchers

`expect:` and `observed:` blocks share these matchers. Each block needs at least one. String values may be templated.

| Matcher | Holds when |
|---|---|
| `status`, `status_in` | The HTTP status equals the value, or is one of the list |
| `body_contains`, `body_not_contains` | The response body contains (or does not contain) every string |
| `header` | Each named header's first value equals the string |
| `header_not_contains` | No response header line (`Name: value`, after redaction) contains any of the strings. A token shows as `<prefix>[REDACTED]`; a Basic, bearer or token credential and a wholly masked `Authorization` or `Cookie` header show as `[REDACTED]`, so `[REDACTED]` finds all of them |
| `header_not_contains_except` | Headers that `header_not_contains` skips. Only `Set-Cookie` is allowed (redaction masks it whole, so its value says nothing) |
| `json` | Each JSON path (`$.a.b`, `$.items[0].id`) has the string value |
| `ghp_denial` | The response is (or is not) a GHP denial (403 or 401 with a GHP message) |
| `exit_code`, `exit_code_in` | The `gh` exit code equals the value, or is one of the list |
| `stdout_contains`, `stderr_contains` | `gh` output contains every string |
| `expires_within: {field, min, max}` | The RFC 3339 timestamp at `field` (`expires_at` or a JSON path) is no earlier than request start + `min` and no later than response end + `max`. `min` and `max` are Go durations and may be templated, for example `"{{add .Instance.DefaultDuration \"-2m\"}}"`. Validation requires 0 <= `min` <= `max` and `max` > 0. Leave a margin for clock skew between the rig and the instance. |

## Reading the report

The report header records the run id, the instance, the GHP version from preflight, the `gh` version (`gh --version`) and the rig commit (`git rev-parse HEAD` of the checkout or worktree, stamped into the binary with `-ldflags -X` by `make scoperig`, with a `-dirty` suffix for a modified tree). Build with `make scoperig`: Go's own VCS stamping can read the parent checkout when building inside a git worktree, so a plain `go build` falls back to it only when no commit was stamped, and `go run` leaves it empty.

### Scenario statuses

| Status | Meaning |
|---|---|
| PASS | The documented claim holds |
| FAIL | The claim does not hold |
| ERROR | The rig could not get a trustworthy result (transport error, cleanup failure, unexpected 5xx) |
| KNOWN | Has a `known_issue`; today's behaviour matches its `observed:` block |
| KNOWN-FIXED | Has a `known_issue`, but `expect:` now holds. Remove `known_issue` and `observed:` |
| KNOWN-CHANGED | Has a `known_issue`; neither `expect:` nor `observed:` matches. New information; shown in a separate "changed" section |

Templates in `expect:` and `observed:` (for example `json: {"$.login": "{{.Login}}"}`) are expanded with the live values before the scenario sends its first request, and again after it with the step captures. A template that cannot expand makes the scenario ERROR with "not run"; no request is sent. Step and `token_api` poll expectations are expanded the same way before they are matched.

A transport error (no HTTP response: connection reset, HTTP/2 GOAWAY, EOF, including through a forward proxy) is retried up to 2 times with backoff (0.5 s, then 1 s), but only when re-sending cannot duplicate a write: GET and HEAD requests, read-only GraphQL documents (queries only), a failed dial, and `gh` runs whose logged requests are all of those kinds. A transport error that remains, or one during a write, makes the scenario ERROR, never FAIL or KNOWN-CHANGED, because no product response was observed.

A 5xx response that the scenario does not name in `expect` is always ERROR, never FAIL. This includes a 500 that GHP itself produces.

A claim is FAIL if any scenario is FAIL, ERROR or KNOWN-CHANGED; else KNOWN if any is KNOWN or KNOWN-FIXED; else PASS if all runnable scenarios pass; else GAP (no runnable scenarios, including unmet `requires`).

### Latency

The latency section is advisory. It never changes the exit code. It is on when `metrics.prometheus_url` is set in `rig/config.yaml`:

```yaml
metrics:
  prometheus_url: https://grafana.example.com/api/datasources/proxy/uid/<datasource-uid>
  bearer_token_env: ""   # optional: name of an env var that holds a bearer token
  selector: ""           # optional label matchers without braces, for example job="ghp"
  scrape_wait: 45s       # default 45s, at most 5m
```

`prometheus_url` is a Prometheus base URL or a Grafana datasource proxy URL (anonymous read works); the rig appends `/api/v1/query`. Keep the real URL in `rig/config.yaml`, which is not checked in. The URL must use `http` or `https` and must not hold credentials, a query or a fragment. When `bearer_token_env` is set, the URL must use `https`, so the bearer token is not sent in clear text.

The rig refuses a bearer token that is equal to `GHP_USER_TOKEN` or that looks like a GitHub or GHP token (`ghp_`, `ghx_`, `gha_`, `github_pat_` and similar). This stops a configuration error from sending a GitHub credential to the Prometheus host. Use a separate token, for example a Grafana service account token.

`selector` must be a comma-separated list of label matchers in the form `label op "value"`. The operator is one of `=`, `!=`, `=~` or `!~`, and the value is a double-quoted string. The rig refuses braces and any other text, and the error names the bad matcher.

`scrape_wait` must be between `0s` and `5m`.

After the run, and after token revocation, the rig waits `scrape_wait` so that Prometheus scrapes the last requests. Then it evaluates `increase(...[<window>])` at the current time. The window starts at the run start, so it includes the scrape wait. The rig reads:

- `ghp_proxy_decision_duration_seconds` buckets, sum and count, by `stage` and `token_type`;
- `ghp_proxy_request_duration_seconds` buckets, sum and count (the `end_to_end` row, token type `all`);
- `ghp_build_info` `version` and `revision` (more than one value means a deploy during the window).

The rig computes p50, p95 and p99 from the bucket increases with the same linear interpolation as PromQL `histogram_quantile`, and the mean from sum / count. The JSON report has the same data under `latency` (`status` is `ok`, `not_configured` or `unavailable`; times are in seconds).

Advisory p99 budgets (from the v0.23.0 baseline):

| Stage | p99 budget |
|---|---|
| `scope_enforcement` | < 1 ms |
| `graphql_analysis` | < 2 ms |
| `token_extraction`, `border_policy_check`, `scope_parsing`, `username_resolution`, `forward_proxy_selection` | < 500 µs |
| `token_resolution` | < 10 ms |
| `github_token_resolution` | < 15 ms |
| `total_excl_body_read` | < 15 ms |

A row over its budget has the flag `WARN over-budget`. A row with fewer than 100 samples has `WARN low-samples`: its p99 rests on one or two observations. The raw `total` row has no budget, because it includes `request_body_read`, the time the client takes to upload a GraphQL body. The derived row `total_excl_body_read` (one per token type, after `total`) holds the 15 ms budget. It is shown as `total_excl_body_read (est.)` with a footnote: per-request differences are not recorded, so its quantiles are an estimate (total minus `request_body_read`, with requests that read no body counted as zero, never below 0); the mean is exact. It is built only when `total` and `request_body_read` come from the same source (both `increase()`, or both raw values, see below); otherwise it is omitted and the section prints `latency note: total_excl_body_read for <type> omitted: ...`. The JSON row has `estimate: true` and the section has `notes`.

A series that first appears inside the window (for example agent tokens after a deploy) is counted from its raw cumulative value at the end, because `increase()` never counts a series' first sample. The rig finds such series by querying which existed at the run start. A counter reset inside the window on such a series is not detected.

Other stages (`upstream_roundtrip`, `cache_lookup`, `enterprise_exception`, `redirect_head_check`, `end_to_end`) have no budget.

Limitations: the histograms are instance-wide, so other traffic in the window (including during the scrape wait) is counted with the rig's own requests; use `selector` to pick the instance's job. Quantiles cannot resolve changes smaller than one bucket. A Prometheus error or an interrupted wait makes the section `unavailable` with the reason.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No FAIL, no ERROR (KNOWN allowed) |
| 1 | At least one FAIL or KNOWN-CHANGED |
| 2 | At least one ERROR and no FAIL, including cleanup residue or a token left unrevoked |
| 3 | Could not start: config or validation error, instance unreachable, session token rejected, missing fixtures |

### Confidence and coverage gaps

- base = claims whose `testable` is `periodic`. Manual claims are listed as "manual"; `never` claims as "untestable". GAP probes (`GAP-*`) that are `periodic` are in base like any other claim. Every GAP scenario expects the safe behaviour, so a closed bypass is PASS and raises confidence, and a regression is FAIL and lowers it.
- **confidence = PASS / (base − KNOWN)**.
- **coverage = covered / base**, where covered is the number of base claims with at least one runnable (not GAP) scenario result. Coverage tells you how much of base the run exercised; confidence tells you how much of that holds. The text report prints both lines; the JSON report has `summary.covered` and `summary.coverage`.
- The coverage-gap list names every base claim with no scenario at all.

Iteration 1 covered 28 claims (about 55% predicted at the time). Base is now 61 periodic claims; batch 5 added CRED-C55 (the git credential helper) and scenarios for GIT-C48, PERM-C18 and LIFE-C39. 59 of the 61 base claims have at least one scenario. The two without one are BORDER-C46 (anonymous git) and ENT-C50 (enterprise restriction header): both need instance configuration that affects real traffic. Some claims that have scenarios still report GAP until a capability is true: BORDER-C43, BORDER-C44 and BORDER-C47 need `instance.border_block`; LIFE-C39 needs `instance.allow_no_expiry: false`; agent scenarios and CRED-C55 need `agent_installation` (CRED-C55 also `ghp_cli`); the non-admin half of TOK-C02 needs `non_admin_session`, which is never set. This branch has not been run live; on an instance with an agent installation and the `ghp` CLI but no border block or `allow_no_expiry` declaration, the expected result is about 56/61. Planned iterations:

| Iteration | Adds | Target |
|---|---|---|
| 1 | Runner, token lifecycle, REST/GraphQL/`gh`/token API kinds, fixtures, report, corpus test, skills | ~55% |
| 2 | Git smart-HTTP kind, agent tokens, remaining GraphQL claims, header/body scan on every response | ~70% |
| 3 | No-expiry config, anonymous git, enterprise exceptions, scheduled runs (expiry after a wait was added in batch 4) | ~80% |
| 4 | Reload and audit-log checks via operator hooks, corpus extended to write commands | 90%+ |

Confidence also rises when a KNOWN issue is fixed: the claim returns to the denominator and must pass.

## Safety

| Action | Where | Undo |
|---|---|---|
| Create and revoke tokens | GHP database | Revoked at end of run; swept at next start |
| Create repositories A, B, W | Operator's GitHub account | Manual; only with `--create-fixtures` |
| Seed issue, PR, branch, release, label | A, B, W | Persistent by design; idempotent |
| Create and delete file `scoperig-<run>.txt` | W | Deleted in cleanup |
| Create and close issue | W | Closed; GitHub cannot delete issues over REST, so closed issues accumulate |
| Create ref and PR, close PR, delete ref | W | Closed PR remains; ref deleted |
| Audit log rows | GHP | None; tagged with the `scoperig-<run>` session id |
| GitHub API quota | Operator's OAuth credential | About 200 calls per run |

Cleanup guarantees:

- Tokens are revoked on normal exit, on panic, and on SIGINT/SIGTERM. A second signal aborts cleanup and prints the ids that remain. SIGKILL cannot be handled; the next run's sweep and the token duration bound the exposure.
- Per-scenario cleanup runs with an `open` token even when steps fail. A cleanup failure is ERROR and is listed as residue with object URLs.
- If tokens are left over (the report prints `leftover token ids`), run:

```bash
./scoperig sweep
```

`sweep` revokes every unrevoked `scoperig-*` token. The next `run` does the same automatically. `sweep` exits 2 if the sweep fails or any token id is left over.

The rig never writes token values to the report, errors or `gh` captures; all captured output is redacted. Redaction finds tokens in plain text, in percent-encoded or JSON `\uXXXX`-escaped form, in `Authorization` Basic, Bearer and token credentials, and in bare base64 or base64url credentials that decode to `<user>:<token>`. The package comment in `tools/scoperig/redact` lists the forms it does not detect.

## Corpus test and the oracle

The corpus test runs offline in `make test`. It checks the GraphQL analyzer against the queries `gh` actually sends, stored under `rig/corpus/gh/<version>/`:

```bash
go test ./internal/proxy -run GHCorpus
```

To refresh the corpus after a `gh` upgrade, run `scoperig oracle`. It runs read-only `gh` commands against a public github.com repository with your own `gh` login, captures the requests, and writes them to `<out>/<version>/`. It prints a diff of the changes.

```bash
scoperig oracle --gh-version auto
```

| Flag | Default | Meaning |
|---|---|---|
| `--out` | `rig/corpus/gh` | Corpus root. |
| `--gh-version` | `auto` | Corpus version directory. `auto` reads `gh --version`. |
| `--oracle-repo` | `cli/cli` | Public repository (`owner/name`) for the read-only commands. |
| `--pr` | `1` | Pull request number in `--oracle-repo` for `pr view`, `pr checks` and `pr diff`. |
| `--issue` | `1` | Issue number in `--oracle-repo` for `issue view`. |
| `--gh` | `$GHP_RIG_GH`, then `gh` on `PATH` | The `gh` binary. |

Safety and limits:

- `pr_create_dryrun` is the only "create" command in the oracle matrix. It is safe: `--dry-run` stops before any change, an explicit `--head` skips the push and fork logic, and `gh` runs in a temporary directory that is not a git checkout, behind a git ceiling.
- The `gh` credential must be in `hosts.yml` or the macOS keychain. The oracle does not pass through the Linux Secret Service (DBUS), so on such hosts `gh` fails closed.
- Choose an oracle repository whose owner and name are not `gh` subcommand words or GraphQL keywords or field names (for example `list`, `view`, `on`, `node`). The identity scrub refuses such a repository and fails closed: nothing is written.
- If a command captures no request (for example, `gh` fails) and a corpus entry for that command exists (this version or the previous one), the oracle stops with an error and writes nothing. If no entry exists, it skips that command and reports it in the diff.
- Before you commit a refreshed corpus, review every `+ operation` and `+ field` line in the oracle diff. A new operation gets `verdict: allow` by default.

As a fallback, capture with `GH_DEBUG=api` by hand and convert the captures with:

```bash
go run ./tools/scoperig/corpus/importghdebug -in <captures dir> -out rig/corpus/gh/<version> \
  -gh-version <version> -owner <owner> -repo <repo>
```

Existing expectations in the output directory are kept per operation.

## Known limitations

- git does not print the response body of a failed request, so `GIT-C48.push-w-contents-read-denied` cannot check GHP's denial text. Its 403 is attributed to GHP scope enforcement only because `GIT-C48.push-w-contents-write` proves the same credential can write to W. Treat the denied result as meaningful only when the write scenario passed in the same run.
- `kind: git_credential` revokes only tokens it can attribute by value. A rig token whose value the helper never printed (for example a mint whose output was lost) is counted in `foreign_new_tokens` and not revoked. A non-zero `foreign_new_tokens` needs a manual check of the token list (session `git-credential:<hostname>`); it may also be the operator's own helper running at the same time.
- LIFE-C39 relies on the operator's `instance.allow_no_expiry` declaration.
- Agent (`gha_`) scenarios cannot test GitHub-side narrowing of the installation token or the non-admin refusal (TOK-C02), and check the CLI's `--app` / `--installation` resolution through the API data only (see [Agent tokens](#agent-tokens)).
- `LIFE-C41.expired-rejected` waits for a 1-minute token to expire, so a run that starts with it polls for up to 150 s.
- `gh` must run outside a github.com checkout, or it ignores `GH_HOST`. The rig runs it in a fresh temporary directory for this reason.
- Closed issues and PRs accumulate in W.
- One run per instance at a time (see the sweep above).

## Skills

Two Claude Code skills drive the rig procedurally:

- `.claude/skills/scope-rig-run/SKILL.md` — run the rig, read the report, triage a FAIL into a GitHub issue.
- `.claude/skills/scope-rig-extend/SKILL.md` — add a scenario for a claim, refresh the corpus after a `gh` upgrade, add GraphQL analyzer table entries.
