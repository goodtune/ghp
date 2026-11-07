# Scope Regression Rig

## What it is

GHP makes one promise: a `ghx_` or `gha_` token can do what its profile allows and nothing more.
`scoperig` is a periodic, deterministic, live check of that promise against a real deployment.
It creates tokens with known profiles, sends real REST, GraphQL and `gh` requests through the instance, compares each result with the documented claim, and reports a status per claim.

It is an operator tool. It is not shipped in the `ghp` binary and it does not run in CI (CI runs only the offline `validate` step and the corpus test).

What iteration 1 does not cover:

- Git smart-HTTP, agent (`gha_`) tokens, enterprise exceptions, border-policy reload, expiry after a wait, anonymous git, audit logs, hard delete.
- Load or performance testing, and metrics scraping.
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
| `GHP_RIG_SCENARIOS` | no | `rig` | Root of claims, profiles and scenarios |
| `GHP_RIG_INSTALLATION_ID` | no | none | Positive integer; enables the `agent_installation` capability |
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

### Capabilities

The preflight step sets these capabilities. A scenario that needs a capability that is false is GAP.

| Capability | True when |
|---|---|
| `repo_w_push` | The user can push to fixture repository W. |
| `repo_create` | The credential has the `repo` or `public_repo` OAuth scope and W's owner is the probed login. |
| `github_vhost` | The instance answers a TLS request with SNI `github.com`. |
| `agent_installation` | `GHP_RIG_INSTALLATION_ID` is set and the session can list all tokens. |
| `border_block_ghp` | `ghp_` is in `instance.border_block`. |
| `border_block_gho` | `gho_` is in `instance.border_block`. |
| `border_block_github_pat` | `github_pat_` is in `instance.border_block`. |

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

Validation rejects, among other things, any non-GET request whose path does not target `/repos/<W>/...` (the exceptions are the GAP-A1 probe and `token_api` scenarios, which must target `/api/tokens`), and paths with `..`, dot segments or encoded dots. A `gh` argument that contains the literal placeholder host `ghp.example` is rejected; use `{{.Host}}`.

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
- `--only GLOB` — run only scenario IDs that match. The run still sweeps and cleans up.
- `--skip-known` — skip scenarios that have a `known_issue`. By default KNOWN scenarios run, so they can report KNOWN-FIXED or KNOWN-CHANGED.
- `--keep-going` — continue after a FAIL or ERROR (default true).

Every HTTP request the rig itself sends (preflight, token management, proxied REST and GraphQL, fixture discovery and seeding, the `github.com` virtual-host probe) carries the User-Agent `ghp-scoperig/<version> (run=<run-id>)`. `<version>` is the module version, or the first 12 characters of the VCS revision for a binary built from a checkout, or `dev`; `<run-id>` is the run id printed in the report (for `sweep` and `fixtures ensure`, the id of their own token session). Filter the instance's access logs on it to isolate one run. `gh` runs keep the GitHub CLI's own User-Agent: `gh` has no setting to change it.

A run starts by sweeping: it revokes every unrevoked token whose session id starts with `scoperig-`. Because of this, **concurrent runs against one instance are not supported** — a second run revokes the first run's tokens.

## Matchers

`expect:` and `observed:` blocks share these matchers. Each block needs at least one. String values may be templated.

| Matcher | Holds when |
|---|---|
| `status`, `status_in` | The HTTP status equals the value, or is one of the list |
| `body_contains`, `body_not_contains` | The response body contains (or does not contain) every string |
| `header` | Each named header's first value equals the string |
| `json` | Each JSON path (`$.a.b`, `$.items[0].id`) has the string value |
| `ghp_denial` | The response is (or is not) a GHP denial (403 or 401 with a GHP message) |
| `exit_code`, `exit_code_in` | The `gh` exit code equals the value, or is one of the list |
| `stdout_contains`, `stderr_contains` | `gh` output contains every string |
| `expires_within: {field, min, max}` | The RFC 3339 timestamp at `field` (`expires_at` or a JSON path) is no earlier than request start + `min` and no later than response end + `max`. `min` and `max` are Go durations and may be templated, for example `"{{add .Instance.DefaultDuration \"-2m\"}}"`. Validation requires 0 <= `min` <= `max` and `max` > 0. Leave a margin for clock skew between the rig and the instance. |

## Reading the report

The report header records the run id, the instance, the GHP version from preflight, the `gh` version (`gh --version`) and the rig commit (the VCS revision stamped into the binary by `make scoperig`; empty under `go run`, with a `-dirty` suffix for a modified tree).

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

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No FAIL, no ERROR (KNOWN allowed) |
| 1 | At least one FAIL or KNOWN-CHANGED |
| 2 | At least one ERROR and no FAIL, including cleanup residue or a token left unrevoked |
| 3 | Could not start: config or validation error, instance unreachable, session token rejected, missing fixtures |

### Confidence and coverage gaps

- base = claims whose `testable` is not `never` or `manual`. Manual claims are listed as "manual"; `never` claims as "untestable". GAP probes (A1–A9) are reported but not in base.
- **confidence = PASS / (base − KNOWN)**.
- The coverage-gap list names every base claim with no runnable scenario.

Iteration 1 covers 28 claims. The prediction is 27 PASS and 22 GAP, so confidence is 27 / 49 (1 KNOWN), about 55%. Planned iterations:

| Iteration | Adds | Target |
|---|---|---|
| 1 | Runner, token lifecycle, REST/GraphQL/`gh`/token API kinds, fixtures, report, corpus test, skills | ~55% |
| 2 | Git smart-HTTP kind, agent tokens, remaining GraphQL claims, header/body scan on every response | ~70% |
| 3 | Expiry after a wait, no-expiry config, anonymous git, enterprise exceptions, scheduled runs | ~80% |
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

The rig never writes token values to the report, errors or `gh` captures; all captured output is redacted.

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

- No git smart-HTTP scenarios.
- No agent (`gha_`) token scenarios.
- No expiry-after-wait scenarios.
- `gh` must run outside a github.com checkout, or it ignores `GH_HOST`. The rig runs it in a fresh temporary directory for this reason.
- Closed issues and PRs accumulate in W.
- One run per instance at a time (see the sweep above).

## Skills

Two Claude Code skills drive the rig procedurally:

- `.claude/skills/scope-rig-run/SKILL.md` — run the rig, read the report, triage a FAIL into a GitHub issue.
- `.claude/skills/scope-rig-extend/SKILL.md` — add a scenario for a claim, refresh the corpus after a `gh` upgrade, add GraphQL analyzer table entries.
