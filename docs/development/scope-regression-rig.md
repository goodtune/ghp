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
- An admin session token (`ghpr_`) for the instance, from `ghp auth login`.
- The three fixture repositories A, B and W (see [Fixtures](#fixtures)).
- The instance's TLS certificate must be trusted by the system trust store. `GHP_RIG_CA_FILE` adds a CA bundle for the rig's own HTTP client. The rig passes `SSL_CERT_FILE` through to `gh` when you set it, but Go ignores `SSL_CERT_FILE` on macOS, so on macOS `gh` relies on the system keychain.

## Configuration

### Environment

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GHP_SERVER_URL` | yes | none | Instance base URL, for example `https://ghp.touchtechnology.network` |
| `GHP_USER_TOKEN` | yes | none | `ghpr_` session token for `/api/tokens` |
| `GHP_RIG_REPO_A` | no | `fixtures.repo_a` in `rig/config.yaml` | Read fixture A |
| `GHP_RIG_REPO_B` | no | `fixtures.repo_b` | Read fixture B (the "other" repository) |
| `GHP_RIG_REPO_W` | no | `fixtures.repo_w` | Write sandbox; the only repository the rig changes |
| `GHP_RIG_GH` | no | `gh` on `PATH` | Path to the `gh` binary |
| `GHP_RIG_SCENARIOS` | no | `rig` | Root of claims, profiles and scenarios |
| `GHP_RIG_INSTALLATION_ID` | no | none | Positive integer; enables the `agent_installation` capability |
| `GHP_RIG_CA_FILE` | no | system pool | Extra PEM CA bundle |

`gh` runs with an environment built from scratch: a fresh `GH_CONFIG_DIR`, a fresh `XDG_CACHE_HOME`, a working directory that is not a git checkout, and the token in `GH_ENTERPRISE_TOKEN` only. No inherited `GH_*` or `GITHUB_*` variable reaches it.

### `rig/config.yaml`

Select another file with the global `--config FILE` flag (default `rig/config.yaml`). The file holds the instance hosts (`host`, `management_host`), token durations, the token-create rate limit (the token manager paces at 75% of it), and the default fixture repositories.

### Global flags

- `--config FILE` — rig config file.
- `--verbose` — print redacted request and response exchanges.

## Fixtures

```bash
./scoperig fixtures ensure
```

`fixtures ensure` finds and seeds repositories A, B and W through GHP with a temporary `open` token, which it creates and revokes. It seeds, idempotently: a `scoperig` label, an open issue, a `scoperig-fixture` branch with one commit, an open PR from it, and a `scoperig-fixture-v0` release. It then prints the discovered values.

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

Validation rejects, among other things, any non-GET request whose path does not target `/repos/<W>/...` (the exceptions are the GAP-A1 probe and `token_api` scenarios, which must target `/api/tokens`), and paths with `..`, dot segments or encoded dots.

Live run:

```bash
export GHP_SERVER_URL=https://ghp.touchtechnology.network
export GHP_USER_TOKEN=...   # from 'ghp auth login'; never paste it into issues or logs
make scoperig
./scoperig run --out /tmp/ghp-rig/reports/run.json
```

`run` flags:

- `--out FILE` — write the JSON report. Write reports under `/tmp/ghp-rig/reports/`; reports are never checked in.
- `--only GLOB` — run only scenario IDs that match. The run still sweeps and cleans up.
- `--skip-known` — skip scenarios that have a `known_issue`. By default KNOWN scenarios run, so they can report KNOWN-FIXED or KNOWN-CHANGED.
- `--keep-going` — continue after a FAIL or ERROR (default true).

A run starts by sweeping: it revokes every unrevoked token whose session id starts with `scoperig-`. Because of this, **concurrent runs against one instance are not supported** — a second run revokes the first run's tokens.

## Reading the report

### Scenario statuses

| Status | Meaning |
|---|---|
| PASS | The documented claim holds |
| FAIL | The claim does not hold |
| ERROR | The rig could not get a trustworthy result (transport error, cleanup failure, unexpected 5xx) |
| KNOWN | Has a `known_issue`; today's behaviour matches its `observed:` block |
| KNOWN-FIXED | Has a `known_issue`, but `expect:` now holds. Remove `known_issue` and `observed:` |
| KNOWN-CHANGED | Has a `known_issue`; neither `expect:` nor `observed:` matches. New information; shown in a separate "changed" section |

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

Iteration 1 covers 28 claims. The prediction is 27 PASS and 22 GAP, so confidence is 27 / 49, about 55%. Planned iterations:

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

`sweep` revokes every unrevoked `scoperig-*` token. The next `run` does the same automatically.

The rig never writes token values to the report, errors or `gh` captures; all captured output is redacted.

## Corpus test and the oracle

The corpus test runs offline in `make test`. It checks the GraphQL analyzer against the queries `gh` actually sends, stored under `rig/corpus/gh/<version>/`:

```bash
go test ./internal/proxy -run GHCorpus
```

The spec describes a `scoperig oracle` command that captures queries from a new `gh` release. It is not implemented yet. Until then, capture with `GH_DEBUG=api` by hand and convert the captures with:

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
