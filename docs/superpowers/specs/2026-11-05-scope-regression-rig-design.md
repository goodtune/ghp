# Scope regression rig (`scoperig`): design

Date: 2026-11-05. Status: design, iteration 1. Target: GHP v0.23.0 at `https://ghp.touchtechnology.network` (repo at 63f1a39).

Inputs: `/tmp/ghp-rig/recon/consensus.md` (cited below as **CONS §A/B**), `/tmp/ghp-rig/recon/codebase-report.md` (claims **C1–C54**, section 4), `/tmp/ghp-rig/recon/env-report.md`, and the `gh` 2.102.0 captures in `/tmp/gh-queries/`.

## 1. Intent

GHP's value is one promise: a `ghx_` or `gha_` token can do what its profile allows and nothing more. Today nothing checks that promise against a real deployment. Unit tests cover the analyzer and handler in isolation. The e2e suite covers token CRUD only. No test drives real `gh` traffic (CONS §B6). Recon has already found doc-vs-code gaps (CONS §A1–A9).

`scoperig` is a periodic, deterministic, live check. It creates tokens with known profiles, sends real requests through the deployed instance, compares each result with what the docs claim, and reports per-claim status. Known defects are filed as GitHub issues once and then never re-triaged: their scenarios still run, but cannot FAIL. They only report whether today's behaviour is unchanged, fixed, or changed (section 3.6). A separate offline unit test keeps the GraphQL analyzer honest against the queries `gh` actually sends.

Token naming: the brief's "user tokens" are `ghx_` proxy tokens (backed by the user's OAuth credential). "Server tokens" are `gha_` agent tokens (backed by a GitHub App installation). No other type exists.

### Goals

- G1. Every documented scoping claim that can be tested periodically has a scenario tied to a claim ID.
- G2. A run is deterministic: same instance state and same scenarios give the same report.
- G3. "Friendly to `gh`" is a CI-enforced, offline property (corpus test), separate from the live rig.
- G4. Each run prints a confidence figure and a coverage-gap list, so progress toward 90% is visible.
- G5. Triage is procedural (skills): FAIL → issue → `known_issue` → skipped from then on.

### Non-goals (iteration 1)

- Git smart-HTTP (C48), agent tokens (C2, C49), enterprise exceptions (C50), border-policy reload (C45), expiry-after-wait (C41), anonymous git (C46), audit logs (C54), hard-delete (C42).
- Load or performance testing. Metrics scraping.
- Fixing product defects. The rig finds them. Fixes are separate PRs.

### Anti-goals (hard rules; the builder must enforce each one in code)

- Never print, log or write a token value (`ghpr_`, `ghx_`, `gha_`, `gho_`). Not in the report, not in errors, not in `gh` stderr captures. Redaction runs on all captured output.
- Never leave rig tokens alive after a run. Revocation runs on normal exit, on panic, and on SIGINT/SIGTERM.
- Never mutate a repository other than the write sandbox (`GHP_RIG_REPO_W`). Any write scenario whose target is not W fails validation at load time.
- Never send requests to `api.github.com` or `github.com` directly, except in oracle mode (`scoperig oracle`), which uses the operator's own `gh` login and only performs reads.
- Never create repositories unless the operator passes `--create-fixtures`.
- No network access except to the GHP instance (and GitHub in oracle mode).

## 2. Constraints (decided by the coordinator)

1. **Go, in this repo, pure Go (`CGO_ENABLED=0`).** Location: `tools/scoperig/` (`package main`). Reason: it is an operator test tool and must not ship in the release binary (goreleaser builds `./cmd/ghp` only). Build with `go build ./tools/scoperig`. One deterministic binary. Note: `make test`, `make vet` and `make lint` run over `./...` (Makefile:14-22), so `tools/scoperig` IS built, vetted, linted and unit-tested in CI. It must be clean under all three. Its unit tests (loader, validation, templating, redaction, roll-up and confidence, report rendering) are offline. The live path never runs under `go test`: *builder's call, fixed here as* the live-run integration test file carries the build tag `//go:build scoperig_live` and is excluded from `./...` by default.
2. **Data-driven.** Scenarios live in `rig/scenarios/*.yaml`, each tied to a claim ID, with token profile, request, expectation and `known_issue`. Scenarios with `known_issue` set never produce FAIL. *Coordinator's call (revised):* they still run, with an `observed:` block for today's behaviour beside `expect:` for the desired behaviour; outcomes are KNOWN / KNOWN-FIXED / KNOWN-CHANGED (section 3.6). `--skip-known` skips them entirely. Rationale: the owner's rule is "don't spend effort re-triaging logged issues", not "stay blind to fixes or regressions-of-regressions".
3. **Token lifecycle.** All tokens are created at run start through `POST /api/tokens` with the `ghpr_` session token from `GHP_SERVER_URL` / `GHP_USER_TOKEN` (the same env the `ghp` CLI uses). Every token carries `session_id: scoperig-<runid>`. All are revoked at the end through `DELETE /api/tokens/{id}`, also on panic and signal. A start-up sweep revokes any live token whose `session_id` starts with `scoperig-`. Token values are never printed.
4. **`gh` integration.** The real `gh` binary runs with `GH_HOST=<instance host>`, `GH_ENTERPRISE_TOKEN=<ghx_>`, `GH_REPO=<host>/<owner>/<repo>`, `GH_CONFIG_DIR=<tmp>`, `XDG_CACHE_HOME=<tmp>`. The working directory is a temp dir that is not a git checkout (CONS §B4: `GH_HOST` is ignored inside a github.com checkout). Config and cache are fresh per scenario, so feature-detection introspection queries are always sent. Oracle mode captures `gh` traffic with `GH_DEBUG=api`.
5. **Fixtures.** `GHP_RIG_REPO_A`, `GHP_RIG_REPO_B` (read), `GHP_RIG_REPO_W` (write sandbox). Defaults: `goodtune/ghp-scoperig-a`, `goodtune/ghp-scoperig-b`, `goodtune/ghp-scoperig-w`. `scoperig fixtures ensure` seeds them. Creating repos on the owner's account is a side effect that needs `--create-fixtures`. Write scenarios are idempotent and self-cleaning.
6. **gh-query corpus.** Sanitised captures under `rig/corpus/gh/<version>/<command>.json`. A unit test `internal/proxy/graphql_ghcorpus_test.go` runs each entry through `analyzeGraphQLRequest` and asserts a per-profile verdict. Currently-failing expectations carry `known_issue`.
7. **Output.** Human table on stdout and JSON via `--out`. Statuses PASS / FAIL / ERROR / KNOWN / KNOWN-FIXED / KNOWN-CHANGED (the last two are extensions of KNOWN, see decision 2). Non-zero exit only on FAIL, ERROR or KNOWN-CHANGED. A confidence line and a coverage-gap list on every run.
8. **Skills.** `.claude/skills/scope-rig-run/SKILL.md` and `.claude/skills/scope-rig-extend/SKILL.md`, following superpowers:writing-skills conventions.
9. **Iteration 1 scope** as listed in section 7. Roadmap in section 11.

## 3. Architecture

### 3.1 Layout

```
tools/scoperig/
  main.go            cobra root: run, fixtures ensure, sweep, oracle, validate
  config.go          env + flags -> Config; preflight
  scenario/          schema types, YAML loader, template expansion, static validation
  tokens/            Manager: sweep, create (paced), revoke-all, signal/defer cleanup
  fixtures/          discover + ensure (repo ids, issue/PR numbers, release id, branch)
  exec/              executors: rest.go, graphql.go, gh.go (one interface)
  expect/            matchers: status, body_contains, body_not_contains, header, json path
  report/            table + JSON writer, confidence, coverage gaps
  redact/            token-pattern scrubber applied to every captured byte
rig/
  claims.yaml        claim catalogue: id, doc reference, one-line claim, iteration
  profiles.yaml      token profile catalogue (section 3.3)
  scenarios/*.yaml   one file per area: repo.yaml, perm.yaml, open.yaml, graphql.yaml,
                     lifecycle.yaml, border.yaml, gh.yaml, gaps.yaml
  corpus/gh/2.102.0/<command>.json
internal/proxy/graphql_ghcorpus_test.go
.claude/skills/scope-rig-run/SKILL.md
.claude/skills/scope-rig-extend/SKILL.md
```

Executor interface:

```go
type Executor interface {
    Kind() string // "rest" | "graphql" | "gh"
    Run(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv) (Observation, error)
}
// Observation: status, headers (redacted), body (redacted, capped 64 KiB), gh exit code,
// gh stdout/stderr (redacted), and for gh, the list of HTTP exchanges parsed from GH_DEBUG=api.
// A non-nil error means rig problem -> ERROR, never FAIL.
```

`tokens.Handle` exposes `ID()` and an unexported value. The value is reachable only by the HTTP client's auth injection and the `gh` env builder. The builder must keep it out of `fmt` verbs (implement `String()` / `GoString()` / `MarshalJSON()` to return `ghx_[REDACTED:<id>]`).

### 3.2 Claim IDs

Stable scheme: `<AREA>-<Cnn>` reusing the recon numbers so cross-references stay valid. Areas: `TOK`, `REPO`, `PERM`, `OPEN`, `GQL`, `LIFE`, `BORDER`, `GIT`, `AGENT`, `ENT`, `GH`, `MISC`. Examples: `REPO-C05`, `GQL-C26`, `GH-C51`. Gap probes from CONS §A use `GAP-A1` … `GAP-A9`. A claim can have many scenarios. Scenario IDs are `<claim>.<slug>`, for example `GQL-C26.search-root`.

`rig/claims.yaml` lists every claim C1–C54 plus the GAP probes, with `iteration:` and `testable: periodic|manual|never`. Claims with `testable: never` (C42, C53) are excluded from the confidence denominator and listed separately.

### 3.2a Rig config (`rig/config.yaml`) (coordinator's call)

Instance settings live in one file, overridable by flags (`--config`, `--instance-host`, and so on), so a non-default instance needs a different config, not code changes:

```yaml
instance:
  host: ghp.touchtechnology.network          # GHES-style /api/v3 and /api/graphql
  management_host: ghp.touchtechnology.network  # /api/tokens, /login
  default_duration: 24h
  max_duration: 168h
  token_create_rate: 20/min                  # api.go:125; the manager paces at 75% of this
fixtures:
  repo_a: goodtune/ghp-scoperig-a
  repo_b: goodtune/ghp-scoperig-b
  repo_w: goodtune/ghp-scoperig-w
```

Env vars (section 3.8) override `fixtures`. Scenarios reference these values as `{{.Instance.DefaultDuration}}`, `{{.Instance.MaxDuration}}` and so on in `expect` and request bodies (for example C37 checks `expires_at` against now + `.Instance.DefaultDuration`; C38 requests `.Instance.MaxDuration` + 1h).

### 3.3 Token profile catalogue (`rig/profiles.yaml`)

Profiles are created once per run and shared across scenarios. Scopes use the enforcement names (`pull_requests`, not `pulls`; see CONS §A5).

| Profile | Type | Repos | Scopes | Used for |
|---|---|---|---|---|
| `open` | proxy | none | none | C7, C20, C21, fixtures discovery and cleanup, gh matrix |
| `perm-ro` | proxy | none | `contents:read,issues:read,pull_requests:read,metadata:read,actions:read` | C11, C13/C14 deny, C29, gh matrix |
| `perm-rw` | proxy | none | `contents:write,issues:write,pull_requests:write` | C12, C13/C14 allow, C16, C31 allow |
| `perm-issues-ro` | proxy | none | `issues:read` | C15, C29, C31 deny |
| `repo-A` | proxy | A | none | C5, C6, C10, C24–C28, gh matrix, A2/A3/A7 probes |
| `repo-AB` | proxy | A, B | none | C25 positive control, multi-repo REST |
| `repo-W` | proxy | W | none | C27 (mutation denied even on the sandbox) |
| `repo-A-perm-ro` | proxy | A | `contents:read,metadata:read` | combined repo + permission checks |
| `perm-contents-ro-W` | proxy | W | `contents:read` | A1 probe (write to unmapped endpoint) |
| `lifecycle-default` | proxy | none | none | C21, C37 (created with an empty body) |
| `lifecycle-revoke` | proxy | none | none | C40 (revoked mid-run) |

Profile schema:

```yaml
- name: repo-A-perm-ro
  type: proxy            # proxy | agent (agent is iteration 2)
  repositories: ["{{.RepoA}}"]
  scopes: "contents:read,metadata:read"
  duration: 2h           # always short; omitted only by lifecycle-default
```

The instance limits token creation to `instance.token_create_rate` (default 20 per minute per IP, `internal/server/api.go:125`). The token manager creates sequentially and paces at 75% of that rate. It retries a 429 once after 60 s. Scenarios that create their own tokens (C38) count toward the budget.

### 3.4 Scenario schema

Common fields:

```yaml
id: REPO-C05.other-repo-pulls
claim: REPO-C05
doc: docs/features/token-scoping.md#repository-restrictions
description: A token scoped to A cannot list pulls on B.
profile: repo-A
kind: rest                    # rest | graphql | gh | token_api
known_issue: ""               # GitHub issue URL; non-empty => observed: is required
observed: {}                  # today's behaviour, same matcher syntax as expect:
requires: []                  # capabilities: repo_w_push, repo_create, github_vhost, agent_installation
cleanup: []                   # requests run with profile `open` after the scenario, always
expect: {...}
```

Template variables (Go `text/template`, resolved before execution, never containing secrets): `.RunID`, `.Host`, `.RepoA`, `.RepoB`, `.RepoW` (`owner/name`), `.RepoA.Owner`, `.RepoA.Name`, `.RepoA.ID` (numeric), `.Fixture.<A|B|W>.IssueNumber|PRNumber|ReleaseID|Branch|Label`, and `.Step.<name>.<jsonpath>` for values captured from an earlier step in the same scenario.

`expect` fields (all optional, all must hold):

```yaml
expect:
  status: 403                 # or status_in: [404, 422]
  body_contains: ["Token is not scoped to"]
  body_not_contains: ["gho_", "ghu_"]
  header: {X-OAuth-Scopes: "repo"}
  json: {"$.login": "{{.Login}}"}
  ghp_denial: true            # body is a GHP denial (message matches the B3 catalogue),
                              # not a GitHub error; used to tell "GHP blocked" from "GitHub 404"
```

Write scenarios may declare `steps:` (an ordered list of requests, each with its own `expect` and optional `capture`). `cleanup` runs even after a failed step.

**REST:**

```yaml
id: PERM-C14.issues-write-allows-create
claim: PERM-C14
profile: perm-rw
kind: rest
steps:
  - name: create
    method: POST
    path: /repos/{{.RepoW}}/issues
    body: {title: "scoperig {{.RunID}} C14", body: "automated; closed immediately"}
    expect: {status: 201}
    capture: {number: "$.number"}
cleanup:
  - {method: PATCH, path: "/repos/{{.RepoW}}/issues/{{.Step.create.number}}", body: {state: closed}}
```

REST paths are sent under `/api/v3` on the instance host (the GHES-style route, `internal/server/server.go:455-456`). The client must send the path verbatim: set `URL.Opaque` or `URL.RawPath` so `..` and case survive (required for GAP-A7 and C10).

**GraphQL:**

```yaml
id: GQL-C28.mixed-literal-and-variable
claim: GQL-C28
profile: repo-A
kind: graphql
query: |
  query($o:String!,$n:String!){
    a: repository(owner:"{{.RepoA.Owner}}", name:"{{.RepoA.Name}}"){ name }
    b: repository(owner:$o, name:$n){ name }
  }
variables: {o: "{{.RepoA.Owner}}", n: "{{.RepoA.Name}}"}
expect:
  status: 403
  body_contains: ["literal string arguments"]
```

Sent as `POST /api/graphql`.

**gh:**

```yaml
id: GH-C51.pr-list.perm-ro
claim: GH-C51
profile: perm-ro
kind: gh
args: ["pr", "list", "--limit", "5"]
repo: A                       # sets GH_REPO=<host>/<RepoA>
expect:
  exit_code: 0
  stdout_contains: ["{{.Fixture.A.PRTitle}}"]
known_issue: ""               # filled after triage (CONS §A9 predicts failure)
```

On failure the report shows the first denied HTTP exchange parsed from `GH_DEBUG=api` (method, path, status, GHP message) so triage does not need a re-run. `gh` runs with a 60 s timeout.

**token_api** (for lifecycle claims):

```yaml
id: LIFE-C38.max-duration
claim: LIFE-C38
kind: token_api
request: {method: POST, path: /api/tokens, body: {type: proxy, duration: "200h", session_id: "scoperig-{{.RunID}}"}}
expect: {status: 400}
# If the server returns 201 the manager records the new id and revokes it with the rest.
```

### 3.5 Run sequence

1. Load and validate `claims.yaml`, `profiles.yaml` and every scenario (schema, unknown claim, unknown profile, write target not W, template errors). Validation errors exit 3 before any network call. `scoperig validate` runs only this step and is safe in CI.
2. Preflight: `GET <server>/login` must return 200 and contain `version`. `GET /api/tokens` with the session token must return 200. Any failure prints the reason and exits 3. No tokens are created.
3. Sweep: list tokens and revoke every live one whose `session_id` has the `scoperig-` prefix. The operator is the owner's own admin account (coordinator's call), so the sweep tries `GET /api/tokens?all=true` first; on 403 or an empty result it falls back to `GET /api/tokens` (own tokens). Entries with `revoked_at` set are filtered out before revoking.
4. Create profile tokens (paced). Register cleanup (defer + `signal.NotifyContext` for SIGINT/SIGTERM).
5. Capability probe with `open` (coordinator's call): `GET /user` (identity, sets `.Login`); `GET /repos/{RepoW}` (exists, and `permissions.push` true gives `repo_w_push`); `GET /api/v3/` and read `X-OAuth-Scopes` (passed through for open tokens; `repo` or `public_repo` scope plus a user-owned target gives `repo_create`). `github_vhost` and `agent_installation` as in section 7. Missing capabilities do not cause ERROR: dependent scenarios become coverage gaps with the reason.
6. Discover fixtures with `open` (repo ids, the seeded issue, PR, release, label, branch). A missing fixture is ERROR for the scenarios that need it, with a hint to run `fixtures ensure`.
7. Run scenarios sequentially, sorted by ID. Known scenarios run too (unless `--skip-known`) and are classified per section 3.6. Unmet `requires` → the scenario is not run and its claim goes to the gap list with the reason.
8. Revoke all tokens. Verify with `GET /api/tokens` that no token from this run is still active (entries with `revoked_at` set are ignored). A failed revoke prints the token **id** (never the value) and turns the run result into ERROR.
9. Write the report and exit.

Determinism rules: sequential execution, sorted order, per-scenario fresh `gh` config/cache, no retries on product responses (only on transport errors, once), fixed timeouts (REST 30 s, gh 60 s), and the report table does not include timings.

### 3.6 Report

Stdout:

```
scoperig run 20261105T0412Z-7f3a  instance=ghp.touchtechnology.network (0.23.0)  scenarios=96

CLAIM       SCENARIO                                   STATUS  DETAIL
REPO-C05    REPO-C05.other-repo-pulls                  PASS    403 Token is not scoped to goodtune/ghp-scoperig-b
REPO-C10    REPO-C10.case-insensitive                  PASS    200
GH-C51      GH-C51.pr-list.perm-ro                     KNOWN   https://github.com/goodtune/ghp/issues/NNN
GAP-A1      GAP-A1.delete-ref-contents-ro              KNOWN   https://github.com/goodtune/ghp/issues/NNN
GQL-C33     GQL-C33.unknown-object-field               FAIL    want 403, got 200
LIFE-C40    LIFE-C40.revoked-rejected                  ERROR   revoke call failed: 500

changed (1): GAP-A7.dotdot-path  KNOWN-CHANGED  observed 200, desired 403/404, got 401
claims: 25 PASS, 1 FAIL, 1 KNOWN, 23 GAP   manual: C45 C54   untestable: C42 C53
confidence: 25/(50-1) = 51.0%   (PASS / (base - KNOWN))
coverage gaps (14): C2 C3 C4 C8 C9 C17 C18 C19 C22 C23 C30 C34 C35 C36 ...
tokens: 11 created, 11 revoked, 0 leftover
```

Known-scenario outcomes (coordinator's call; mirrors the corpus `current` field in section 6 so both surfaces agree):

| Result | Condition | Exit effect |
|---|---|---|
| KNOWN | `observed:` matches | none |
| KNOWN-FIXED | `expect:` now holds | none; report says "remove `known_issue` and `observed:` from <scenario>" |
| KNOWN-CHANGED | neither matches | non-zero (new information); shown in a separate "changed" section at the top |

Claim roll-up and confidence (coordinator's call, fixed and unit-tested in `report/confidence_test.go`):

- base = claims whose `testable` is not `never` or `manual`.
- Claim status: FAIL if any scenario is FAIL, ERROR or KNOWN-CHANGED; else KNOWN if any is KNOWN or KNOWN-FIXED; else PASS if all runnable scenarios PASS; else GAP (no runnable scenarios, including unmet `requires`).
- confidence = PASS / (base − KNOWN).
- Manual claims (C45, C54) are listed separately as "manual" and are not in base. `never` claims (C42, C53) are listed as "untestable".
- GAP probes (A1–A9) are reported but excluded from base (they are defect evidence, not doc claims).

JSON (`--out report.json`): `{run_id, started_at, instance, ghp_version, gh_version, rig_commit, summary{pass,fail,known,error,confidence}, coverage_gaps[], claims[{id, status, scenarios[{id, status, known_issue, observation{status, ghp_message, gh_exit, first_denied_exchange}, error}]}], tokens{created, revoked, leftover_ids[]}}`. Scenario order is sorted. No token values.

### 3.7 Exit codes

| Code | Meaning |
|---|---|
| 0 | No FAIL, no ERROR (KNOWN allowed) |
| 1 | At least one FAIL or KNOWN-CHANGED |
| 2 | At least one ERROR (and no FAIL), including cleanup failure |
| 3 | Could not start: config/validation error, instance unreachable, session token rejected |

### 3.8 Environment and flags

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GHP_SERVER_URL` | yes | none | Instance base URL, for example `https://ghp.touchtechnology.network` |
| `GHP_USER_TOKEN` | yes | none | `ghpr_` session token for `/api/tokens` |
| `GHP_RIG_REPO_A` | no | `goodtune/ghp-scoperig-a` | Read fixture A |
| `GHP_RIG_REPO_B` | no | `goodtune/ghp-scoperig-b` | Read fixture B (the "other" repo) |
| `GHP_RIG_REPO_W` | no | `goodtune/ghp-scoperig-w` | Write sandbox; the only repo the rig mutates |
| `GHP_RIG_GH` | no | `gh` on `PATH` | Path to the `gh` binary |
| `GHP_RIG_SCENARIOS` | no | `rig/` | Root of claims, profiles, scenarios |
| `GHP_RIG_INSTALLATION_ID` | no | none | Enables `agent_installation` capability (A6 probe; iteration 2 scenarios) |
| `GHP_RIG_CA_FILE` | no | system pool | Extra CA bundle (homelab root CA) |

Flags: `--config FILE` (default `rig/config.yaml`), `--skip-known`, `--out FILE`, `--only GLOB` (scenario ID filter; still sweeps and cleans up), `--create-fixtures` (on `fixtures ensure`), `--keep-going` (default true), `--verbose` (prints redacted exchanges).

## 4. Fixtures

`scoperig fixtures ensure [--create-fixtures]` runs through GHP with a temporary `open` token (created and revoked by the same manager), so the rig never needs a direct GitHub credential.

For each of A, B, W:
- If the repo is missing: without `--create-fixtures`, print what would be created and exit 3. With it, and only if the capability probe found `repo_create`, `POST /user/repos` (private, `auto_init: true`). Without `repo_create` it refuses and prints out-of-band instructions (create the three private repos by hand or with `gh repo create --private` under your own login, then re-run `fixtures ensure` to seed).
- Seed, idempotently, keyed by fixed names: README (from `auto_init`), label `scoperig`, issue titled `scoperig fixture issue` (open), branch `scoperig-fixture` with one commit adding `fixture.txt`, PR titled `scoperig fixture PR` from that branch (open), release `scoperig-fixture-v0` on the default branch.
- Print the discovered values (repo ids, numbers). These are the template variables the run uses.

W also receives these seeds so that write scenarios have stable parents. Write scenarios create only uniquely named objects (`scoperig-{{.RunID}}-*`) and remove or close them in `cleanup`.

## 5. Oracle and corpus flow

`scoperig oracle --gh-version auto --repo cli/cli` (operator-run, after a `gh` upgrade):
1. For each command in the gh matrix, run `gh` with `GH_DEBUG=api`, a fresh `GH_CONFIG_DIR` copied from the operator's real `gh` auth (read-only), and a fresh `XDG_CACHE_HOME`, against `github.com`. Read commands only.
2. Parse each GraphQL request (query, variables, operationName) and REST request line from the debug log.
3. Sanitise: drop all headers except `User-Agent` and `X-Github-Api-Version`; drop responses; replace concrete owner/repo/number values in variables with stable placeholders (`OWNER`, `REPO`, `1`); refuse to write if any token pattern survives.
4. Write `rig/corpus/gh/<version>/<command>.json`. If expectations exist for the previous version, copy them forward as the starting point and print a diff of operations and field names.

The seed corpus for 2.102.0 is produced from `/tmp/gh-queries/*.txt` with the same parser (the builder writes it once; `index.json` documents the shapes).

## 6. Corpus unit test

File: `internal/proxy/graphql_ghcorpus_test.go`. Offline, runs in `make test`.

Corpus entry format:

```json
{
  "gh_version": "2.102.0",
  "command": "pr list",
  "rest": ["GET /repos/OWNER/REPO/readme"],
  "graphql": [
    {
      "operation": "PullRequestList",
      "body": {"query": "query PullRequestList(...) {...}", "variables": {"owner":"OWNER","repo":"REPO","limit":30,"state":["OPEN"]}, "operationName": "PullRequestList"},
      "expect": {
        "open":      {"verdict": "allow"},
        "perm-ro":   {"verdict": "allow", "known_issue": "https://github.com/goodtune/ghp/issues/NNN", "current": "deny:unmapped"},
        "repo":      {"verdict": "allow", "known_issue": "https://github.com/goodtune/ghp/issues/NNN", "current": "deny:unpinned"}
      }
    }
  ]
}
```

- `verdict` is the desired product behaviour. `current` is required when `known_issue` is set and records today's behaviour.
- Verdict vocabulary: `allow`, `parse`, `deny:subscription`, `deny:unmapped`, `deny:cross_repo`, `deny:mutation_repo`, `deny:unpinned`, `deny:no_repo_ref`, `deny:repo_not_allowed`, `deny:missing_scope`, `deny:mutation_unscoped`.
- Test profiles (fixed in the test): `open` (no repos, no scopes), `perm-ro` (same scopes as the live profile), `repo` (repos `[OWNER/REPO]`, no scopes).

Invocation. `analyzeGraphQLRequest(body []byte)` (`internal/proxy/graphql.go:402`) returns a `graphQLAnalysis` (`graphql.go:28-62`). The allow/deny decision lives inline in `ServeHTTP` (`internal/proxy/proxy.go:~455-580`: subscription, unknown fields, then for repo-restricted tokens cross-repo, mutation, unpinned, no reference, allowlist; then scope checks via `satisfiedBy`/`missingScopes`, `graphql.go:699-711`). The builder must extract that sequence into one pure function called by both `ServeHTTP` and the test:

```go
type graphQLDecision struct {
    Allow   bool
    Status  int    // 403, 400 (parse), 413, ...; 0 when Allow
    Message string // exact text passed to writeGraphQLError today
    Reason  string // verdict vocabulary below, e.g. "deny:unpinned"
    Repo    string // repo for logRequest when the denial names one
    Stage   string // metrics stage reached (scope_parsing / scope_enforcement)
}
func graphQLVerdict(body []byte, si tokenScopeInfo) graphQLDecision
```

Requirements:
- Parameter type is the existing `tokenScopeInfo`.
- It includes the open-scoped shortcut (`proxy.go:396-404`), so the corpus `open` profile exercises the real path and returns `allow` without analysis.
- Parse errors (400 at `proxy.go:439-449`) return Reason `parse`, a separate outcome, not a 403 verdict.
- The handler keeps identical `metrics.ObserveDecision` and `h.logRequest` calls, driven by `Stage`, `Status`, `Repo` and `Message`.
- The refactor is covered by the existing handler tests (`TestServeHTTP_GraphQL_*`), which must pass unchanged. It lands as its own commit before the corpus test commit.
- The test must not reimplement the decision.

Assertions per entry and profile:
- No `known_issue`: `got == verdict`, else fail with the analyzer's unknown/cross-repo field lists.
- `known_issue` set: `got == current` passes (KNOWN). `got == verdict` fails with "fixed; remove known_issue and current" (the KNOWN-FIXED case; a hard failure here because CI should force the corpus update). Neither fails with "changed" (KNOWN-CHANGED). Same semantics as the live rig's `observed:`.

Also a structural test: every file under `rig/corpus/gh/*/` parses, has expectations for all three profiles, and contains no token pattern.

Initial expectations come from CONS §A9: `open` allows everything; `perm-ro` allows `RepositoryInfo`, `viewer` and `RepositoryReleaseList` and currently denies the rest as `deny:unmapped`; `repo` currently denies every variable-driven query as `deny:unpinned` and `pr status`/`pr checks` as cross-repo. The desired `verdict` for `repo` on `search`/root `node` stays `deny:cross_repo` (by design, CONS §A9); for variable-driven repo lookups the desired verdict is an open product question, recorded as `known_issue` pointing to the A9 issue.

## 7. Iteration 1: claim to scenario mapping

"Expect" is today's predicted result against v0.23.0. KNOWN-expected rows will fail on the first run, be triaged into issues, then carry `known_issue` plus an `observed:` block recording the behaviour seen. Write scenarios (C12, C13 allow, C14 allow, C31 allow) declare `requires: [repo_w_push]`.

| Claim | Profile(s) | Request | Expected outcome | Expect |
|---|---|---|---|---|
| REPO-C05 | repo-A | `GET /repos/B/pulls` | 403, `Token is not scoped to B`, `ghp_denial` | PASS |
| REPO-C06 | repo-A, repo-AB | `GET /repos/A`, `GET /repos/A/pulls`; AB also `GET /repos/B` | 200 | PASS |
| REPO-C07 | open | `GET /repos/A`, `GET /repos/B` | 200 both | PASS |
| REPO-C10 | repo-A | `GET /repos/<OWNER upper>/<name upper>` | 200 | PASS |
| PERM-C11 | perm-ro | `PUT /repos/W/contents/scoperig-<run>.txt` | 403 `contents:write` | PASS |
| PERM-C12 | perm-rw | PUT contents on W (201), cleanup `DELETE` with captured sha | 201 | PASS |
| PERM-C13 | perm-ro / perm-rw | `POST /repos/W/pulls` from fixture branch to a run branch (rw creates ref first, cleanup closes PR and deletes ref with `open`) | ro 403 `pull_requests:write`; rw 201 | PASS |
| PERM-C14 | perm-ro / perm-rw | `POST /repos/W/issues`; rw closes it | ro 403; rw 201 | PASS |
| PERM-C15 | perm-issues-ro | `GET /repos/A`, `GET /user` | 200 both | PASS |
| PERM-C16 | perm-rw | `GET /repos/W/contents/README.md` | 200 | PASS |
| OPEN-C20 | open | `GET /user`, `GET /repos/A/readme`, `GET /rate_limit` | 200; `$.login` equals the session user | PASS |
| OPEN-C21 | lifecycle-default | token_api create with only `session_id` | 201, `repositories` and `scopes` null | PASS |
| GQL-C24 | repo-A | `{viewer{login}}` | 403 `must reference repository(owner, name)` | PASS |
| GQL-C25 | repo-A; repo-AB control | literal `repository(B)`; AB with A and B literals | A: 403 `not scoped to B`; AB: 200 | PASS |
| GQL-C26 | repo-A | root `search`, root `node(id:)`, `viewer{repositories}` (3 scenarios), plus an aliased `search` | 403 `cross-repository fields` | PASS |
| GQL-C27 | repo-W | `createIssue` mutation (never reaches GitHub) | 403 `mutations are not supported` | PASS |
| GQL-C28 | repo-A | variable-only lookup; mixed literal + variable | 403 `literal string arguments` | PASS |
| GQL-C29 | perm-issues-ro | literal repo A `pullRequests(first:1){nodes{number}}` | 403 naming `pull_requests:read` | PASS |
| GQL-C31 | perm-issues-ro / perm-rw | `createIssue` on W (repositoryId from a prior query); rw closes the issue via REST cleanup | ro 403; rw 200 without `errors` | PASS |
| GQL-C32 | perm-ro | `subscription{...}` | 403 | PASS |
| GQL-C33 | perm-ro | `repository(owner:"A",name:"a"){foo{bar}}` | 403 `unmapped fields: foo` | PASS |
| LIFE-C37 | lifecycle-default | inspect create response | `expires_at` within now + `.Instance.DefaultDuration` ±2 min | PASS |
| LIFE-C38 | none (token_api) | create with `duration` = `.Instance.MaxDuration` + 1h | 400 | PASS |
| LIFE-C40 | lifecycle-revoke | 200 on `GET /user`; `DELETE /api/tokens/{id}`; poll `GET /user` every 2 s up to 35 s | 401 `token has been revoked` within 35 s (30 s cache, CONS §B3) | PASS |
| BORDER-C43 | raw header | `Authorization: token ghp_` + 36 fake chars, `GET /api/v3/user`; repeat for `gho_`, `github_pat_` | 403 border-policy message; not GitHub's 401 | PASS |
| BORDER-C44 | open | `GET /user` | 200 (ghx_ accepted) | PASS |
| MISC-C52 | repo-A | `GET /api/v3/` | 200 with `X-OAuth-Scopes` present (synthetic) | PASS |
| GH-C51 | open, perm-ro, repo-A | gh matrix below | see below | mixed |
| GAP-A1 | perm-contents-ro-W | `DELETE /repos/W/git/refs/heads/scoperig-absent-<run>` (ref never exists, so a forwarded request is harmless) | desired 403 `ghp_denial`; today GitHub 422 | KNOWN |
| GAP-A2 | repo-A | `GET /repositories/{RepoB.ID}` | desired 403; today 200 | KNOWN |
| GAP-A3 | repo-A | `GET https://github.com/B/archive/HEAD.tar.gz` via the github.com vhost; `requires: [github_vhost]` | desired 403; today forwarded | KNOWN |
| GAP-A6 | agent | create a `gha_` token for A; `requires: [agent_installation]` | desired 201; record mint result | KNOWN (or gap) |
| GAP-A7 | repo-A | `GET /repos/A/../../B/contents/README.md`, path sent verbatim | desired 403 or 404 with no B content; today unverified | KNOWN if B content returned, else PASS |

gh matrix (`GH-C51`, 11 commands × 3 profiles = 33 scenarios): `repo view`, `pr list`, `pr view <fixture PR>`, `pr status`, `pr checks <fixture PR>`, `issue list`, `issue view <fixture issue>`, `release list`, `label list`, `run list`, `api graphql -f query='{viewer{login}}'`. All run with `GH_REPO=<host>/<RepoA>`. Expectation for every cell: exit 0 and stdout contains the fixture's title or name.

Predicted results (CONS §A9):
- `open`: all PASS.
- `perm-ro`: PASS for `repo view` (note: its REST `/readme` is unmapped and forwarded, which is A1 evidence, not a gh failure), `run list`, `api viewer`; `release list` FAIL on a fresh cache (introspection `fields` unmapped). `pr list`, `pr view`, `pr status`, `pr checks`, `issue list`, `issue view`, `label list` FAIL. All become KNOWN against the A9 issue(s).
- `repo-A`: PASS for `run list`; every GraphQL-backed command FAIL (unpinned lookup), `api viewer` FAIL (no repo reference, correct per C24, so its expectation is exit non-zero with the C24 message, PASS). The rest become KNOWN.

`requires` capabilities: `github_vhost` is detected by a preflight TLS dial to the instance address with SNI `github.com` (instance CA); if the handshake or a `GET /` fails, the capability is absent. `agent_installation` is present when `GHP_RIG_INSTALLATION_ID` is set and the session is admin.

## 8. Safety

### Side-effect inventory

| Action | Where | Token | Undo |
|---|---|---|---|
| Create/revoke tokens | GHP DB | `ghpr_` session | Revoke at end; sweep at next start |
| Create repos A, B, W | owner's GitHub account | `open` ghx_ | Manual; only with `--create-fixtures` |
| Seed issue, PR, branch, release, label | A, B, W | `open` | Persistent by design; idempotent |
| Create/delete file `scoperig-<run>.txt` | W | `perm-rw`; cleanup `open` | DELETE in cleanup |
| Create/close issue | W | `perm-rw`; cleanup `open` | Closed (GitHub cannot delete issues via REST; closed issues accumulate, titled with run id) |
| Create ref + PR, close PR, delete ref | W | `perm-rw`; cleanup `open` | Closed PR remains; ref deleted |
| Forwarded A1 probe | W, absent ref | `perm-contents-ro-W` | Nothing to undo |
| Audit log rows | GHP | all | None; tagged with `scoperig-<run>` session id |
| GitHub API quota | owner's OAuth credential | all | ~200 calls per run; well inside 5000/h |

### Cleanup guarantees

- Token revocation (sweep and leftover check skip entries with `revoked_at` set): deferred in `main`, also triggered by `signal.NotifyContext`. A second signal aborts cleanup and prints the ids that remain (the next run's sweep revokes them). `SIGKILL` cannot be handled; the sweep and the 2 h profile duration bound the exposure.
- Repo cleanup: per-scenario `cleanup` runs with `open`, even if steps fail. Cleanup failures are ERROR for that scenario and are listed under "residue" in the report with object URLs.
- Static validation refuses any non-GET request whose path does not target `/repos/{{.RepoW}}/...`. Exceptions: the GAP-A1 probe, `fixtures ensure`, and `token_api` scenarios (they target `/api/tokens` on the management host, never `/repos/`; validation checks that their path starts with `/api/tokens`).
- Sweep and the end-of-run leftover check ignore tokens with `revoked_at` set.

### Instance unreachable or degraded

- Preflight failure: exit 3, no tokens created, nothing to clean up.
- Failure mid-run: each remaining scenario is ERROR with the transport error. The run still attempts revocation; if revocation fails, the report lists token ids and exits 2. The next run's sweep finishes the job.
- A 5xx from GHP is ERROR, not FAIL, unless the scenario explicitly expects it.

## 9. Skills

**`.claude/skills/scope-rig-run/SKILL.md`** (frontmatter `name: scope-rig-run`, `description: Use when running the GHP scope regression rig, reading its report, or triaging a FAIL into a GitHub issue`). Steps:
1. Build: `CGO_ENABLED=0 go build -o /tmp/scoperig ./tools/scoperig`.
2. Env: `GHP_SERVER_URL`, `GHP_USER_TOKEN` (from the `ghp` CLI config). Never echo them.
3. `scoperig validate`, then `scoperig run --out /tmp/scoperig-report.json`.
4. Exit 3: fix config or instance. Exit 2: rig problem; read ERROR detail, fix the rig, do not file a product issue. Exit 1: triage each FAIL.
5. Triage one FAIL: confirm it reproduces with `--only <scenario id>`; search existing issues (`gh issue list -R goodtune/ghp --search "<claim id>"`); file with the template below; set `known_issue:` and an `observed:` block (today's behaviour) on the scenario. For KNOWN-FIXED: remove both and confirm PASS. For KNOWN-CHANGED: comment on the issue with the new observation and update `observed:` (and on matching corpus expectations); re-run `--only` to confirm KNOWN; open a PR for the scenario change. If the fix is small and clear, open a separate fix PR that removes `known_issue`.
6. Issue template: title `scoperig: <claim id> <one-line claim> fails`; body sections Claim (doc link), Scenario id and profile (no token values), Expected, Observed (status, GHP message, first denied gh exchange), Code pointer (file:line), Instance version, Run id. Label `scoperig`.

**`.claude/skills/scope-rig-extend/SKILL.md`** (`description: Use when adding a scope-rig scenario for a documented claim, refreshing the gh query corpus after a gh upgrade, or adding GraphQL analyzer table entries`). Steps:
1. New scenario: find the claim in `rig/claims.yaml` (add it if missing, with doc anchor); pick an existing profile (add one only if no profile fits, keep tokens under the create budget); copy the closest scenario; write targets only W; add `cleanup`; `scoperig validate`; `scoperig run --only <id>`.
2. gh upgrade: `scoperig oracle`; review the diff; for every new denied field follow CLAUDE.md "GraphQL Scope Mapping" (pick the table, prefer stricter); update corpus expectations; `go test ./internal/proxy -run GHCorpus`.
3. Analyzer fix: add the table entry and the unit test CLAUDE.md requires; then in the corpus set `verdict` and remove `known_issue`/`current` where the test reports "fixed".

## 10. Left to the builder

- The `graphQLVerdict` extraction from `proxy.go` (no behaviour change, own commit, section 6) and its use in the corpus test.
- The `scoperig_live` build-tagged integration test, and keeping `tools/scoperig` clean under `make test`, `make vet` and `make lint`.
- The capture parser for `GH_DEBUG=api` output (shared by oracle and gh failure detail) and the one-off conversion of `/tmp/gh-queries/*.txt` into the 2.102.0 corpus.
- Exact GHP denial message catalogue for `ghp_denial` (from `proxy.go` and CONS §B3).
- The redaction regexes (`gh[oupsrx]_`, `gha_`, `ghpr_`, `github_pat_`), and a unit test that feeds every executor's output through them.
- How to obtain `.Login` (from `GET /user` with `open`) and the numeric repo IDs.
- The exact REST body for GAP-A3 on the github.com vhost and the `github_vhost` probe.
- `make scoperig` and `make scoperig-validate` targets; adding `scoperig validate` and the corpus test to CI (`.github/workflows/test.yml`). The live run is not in CI.
- A short operator page `docs/development/scope-rig.md` linking the skills (only if the owner wants it in the docs site).
- Filing the initial issues for CONS §A1–A9 and back-filling `known_issue` after the first run.

## 11. Roadmap to 90%

Base: C1–C54 = 54, minus `never` (C42, C53) and `manual` (C45, C54) = **50**.

Iteration-1 estimate with the section 3.6 formula: 27 claims get scenarios. Of these, GH-C51 is predicted KNOWN (its scoped gh cells fail per CONS §A9) and the other 26 are predicted PASS. The remaining 23 claims are GAP. Confidence = 26 / (50 − 1) = 26 / 49 ≈ **53%**. If any predicted PASS turns out FAIL, each costs about 2 points.

| Iteration | Adds | Claims newly covered | Target confidence |
|---|---|---|---|
| 1 (this doc) | Runner, token lifecycle, REST/GraphQL/gh/token_api kinds, fixtures, report, corpus test, skills | C5–C7, C10–C16, C20, C21, C24–C29, C31–C33, C37, C38, C40, C43, C44, C51, C52 (27) + GAP A1, A2, A3, A6, A7 | ~53% (26/49) |
| 2 | `git` kind (ls-remote, fetch, push --dry-run via `GIT_ASKPASS`, with and without `.git`); `gha_` agent profiles and minting; remaining GraphQL claims; C1 header/body scan on every response | C1, C2, C3, C4, C8, C9, C17, C18, C19, C22, C23, C30, C34, C35, C36, C47, C48, C49 | ~70% |
| 3 | Long-wait kind for expiry (C41, `1m` token); C39 (needs config knowledge, read from a `requires: allow_no_expiry` capability); anonymous git (C46); enterprise exceptions with an upstream echo or off-enterprise repo (C50); scheduled runs | C39, C41, C46, C50 | ~80% |
| 4 | Operator hooks: SIGUSR1 reload check (C45) and audit-log assertion (C54) via an optional SSH or log-endpoint capability; oracle "matches direct GitHub" comparisons for open tokens; corpus extended to write commands (`pr create`, `issue create`, `pr comment`) captured against W | C45, C54, deeper C20/C51 | 90%+ (with fixed KNOWN items no longer excluded) |

Confidence rises both by adding scenarios and by fixing KNOWN issues: each fix removes `known_issue`, so the claim returns to the denominator and must PASS.
