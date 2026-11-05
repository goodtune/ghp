# Scope Regression Rig (`scoperig`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build iteration 1 of `scoperig`. It is a live, deterministic checker that creates `ghx_` tokens with known profiles, sends REST, GraphQL, `gh` and token-API requests through a deployed GHP instance, and reports per-claim PASS/FAIL/KNOWN. It also adds an offline corpus test that pins the GraphQL analyzer against real `gh` 2.102.0 queries.

**Architecture:** A pure-function extraction (`graphQLVerdict`) of the GraphQL allow/deny chain in `internal/proxy/proxy.go` is shared by the handler and a new offline corpus test. The live rig is a separate `package main` under `tools/scoperig/`, with small sub-packages (scenario, tokens, fixtures, exec, expect, report, redact, ghdebug). It is driven by YAML data under `rig/`. It is not part of the release binary.

**Tech Stack:** Go 1.24, cobra, `gopkg.in/yaml.v3` (already in go.mod), `net/http`, `os/exec` for `gh`, `text/template`. No new modules.

**Spec:** `docs/superpowers/specs/2026-11-05-scope-regression-rig-design.md` (authoritative). Section numbers below (`§3.4` etc.) refer to it. Read it with this plan.

## Global Constraints

- `CGO_ENABLED=0`. Pure Go. No new third-party modules.
- `tools/scoperig` is built, vetted, linted and unit-tested by `make test` / `make vet` / `make lint` (they run over `./...`). It must be clean under all three.
- Live tests carry `//go:build scoperig_live`. Nothing under plain `go test ./...` makes a network call outside `httptest`.
- Never print, log or write a token value (`ghpr_`, `ghx_`, `gha_`, `gho_`, `ghu_`, `ghs_`, `ghp_`, `github_pat_`). `tokens.Handle` formats as `ghx_[REDACTED:<id>]`.
- Every rig token has `session_id: scoperig-<runid>` and `duration` ≤ `2h` (except `lifecycle-default`, which has no duration).
- Only `GHP_RIG_REPO_W` may be mutated. Validation rejects any non-GET request outside `/repos/{{.RepoW}}/...`, with the exceptions in §8 (GAP-A1 probe, `fixtures ensure`, `token_api` scenarios on `/api/tokens`).
- Repositories are created only by `scoperig fixtures ensure --create-fixtures`.
- Token creation is sequential and paced at 75% of `instance.token_create_rate` (default `20/min`, so one create per 4 s). Retry a 429 once after 60 s.
- Timeouts: REST 30 s, `gh` 60 s. Retries only on transport errors, once.
- Statuses: `PASS FAIL ERROR KNOWN KNOWN-FIXED KNOWN-CHANGED`. Exit codes: 0 clean, 1 FAIL or KNOWN-CHANGED, 2 ERROR (no FAIL), 3 cannot start.
- confidence = PASS / (base − KNOWN), where base = claims with `testable: periodic` (not `manual`/`never`), excluding `GAP-*`.
- Reports are never checked in. Default report path is none (stdout only). The live run writes to `/tmp/ghp-rig/reports/`. `rig/reports/` is in `.gitignore`.
- Known-issue links: A1 #290, A2 #291, A3+A4 #292, A5 #293, A6 #294, A7 #295, A8 #296, A9(i) unpinned #297, A9(ii) unmapped gh fields #298, A9(iii) `__typename` at mutation root #299 (all `https://github.com/goodtune/ghp/issues/NNN`).
- Code style per CLAUDE.md: gofmt, table-driven tests with `t.Run`, explicit error handling.

## Review Focus

1. **Token value leaks through error paths.** A failed create or a `gh` stderr that echoes `GH_ENTERPRISE_TOKEN` must not show the value. Test: `TestRedact_ExecutorOutputs` (Task 2) and `TestHandle_NeverFormatsValue` (Task 11).
2. **Cleanup after a mid-run crash or SIGINT.** Tokens created before a panic must still be revoked. Test: `TestManager_RevokeAllAfterPanic` (Task 11) and `TestRun_SignalTriggersRevoke` (Task 16).
3. **A known scenario whose behaviour changed.** It must become KNOWN-CHANGED and exit 1, not silently stay KNOWN. Test: `TestClassify_Known` (Task 10), `TestCorpus_KnownChanged` semantics (Task 5).
4. **Paths with `..`, upper case or `%2e`.** These must reach the instance verbatim (GAP-A7, REPO-C10). Test: `TestREST_SendsPathVerbatim` (Task 14).
5. **A write scenario that targets A or B by mistake.** It must fail validation before any network call. Test: `TestValidate_WriteOutsideW` (Task 7).

## Dependencies

Execution waves (tasks in one wave can run in parallel; parentheses list hard dependencies):

| Wave | Tasks |
|---|---|
| 1 | T1, T2, T6 |
| 2 | T3 (T2), T7 (T6) |
| 3 | T4 (T3), T8 (T7), T9 (T3, T6), T11 (T2, T7), T13 (T7) |
| 4 | T5 (T1, T4), T10 (T9), T12 (T7, T11; creates the `main.go` stub) |
| 5 | T14 |
| 6 | T15 |
| 7 | T16 |
| 8 | T17 ∥ T18 |
| 9 | T19, then T20 (both edit `rigtree_test.go`; T19 changes scenario types) |
| 10 | T21 ∥ T22 ∥ T23 |
| 11 | T24 |

Each task is one commit. T1 and T5 are separate commits (spec §6).

## File Structure

```
internal/proxy/graphql_verdict.go          T1  graphQLDecision, graphQLVerdict
internal/proxy/graphql_verdict_test.go     T1
internal/proxy/proxy.go                    T1  handleGraphQL uses graphQLVerdict
internal/proxy/graphql_ghcorpus_test.go    T5
tools/scoperig/redact/redact.go            T2
tools/scoperig/ghdebug/parse.go            T3  GH_DEBUG=api parser
tools/scoperig/ghdebug/sanitise.go         T3
tools/scoperig/corpus/corpus.go            T4  corpus JSON types (shared by importer, oracle)
tools/scoperig/corpus/importghdebug/main.go T4 deterministic generator
rig/corpus/gh/2.102.0/*.json               T4
tools/scoperig/scenario/{types,load,validate,template}.go  T6, T7
rig/{config,claims,profiles}.yaml          T8
tools/scoperig/expect/expect.go            T9
tools/scoperig/report/{rollup,confidence,render}.go  T10
tools/scoperig/tokens/{handle,manager}.go  T11
tools/scoperig/config.go, preflight.go     T12
tools/scoperig/fixtures/fixtures.go        T13
tools/scoperig/exec/{exec,rest,graphql,tokenapi,gh}.go  T14, T15
tools/scoperig/main.go, run.go             T16
tools/scoperig/oracle.go                   T17
rig/scenarios/{repo,perm,open,lifecycle,border,misc}.yaml  T18
rig/scenarios/{graphql,gaps}.yaml          T19
rig/scenarios/gh.yaml                      T20
tools/scoperig/live_test.go                T21 (//go:build scoperig_live)
Makefile, .github/workflows/test.yml, .gitignore  T21
.claude/skills/scope-rig-run/SKILL.md      T22
.claude/skills/scope-rig-extend/SKILL.md   T22
docs/development/scope-regression-rig.md, mkdocs.yml  T23
```

Note: the `internal/proxy` corpus test must not import `tools/scoperig/corpus`. The corpus test declares its own small decode structs (Task 5). The `corpus` package in `tools/` is for the importer and oracle only.

---

### Task 1: Extract `graphQLVerdict` from `handleGraphQL` (no behaviour change)

**Depends on:** none

**Files:**
- Create: `internal/proxy/graphql_verdict.go`
- Create: `internal/proxy/graphql_verdict_test.go`
- Modify: `internal/proxy/proxy.go:380-581` (`handleGraphQL`)

**Interfaces:**
- Produces:

```go
// Reason values (verdict vocabulary, spec §6).
const (
    reasonAllow             = "allow"
    reasonParse             = "parse"
    reasonSubscription      = "deny:subscription"
    reasonUnmapped          = "deny:unmapped"
    reasonCrossRepo         = "deny:cross_repo"
    reasonMutationRepo      = "deny:mutation_repo"
    reasonUnpinned          = "deny:unpinned"
    reasonNoRepoRef         = "deny:no_repo_ref"
    reasonRepoNotAllowed    = "deny:repo_not_allowed"
    reasonMutationUnscoped  = "deny:mutation_unscoped"
    reasonMissingScope      = "deny:missing_scope"
)

type graphQLDecision struct {
    Allow    bool
    Status   int    // 0 when Allow; 400 for parse; 403 for denials
    Message  string // exact text passed to writeGraphQLError today
    Reason   string // one of the reason* constants
    Repo     string // set only for deny:repo_not_allowed, and for allow with exactly one referenced repo
    Analyzed bool   // false only for the open-scoped shortcut (no analysis ran)
    Analysis graphQLAnalysis // zero value when !Analyzed or parse error; used by tests for field lists
    AnalysisDuration time.Duration // time spent in analyzeGraphQLRequest
}

func graphQLVerdict(body []byte, si tokenScopeInfo) graphQLDecision
```

The spec's `Stage` field is replaced by `Analyzed` plus `Status`. The handler derives the stage from them. This is the only deviation and does not change behaviour.

- [ ] **Step 1: Write the verdict test (it fails to compile)**

`TestGraphQLVerdict` in `graphql_verdict_test.go`, table-driven. Each row: `name`, `body` (JSON `{"query": ...}`), `si`, want `Reason`, want `Status`, want `Message` substring.

| name | si | query | Reason | Status | Message contains |
|---|---|---|---|---|---|
| open shortcut | `{}` | `{viewer{login}}` | `allow` | 0 | "" (and `Analyzed == false`) |
| parse error | `Scopes: issues:read` | `{` | `parse` | 400 | `Invalid request: graphql:` |
| subscription | `Scopes: issues:read` | `subscription{x}` | `deny:subscription` | 403 | `subscriptions are not supported` |
| unmapped | `Scopes: issues:read` | `{repository(owner:"o",name:"r"){foo{bar}}}` | `deny:unmapped` | 403 | `unmapped fields: foo` |
| cross repo | `Repos: [o/r]` | `{search(query:"x",type:REPOSITORY,first:1){repositoryCount}}` | `deny:cross_repo` | 403 | `cross-repository fields: search` |
| mutation repo | `Repos: [o/r]` | `mutation{createIssue(input:{repositoryId:"x",title:"t"}){issue{id}}}` | `deny:mutation_repo` | 403 | `mutations are not supported` |
| unpinned | `Repos: [o/r]` | `query($o:String!){repository(owner:$o,name:"r"){name}}` | `deny:unpinned` | 403 | `literal string arguments` |
| no repo ref | `Repos: [o/r]` | `{viewer{login}}` | `deny:no_repo_ref` | 403 | `must reference repository(owner, name)` |
| repo not allowed | `Repos: [o/r]` | `{repository(owner:"o",name:"other"){name}}` | `deny:repo_not_allowed` | 403 | `Token is not scoped to o/other` (and `Repo == "o/other"`) |
| missing scope | `Scopes: issues:read` | `{repository(owner:"o",name:"r"){pullRequests(first:1){nodes{number}}}}` | `deny:missing_scope` | 403 | `pull_requests:read` |
| allow repo | `Repos: [o/r]` | `{repository(owner:"o",name:"r"){name}}` | `allow` | 0 | "" (and `Repo == "o/r"`) |

Build `Scopes` the way existing tests in `graphql_test.go` do (copy the helper they use, do not add a new one to production code). `deny:mutation_unscoped` is reachable only when a mutation maps to no scope but passes the unknown-fields check. If no input reaches it, leave it out of the table and add a comment saying so.

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/proxy -run TestGraphQLVerdict`
Expected: build failure, `undefined: graphQLVerdict`.

- [ ] **Step 3: Implement `graphQLVerdict` in `graphql_verdict.go`**

Move the decision chain from `proxy.go` lines ~396-569 in the same order: open-scoped shortcut → `analyzeGraphQLRequest` (time it into `AnalysisDuration`) → subscription → unknown fields → (if `len(si.Repos) > 0`) cross-repo, mutation, unpinned, no reference, allowlist loop → (if `len(si.Scopes) > 0`) mutation without scopes, `missingScopes`. Copy every message string byte-for-byte. Keep `summariseFieldList(..., maxRenderedFieldNames)`.

- [ ] **Step 4: Rewrite `handleGraphQL` to call it**

Keep the POST check, body read and size limit in the handler as they are. Then:
- Keep the explicit `if si.isOpenScoped()` shortcut before reading the body, unchanged (the same two zero-duration `ObserveDecision` calls and `forwardGraphQL(..., nil)`). Do not read the body for open tokens.
- After the body read and size check, call `d := graphQLVerdict(body, si)` exactly once. (`graphQLVerdict` also short-circuits for open tokens, returning `Allow, Analyzed=false`, so the corpus `open` profile exercises real code; the handler never reaches that branch.)
- Otherwise emit `ObserveDecision(StageGraphQLAnalysis, tokenType, d.AnalysisDuration)`.
- `Reason == parse`: emit `StageTotal`, `writeGraphQLError(w, 400, d.Message)`, log `proxy_request_invalid`. No `StageScopeEnforcement` (same as today).
- Other denials: emit `StageScopeEnforcement` with duration `time.Since(callStart) - d.AnalysisDuration` (`callStart` taken just before the `graphQLVerdict` call), then `StageTotal`, then `writeGraphQLError(w, d.Status, d.Message)` and `h.logRequest(pt, r, "/graphql", d.Repo, d.Status, time.Since(start), "proxy_scope_denied")`.
- Allow: emit `StageScopeEnforcement` (same duration rule), then `forwardGraphQL(..., &d.Repo)`.

- [ ] **Step 5: Run the new and existing tests**

Run: `go test ./internal/proxy -run 'TestGraphQLVerdict|TestServeHTTP_GraphQL|TestAnalyzeGraphQL' -count=1`
Expected: PASS. The 16 existing `TestServeHTTP_GraphQL_*` tests pass without edits. Do not change any existing test file.

Run: `make check && gofmt -l internal/`
Expected: PASS, no gofmt output.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/graphql_verdict.go internal/proxy/graphql_verdict_test.go internal/proxy/proxy.go
git commit -m "refactor(proxy): extract graphQLVerdict from handleGraphQL"
```

---

### Task 2: `redact` package

**Depends on:** none

**Files:**
- Create: `tools/scoperig/redact/redact.go`, `tools/scoperig/redact/redact_test.go`

**Interfaces:**
- Produces:

```go
package redact
// Pattern matches any GitHub or GHP token-shaped string.
var Pattern *regexp.Regexp // `(gh[oupsrx]_|gha_|ghpr_|github_pat_)[A-Za-z0-9_]{8,}`
func String(s string) string   // replaces each match with "<prefix>[REDACTED]"
func Bytes(b []byte) []byte
func Header(h http.Header) http.Header // copy; Authorization, Cookie, Set-Cookie values -> "[REDACTED]"; others through String
func Contains(b []byte) bool   // true if any match remains (used by corpus writers to refuse output)
```

- [ ] **Step 1: Write `TestString` (table), `TestHeader`, `TestContains`**

Rows: `ghx_abcdefgh12345678` → `ghx_[REDACTED]`; `gha_…`, `ghpr_…`, `gho_…`, `ghu_…`, `ghs_…`, `ghp_…`, `github_pat_11ABC…` all redacted; `"token REDACTED"` unchanged; `ghx_` alone (too short) unchanged; a JSON body with a token in a nested string is redacted and stays valid JSON.

Also `TestRedact_ExecutorOutputs`: a table of strings shaped like each executor's output (`gh` stderr `"HTTP 401: Bad credentials (https://h/api/v3/user)\nGH_ENTERPRISE_TOKEN=ghx_…"`, a REST body echoing a token, a header map with `Authorization: token ghx_…`). After redaction `Contains` is false.

- [ ] **Step 2:** `go test ./tools/scoperig/redact/...` → FAIL (undefined).
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `go test ./tools/scoperig/redact/... && go vet ./tools/scoperig/... && gofmt -l tools/` → PASS, no output.
- [ ] **Step 5: Commit** `git add tools/scoperig/redact/ && git commit -m "feat(scoperig): add token redaction package"`

---

### Task 3: `ghdebug` parser and sanitiser

**Depends on:** T2

**Files:**
- Create: `tools/scoperig/ghdebug/parse.go`, `sanitise.go`, `parse_test.go`, `sanitise_test.go`
- Create: `tools/scoperig/ghdebug/testdata/pr_list.txt` (a short sanitised excerpt: one REST and one GraphQL exchange, `Authorization: token REDACTED`)

**Interfaces:**
- Consumes: `redact.Contains`, `redact.String`.
- Produces:

```go
package ghdebug
type Exchange struct {
    Method, URL, Path string     // Path is the URL path, e.g. "/graphql" or "/repos/cli/cli/readme"
    RequestHeaders  http.Header  // redacted
    GraphQL         *GraphQLRequest // non-nil when "GraphQL query:" block present
    Status          int          // from "< HTTP/2.0 200 OK"; 0 if none
    ResponseBody    string       // redacted, capped 64 KiB
}
type GraphQLRequest struct {
    Query         string
    Variables     map[string]any // decoded with json.Decoder.UseNumber()
    OperationName string         // parsed from "query Name(" / "mutation Name"; "" if anonymous
}
func Parse(r io.Reader) ([]Exchange, error)
// Sanitise replaces concrete owner/repo/number values in Variables with OWNER, REPO, 1
// (keys: owner, repo, name, number, prNumber, issueNumber, selector, endCursor->nil) and
// returns an error if redact.Contains finds a token in any retained string.
func Sanitise(g GraphQLRequest, owner, repo string) (GraphQLRequest, error)
func FirstDenied(ex []Exchange) *Exchange // first exchange with Status >= 400
```

**Blocked if `/tmp/gh-queries/*.txt` is absent.** Regenerate with the recipe: for each command, `GH_DEBUG=api gh <args> -R cli/cli 2> /tmp/gh-queries/<name>.txt >/dev/null` outside any git checkout, then replace the Authorization header value with `REDACTED` (`sed -i '' -E 's/^(> Authorization: token ).*/\1REDACTED/'`). After T17 lands, `scoperig oracle` replaces this recipe.

Format facts (from `/tmp/gh-queries/pr_list.txt`): each request starts with `* Request at …` then `* Request to <url>`, request lines prefixed `> `, then optional `GraphQL query:` (multi-line, ends at the line starting `GraphQL variables: `), then response lines prefixed `< `, then the body.

- [ ] **Step 1: Tests**

`TestParse_PRList` on the testdata file: 2 exchanges; exchange[1].Path == `/graphql`; `GraphQL.OperationName == "PullRequestList"`; `Variables["owner"] == "cli"`; `Status == 200`; `RequestHeaders.Get("Authorization") == "[REDACTED]"`.
`TestSanitise`: owner/repo replaced, `limit` kept as `json.Number("30")`; a query containing `ghx_aaaaaaaaaaaa` returns an error.
`TestFirstDenied`: picks the first 403 from a slice.

- [ ] **Step 2:** `go test ./tools/scoperig/ghdebug/...` → FAIL.
- [ ] **Step 3:** Implement with `bufio.Scanner` (buffer 1 MiB).
- [ ] **Step 4:** `go test ./tools/scoperig/ghdebug/... && gofmt -l tools/` → PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/ghdebug/ && git commit -m "feat(scoperig): parse and sanitise GH_DEBUG=api captures"`

---

### Task 4: Corpus importer and seed corpus for gh 2.102.0

**Depends on:** T3

**Files:**
- Create: `tools/scoperig/corpus/corpus.go`, `corpus_test.go`
- Create: `tools/scoperig/corpus/importghdebug/main.go`
- Create: `rig/corpus/gh/2.102.0/<command>.json` (one per capture except `pr_create_dryrun` and `auth_status`, which carry no read GraphQL worth pinning; include them anyway if they parse, since the structural test accepts empty `graphql`)

**Interfaces:**
- Consumes: `ghdebug.Parse`, `ghdebug.Sanitise`, `redact.Contains`.
- Produces (JSON format, spec §6):

```go
package corpus
type File struct {
    GHVersion string    `json:"gh_version"`
    Command   string    `json:"command"`     // "pr list"
    REST      []string  `json:"rest"`        // "GET /repos/OWNER/REPO/readme"
    GraphQL   []Entry   `json:"graphql"`
}
type Entry struct {
    Operation string                 `json:"operation"` // "(anonymous)" if none
    Body      Body                   `json:"body"`
    Expect    map[string]Expectation `json:"expect"`    // keys: open, perm-ro, repo
}
type Body struct {
    Query         string         `json:"query"`
    Variables     map[string]any `json:"variables"`
    OperationName string         `json:"operationName,omitempty"`
}
type Expectation struct {
    Verdict    string `json:"verdict"`
    KnownIssue string `json:"known_issue,omitempty"`
    Current    string `json:"current,omitempty"`
}
func Build(version, command string, ex []ghdebug.Exchange, prev *File) (File, error)
func Marshal(f File) ([]byte, error) // json.MarshalIndent 2 spaces, trailing newline, sorted map keys (encoding/json sorts)
```

`Build` sets REST paths with owner/repo replaced by `OWNER/REPO` and numeric path segments after `pulls|issues|releases` replaced by `1`. When `prev` has an entry with the same `Operation`, copy its `Expect`. Otherwise set every profile to `{"verdict":"allow"}` (the human edits expectations in Task 5).

**Blocked if `/tmp/gh-queries/*.txt` is absent** (see the regeneration recipe in Task 3; or, once T17 exists, `scoperig oracle`).

Importer: `go run ./tools/scoperig/corpus/importghdebug -in /tmp/gh-queries -out rig/corpus/gh/2.102.0 -gh-version 2.102.0 -owner cli -repo cli`. File name `<capture name>.json` (e.g. `pr_list.json`). Command name: capture name with `_` → space (`pr list`, `api graphql viewer`). Processes files in sorted order. Refuses to write (exit 1) if `redact.Contains` is true for the output.

- [ ] **Step 1: Tests** — `TestBuild_PRList` (from `ghdebug/testdata/pr_list.txt`): one entry, `Operation == "PullRequestList"`, `Variables["owner"] == "OWNER"`, three `Expect` keys. `TestBuild_CopiesPrevExpect`. `TestMarshal_Deterministic`: two calls give identical bytes.
- [ ] **Step 2:** `go test ./tools/scoperig/corpus/...` → FAIL.
- [ ] **Step 3:** Implement `corpus.go` and `importghdebug/main.go` (flag package, no cobra).
- [ ] **Step 4: Sanitisation check before generating.** Run:

```bash
grep -nE 'gh[opsurx]_[A-Za-z0-9]{8,}|ghpr_|github_pat_|gha_[A-Za-z0-9]{8,}' /tmp/gh-queries/*.txt
grep -niE '^> (authorization|cookie):' /tmp/gh-queries/*.txt | grep -v 'REDACTED'
```
Expected: no output from either. If anything prints, stop and report. Do not import.

- [ ] **Step 5: Generate and check the output**

```bash
go run ./tools/scoperig/corpus/importghdebug -in /tmp/gh-queries -out rig/corpus/gh/2.102.0 -gh-version 2.102.0 -owner cli -repo cli
grep -rnE 'gh[opsurx]_|ghx_|ghpr_|github_pat_|gha_' rig/corpus/ ; echo "grep exit $?"
grep -rniE 'authorization|cookie|"cli"' rig/corpus/ ; echo "grep exit $?"
go run ./tools/scoperig/corpus/importghdebug -in /tmp/gh-queries -out /tmp/corpus-regen -gh-version 2.102.0 -owner cli -repo cli && diff -r rig/corpus/gh/2.102.0 /tmp/corpus-regen
```
Expected: both greps print nothing and `grep exit 1`; `diff` prints nothing (deterministic). Note `gh_` would match `"gh_version"`; the pattern above requires a letter after `gh` so it does not.

- [ ] **Step 6:** `go test ./tools/scoperig/... && gofmt -l tools/` → PASS.
- [ ] **Step 7: Commit**

```bash
git add tools/scoperig/corpus/ rig/corpus/gh/2.102.0/
git commit -m "feat(scoperig): add gh debug corpus importer and gh 2.102.0 corpus"
```

---

### Task 5: Corpus unit test against `graphQLVerdict`

**Depends on:** T1, T4

**Files:**
- Create: `internal/proxy/graphql_ghcorpus_test.go`
- Modify: `rig/corpus/gh/2.102.0/*.json` (set expectations)

**Interfaces:**
- Consumes: `graphQLVerdict(body []byte, si tokenScopeInfo) graphQLDecision` (Task 1); corpus JSON format (Task 4). The test declares its own decode structs; it must not import `tools/`.

Test profiles (fixed in the test):
- `open`: `tokenScopeInfo{}`
- `perm-ro`: scopes `contents:read,issues:read,pull_requests:read,metadata:read,actions:read`
- `repo`: `Repos: []string{"OWNER/REPO"}`, no scopes

Corpus root: `filepath.Join("..", "..", "rig", "corpus", "gh")`.

- [ ] **Step 1: Write the tests**

`TestGHCorpus` walks every `*.json` under the root, sorted. For each entry and each of the three profiles, `t.Run("<version>/<command>/<operation>/<profile>")`:
- marshal `entry.Body` to bytes; `d := graphQLVerdict(b, si)`; `got := d.Reason`.
- No `known_issue`: `got == verdict`, else `t.Errorf` with `d.Message`, `d.Analysis.unknownFields`, `d.Analysis.crossRepoFields`.
- `known_issue` set: `got == current` → pass. `got == verdict` → `t.Errorf("fixed; remove known_issue and current")`. Else → `t.Errorf("changed: current %q, got %q (%s)")`.

`TestGHCorpus_Structure`: every file parses; `gh_version` matches its directory; every entry has exactly the keys `open`, `perm-ro`, `repo`; `current` is non-empty iff `known_issue` is non-empty; `known_issue` starts with `https://github.com/goodtune/ghp/issues/`; verdicts are in the vocabulary; and the raw bytes do not match `(gh[opsurx]_|gha_|ghpr_|github_pat_)[A-Za-z0-9_]{8,}`.

`TestGHCorpus_KnownChanged` is a table test of the classify helper `classifyCorpus(got, verdict, current string, known bool) string` (returns `"pass"`, `"fixed"`, `"changed"`, `"fail"`), defined in the test file.

- [ ] **Step 2: Run to see which expectations fail**

Run: `go test ./internal/proxy -run GHCorpus -count=1`
Expected: FAIL for every entry that the importer defaulted to `allow` and that is denied today.

- [ ] **Step 3: Set expectations in the corpus JSON**

Rules (spec §6, CONS §A9). Use `-v` output from Step 2 to fill `current` with the observed reason:
- `open`: `{"verdict":"allow"}` for all.
- `perm-ro`: `RepositoryInfo`, the `viewer` query (`api_graphql_viewer`) and `RepositoryReleaseList` → `allow` with no known issue if they pass. Every entry denied as `deny:unmapped` → `{"verdict":"allow","known_issue":".../issues/298","current":"deny:unmapped"}`. Root `search` (`pr status`, `search prs`): a perm-ro token has no repo allowlist, so the desired verdict is `allow`; record `known_issue` #298 and the observed `current`.
- `repo`: every variable-driven query → `{"verdict":"allow","known_issue":".../issues/297","current":"deny:unpinned"}`. Queries with root `search` or root `node` → `{"verdict":"deny:cross_repo"}` with no known issue if that is what is observed; if the analyzer hits unpinned first, record `current` as observed and `known_issue` #297. Anonymous `viewer` → `{"verdict":"deny:no_repo_ref"}` (correct per C24). Introspection probes (`PullRequest_fields` etc.) → desired `allow`, known issue #298, current as observed.
- Any mutation root with `__typename` → known issue #299.

Never edit `body`. Only `expect`.

- [ ] **Step 4:** `go test ./internal/proxy -run GHCorpus -count=1 -v | tail -20` → PASS. Then `make check`.
- [ ] **Step 5: Commit**

```bash
git add internal/proxy/graphql_ghcorpus_test.go rig/corpus/gh/2.102.0/
git commit -m "test(proxy): pin GraphQL analyzer against gh 2.102.0 query corpus"
```

---

### Task 6: Scenario schema types and loader

**Depends on:** none

**Files:**
- Create: `tools/scoperig/scenario/types.go`, `load.go`, `load_test.go`, `testdata/ok/{claims.yaml,profiles.yaml,scenarios/a.yaml}`

**Interfaces:**
- Produces:

```go
package scenario
type Claim struct {
    ID        string `yaml:"id"`         // "REPO-C05", "GAP-A1"
    Doc       string `yaml:"doc"`        // "docs/features/token-scoping.md#repository-restrictions"
    Claim     string `yaml:"claim"`
    Iteration int    `yaml:"iteration"`
    Testable  string `yaml:"testable"`   // periodic | manual | never
}
type Profile struct {
    Name         string   `yaml:"name"`
    Type         string   `yaml:"type"`          // proxy (agent rejected in iteration 1)
    Repositories []string `yaml:"repositories"`  // templated
    Scopes       string   `yaml:"scopes"`
    Duration     string   `yaml:"duration"`      // "" only for lifecycle-default
}
type Request struct {
    Name    string            `yaml:"name"`
    Method  string            `yaml:"method"`
    Path    string            `yaml:"path"`
    Headers map[string]string `yaml:"headers"`  // e.g. raw Authorization for BORDER-C43
    Body    any               `yaml:"body"`
    Expect  *Expect           `yaml:"expect"`
    Capture map[string]string `yaml:"capture"`  // name -> "$.json.path"
}
type Expect struct {
    Status          int               `yaml:"status"`
    StatusIn        []int             `yaml:"status_in"`
    BodyContains    []string          `yaml:"body_contains"`
    BodyNotContains []string          `yaml:"body_not_contains"`
    Header          map[string]string `yaml:"header"`
    JSON            map[string]string `yaml:"json"`
    GHPDenial       *bool             `yaml:"ghp_denial"`
    ExitCode        *int              `yaml:"exit_code"`
    StdoutContains  []string          `yaml:"stdout_contains"`
    StderrContains  []string          `yaml:"stderr_contains"`
}
type Scenario struct {
    ID          string         `yaml:"id"`
    Claim       string         `yaml:"claim"`
    Doc         string         `yaml:"doc"`
    Description string         `yaml:"description"`
    Profile     string         `yaml:"profile"`       // "" allowed for token_api
    Kind        string         `yaml:"kind"`          // rest | graphql | gh | token_api
    KnownIssue  string         `yaml:"known_issue"`
    Observed    *Expect        `yaml:"observed"`
    Requires    []string       `yaml:"requires"`      // repo_w_push repo_create github_vhost agent_installation
    Cleanup     []Request      `yaml:"cleanup"`
    Expect      *Expect        `yaml:"expect"`
    // kind-specific
    Steps     []Request      `yaml:"steps"`          // rest (single request = one step)
    Method    string         `yaml:"method"`         // rest shorthand
    Path      string         `yaml:"path"`
    Headers   map[string]string `yaml:"headers"`
    Body      any            `yaml:"body"`
    Query     string         `yaml:"query"`          // graphql
    Variables map[string]any `yaml:"variables"`
    Args      []string       `yaml:"args"`           // gh
    Repo      string         `yaml:"repo"`           // gh: A | B | W
    Request   *Request       `yaml:"request"`        // token_api
    Poll      *Poll          `yaml:"poll"`           // LIFE-C40
    File      string         `yaml:"-"`              // source file for error messages
}
type Poll struct { Interval string `yaml:"interval"`; Timeout string `yaml:"timeout"` } // "2s", "35s"
type Tree struct {
    Claims    map[string]Claim
    Profiles  map[string]Profile
    Scenarios []*Scenario // sorted by ID
}
func Load(root string) (*Tree, error) // reads root/claims.yaml, root/profiles.yaml, root/scenarios/*.yaml
func (s *Scenario) Normalise()        // rest shorthand (Method/Path/Body/Expect) -> Steps[0]
```

Each `scenarios/*.yaml` holds a YAML sequence of scenarios. Use `yaml.v3` `Decoder.KnownFields(true)` so typos fail.

- [ ] **Step 1: Tests** — `TestLoad_OK` (testdata/ok: 2 claims, 1 profile, 2 scenarios sorted by ID, shorthand normalised to one step); `TestLoad_UnknownField` (a scenario with `expct:` fails naming the file); `TestLoad_DuplicateID` (fails).
- [ ] **Step 2:** `go test ./tools/scoperig/scenario/...` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `go test ./tools/scoperig/scenario/... && gofmt -l tools/` → PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/scenario/ && git commit -m "feat(scoperig): scenario schema and loader"`

---

### Task 7: Static validation and template expansion

**Depends on:** T6

**Files:**
- Create: `tools/scoperig/scenario/validate.go`, `template.go`, `validate_test.go`, `template_test.go`

**Interfaces:**
- Consumes: Task 6 types.
- Produces:

```go
type RepoRef struct { Owner, Name string; ID int64 }
func (r RepoRef) String() string // "owner/name"
type FixtureVals struct { IssueNumber, PRNumber int; ReleaseID int64; Branch, Label, PRTitle, IssueTitle, ReleaseTag string }
type InstanceVals struct { Host, ManagementHost string; DefaultDuration, MaxDuration time.Duration }
type Vars struct {
    RunID, Host, Login string
    RepoA, RepoB, RepoW RepoRef
    Fixture  map[string]FixtureVals        // keys "A","B","W"
    Instance InstanceVals
    Step     map[string]map[string]string  // captured values
}
func Expand(s string, v *Vars) (string, error)      // text/template, Option("missingkey=error")
func ExpandAny(x any, v *Vars) (any, error)          // walks maps/slices/strings
func Validate(t *Tree, v *Vars) []error              // all problems, sorted by scenario ID
```

Template helpers: `add` (durations, for `MaxDuration` + 1h), `upper`.

`Validate` checks (each error names scenario ID and file):
1. `claim` exists in `Claims`; `profile` exists (unless `kind: token_api`); `kind` is one of four.
2. `known_issue` non-empty ⇔ `observed` non-nil; `known_issue` matches `^https://github\.com/goodtune/ghp/issues/\d+$`.
3. Every `requires` value is one of the four capabilities.
4. Profiles: `type: proxy` only; `duration` parses and is ≤ 2h, or is empty only for `lifecycle-default`.
5. **Write target rule.** Expand with placeholder `Vars` (RepoW = `w-owner/w-repo`). For every request in `Steps` and `Cleanup` with method ≠ GET/HEAD: path must start with `/repos/w-owner/w-repo/`. Exceptions: `kind: token_api` (path must start with `/api/tokens`), and scenario ID `GAP-A1.delete-ref-contents-ro` (path must still be under W). `kind: graphql` whose query contains `mutation` must use a profile whose repositories are empty or exactly `[{{.RepoW}}]`, and any repo literal in the query must be W.
6. Every template expands without error (Step vars are allowed to be missing at validation time: pre-populate `Step` from each scenario's `capture` names with value `"0"`).

- [ ] **Step 1: Tests** — `TestExpand` (table: `{{.RepoA}}` → `o/a`, `{{.RepoA.Owner}}`, `{{.Fixture.A.PRNumber}}`, `{{add .Instance.MaxDuration "1h"}}` → `169h0m0s`, unknown key → error). `TestValidate_WriteOutsideW` (POST to `/repos/{{.RepoA}}/issues` → error mentioning `RepoW`). `TestValidate_KnownNeedsObserved`. `TestValidate_TokenAPIPath`. `TestValidate_UnknownClaimAndProfile`. `TestValidate_OK` on `testdata/ok`.
- [ ] **Step 2:** `go test ./tools/scoperig/scenario/...` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `go test ./tools/scoperig/scenario/... && gofmt -l tools/` → PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/scenario/ && git commit -m "feat(scoperig): scenario validation and templating"`

---

### Task 8: Rig data: config, claims, profiles

**Depends on:** T7

**Files:**
- Create: `rig/config.yaml` (exact content of spec §3.2a)
- Create: `rig/claims.yaml`
- Create: `rig/profiles.yaml` (the 11 profiles of spec §3.3)
- Create: `rig/scenarios/.keep` (empty; scenario files land in T18–T20)
- Create: `tools/scoperig/scenario/rigtree_test.go`

`claims.yaml`: one entry per claim C1–C54 using the recon area prefixes (copy the one-line claim and doc anchor from `/tmp/ghp-rig/recon/codebase-report.md` section 4), plus `GAP-A1` … `GAP-A9`. Set `testable: never` for C42, C53; `manual` for C45, C54; `periodic` for the rest. Set `iteration: 1` for the 27 claims of spec §7 table (C5–C7, C10–C16, C20, C21, C24–C29, C31–C33, C37, C38, C40, C43, C44, C51, C52) and GAP-A1/A2/A3/A6/A7; others take the iteration from spec §11.

Example entries:

```yaml
- id: REPO-C05
  doc: docs/features/token-scoping.md#repository-restrictions
  claim: A repository-restricted token is rejected for repositories outside its list.
  iteration: 1
  testable: periodic
- id: GAP-A1
  doc: docs/features/token-scoping.md#permission-scoping
  claim: Unmapped REST write endpoints are permission-checked for scoped tokens.
  iteration: 1
  testable: periodic
```

Profile example (repeat for all 11, scopes exactly as spec §3.3):

```yaml
- name: repo-A-perm-ro
  type: proxy
  repositories: ["{{.RepoA}}"]
  scopes: "contents:read,metadata:read"
  duration: 2h
- name: lifecycle-default
  type: proxy
```

- [ ] **Step 1: Test** `TestRigTree` loads `../../../rig` with `Load` and runs `Validate` with placeholder `Vars`; asserts zero errors; the set of claim numbers (ID suffix after the area prefix) equals exactly `C1`…`C54` plus `GAP-A1`…`GAP-A9` (set comparison, reporting missing and extra IDs, not just a count); 11 profiles; and that `C42`/`C53` are `never`, `C45`/`C54` are `manual`. Claim IDs are matched by suffix (`strings.HasSuffix(id, "-C42")`).
- [ ] **Step 2:** `go test ./tools/scoperig/scenario -run TestRigTree` → FAIL (files missing).
- [ ] **Step 3:** Write the YAML files.
- [ ] **Step 4:** `go test ./tools/scoperig/scenario/...` → PASS.
- [ ] **Step 5: Commit** `git add rig/config.yaml rig/claims.yaml rig/profiles.yaml rig/scenarios/.keep tools/scoperig/scenario/rigtree_test.go && git commit -m "feat(scoperig): claim catalogue, profiles and instance config"`

---

### Task 9: `expect` matchers

**Depends on:** T3, T6

**Files:**
- Create: `tools/scoperig/expect/expect.go`, `expect_test.go`

**Interfaces:**
- Consumes: `scenario.Expect`.
- Produces:

```go
package expect
type Observation struct {
    Status   int
    Header   http.Header // redacted
    Body     []byte      // redacted, capped 64 KiB
    GHExit   *int
    Stdout, Stderr string
    Exchanges []ghdebug.Exchange
}
// Match returns nil if every set field of e holds, else one error per mismatch,
// each phrased "want X, got Y".
func Match(e *scenario.Expect, o *Observation) []error
func JSONPath(body []byte, path string) (string, error) // "$.a.b", "$.items[0].id"; numbers rendered without exponent
func GHPMessage(body []byte) string                      // $.message if body is JSON, else ""
func IsGHPDenial(body []byte) bool
```

`IsGHPDenial` is true when `GHPMessage` starts with one of these prefixes (from `proxy.go`, CONS §B3): `Token is not scoped to`, `Token does not have permission`, `Token does not grant required GraphQL scopes`, `Token is repository-restricted`, `GraphQL request references unmapped fields`, `GraphQL subscriptions are not supported`, `GraphQL mutation could not be statically scoped`, `token has been revoked`, `token has expired`. Define these as named constants (`MsgNotScoped`, …), plus `MsgBorderPolicy` (the border-policy 403 text; grep `internal/proxy` for it and copy it exactly) and `MsgInvalidToken` (`Invalid token`, the 401 for an unknown `ghx_`). The implementer must grep `writeGraphQLError\|writeError\|http.Error` in `internal/proxy/*.go` (non-test) and add any other 401/403 prefix found.

- [ ] **Step 1: Tests** — `TestMatch` table (status, status_in, body_contains miss, body_not_contains hit, header, json path, ghp_denial true/false, exit_code, stdout_contains); `TestJSONPath`; `TestIsGHPDenial` (each prefix true; GitHub's `"Not Found"` false).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `go test ./tools/scoperig/expect/...` PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/expect/ && git commit -m "feat(scoperig): expectation matchers"`

---

### Task 10: Report: classification, roll-up, confidence, rendering

**Depends on:** T9

**Files:**
- Create: `tools/scoperig/report/{report.go,classify.go,confidence.go,render.go}` and `classify_test.go`, `confidence_test.go`, `render_test.go`, `testdata/report.golden.txt`, `testdata/report.golden.json`

**Interfaces:**
- Consumes: `scenario.Tree`, `expect.Match`.
- Produces:

```go
package report
type Status string // "PASS","FAIL","ERROR","KNOWN","KNOWN-FIXED","KNOWN-CHANGED","GAP"
type ScenarioResult struct {
    ID, Claim, KnownIssue string
    Status   Status
    Detail   string   // one line for the table
    GHPMessage string
    GHExit   *int
    FirstDeniedExchange string // "POST /api/graphql 403 <message>"
    Error    string
    GapReason string  // unmet requires
    Residue  []string // cleanup failures (object URLs)
}
// Classify: rigErr != nil -> ERROR. Not known: no mismatch -> PASS else FAIL.
// Known: observed matches -> KNOWN; else expect matches -> KNOWN-FIXED; else KNOWN-CHANGED.
// A 5xx observation is ERROR unless the matched expectation names that status.
func Classify(s *scenario.Scenario, o *expect.Observation, rigErr error) (Status, string)
type ClaimResult struct { ID string; Status Status; Scenarios []ScenarioResult }
func RollUp(t *scenario.Tree, results []ScenarioResult) []ClaimResult // spec §3.6 rules
type Summary struct { Pass, Fail, Known, Error, Gap, Base int; Confidence float64; Manual, Untestable, Gaps []string }
func Summarise(t *scenario.Tree, claims []ClaimResult) Summary
type Report struct {
    RunID, StartedAt, Instance, GHPVersion, GHVersion, RigCommit string
    Summary  Summary
    Claims   []ClaimResult
    Tokens   struct{ Created, Revoked int; LeftoverIDs []string }
}
func (r *Report) WriteTable(w io.Writer) error // format of spec §3.6; no timings
func (r *Report) WriteJSON(w io.Writer) error  // field names of spec §3.6
func ExitCode(r *Report) int                    // 0/1/2 per §3.7 (3 is decided before a report exists)
```

Roll-up: claim FAIL if any scenario FAIL/ERROR/KNOWN-CHANGED; else KNOWN if any KNOWN/KNOWN-FIXED; else PASS if every runnable scenario PASS; else GAP. Claims in `claims.yaml` with no scenario are GAP. `base` = `testable: periodic` claims not prefixed `GAP-`. `Confidence = Pass / (Base − Known)`, 0 when the denominator is 0. KNOWN-FIXED lines add `remove known_issue and observed: from <id>` to Detail.

- [ ] **Step 1: Tests** — `TestClassify` (table over the 6 outcomes plus "5xx is ERROR"), `TestClassify_Known` (observed matches → KNOWN; expect matches → KNOWN-FIXED; neither → KNOWN-CHANGED), `TestRollUp`, `TestConfidence` (the spec's example: 26 pass, 1 known, base 50 → `26/49`, printed `53.1%`), `TestExitCode`, `TestRender_Golden` (table and JSON against golden files; regenerate with `-update` flag defined in the test). Golden output must contain no `ghx_`.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `go test ./tools/scoperig/report/...` PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/report/ && git commit -m "feat(scoperig): report classification, roll-up and rendering"`

---

### Task 11: Token manager

**Depends on:** T2, T7

**Files:**
- Create: `tools/scoperig/tokens/{handle.go,manager.go}`, `handle_test.go`, `manager_test.go`

**Interfaces:**
- Consumes: `scenario.Profile`, `scenario.Expand`, `redact`.
- Produces:

```go
package tokens
type Handle struct { id string; value string } // value unexported
func (h Handle) ID() string
func (h Handle) String() string               // "ghx_[REDACTED:<id>]"
func (h Handle) GoString() string             // same
func (h Handle) MarshalJSON() ([]byte, error) // same, quoted
func (h Handle) Authorize(r *http.Request)    // sets "Authorization: token <value>"
func (h Handle) GHEnv() []string              // ["GH_ENTERPRISE_TOKEN=<value>"]
type Manager struct { /* base URL, session token, http.Client, pace, runID, created []string, revoked map */ }
func NewManager(mgmtURL, sessionToken, runID string, client *http.Client, pace time.Duration) *Manager
func (m *Manager) Sweep(ctx context.Context) (revoked []string, err error)
func (m *Manager) Create(ctx context.Context, p scenario.Profile, v *scenario.Vars) (Handle, error)
func (m *Manager) CreateRaw(ctx context.Context, body map[string]any) (status int, resp map[string]any, err error) // token_api; records id; strips "token" from resp
func (m *Manager) Revoke(ctx context.Context, id string) error
func (m *Manager) RevokeAll(ctx context.Context) (leftover []string)
func (m *Manager) VerifyNoneLeft(ctx context.Context) (leftover []string, err error)
func (m *Manager) Created() int
```

Behaviour:
- Session auth: `Authorization: Bearer <GHP_USER_TOKEN>` (same as `cmd/ghp/token.go:122`).
- Create: `POST /api/tokens` with `{type, repositories, scopes, duration, session_id: "scoperig-<runid>"}`. Response 201 `{token,id,...}` (`internal/server/api.go:369-376`). Wait `pace` between creates (`60s / (rate*0.75)`). On 429, wait 60 s and retry once. Non-201: error text includes status and redacted `message`, never the request body.
- Sweep: `GET /api/tokens?all=true`; on 403 or empty list, `GET /api/tokens`. Revoke entries with `session_id` prefix `scoperig-` and no `revoked_at`.
- Revoke: `DELETE /api/tokens/{id}`; on success mark the id revoked in the manager. Idempotent: an id already marked is skipped; a 400 `token not found or already revoked` (`internal/database/sqlite.go:506`, `internal/server/api.go:448-449`) is treated as success after a `GET /api/tokens/{id}` confirms `revoked_at` is set.
- RevokeAll: calls `Revoke` for every created id not yet marked; collect failures. Idempotent.
- CreateRaw shares the same pacer (and 429 retry) as Create.
- VerifyNoneLeft: list tokens; any id from this run without `revoked_at` → leftover.

- [ ] **Step 1: Tests (httptest server faking `/api/tokens`)**
  - `TestHandle_NeverFormatsValue`: `fmt.Sprintf("%v %+v %#v %s", h, h, h, h)`, `json.Marshal(struct{H Handle}{h})`, and `slog` text output of `h` contain no `ghx_secret`.
  - `TestManager_CreateSendsSessionID`, `TestManager_CreateRetries429Once` (pace overridable to 0 and the 60 s wait injectable via a field `sleep func(time.Duration)`), `TestManager_CreateErrorRedacted` (server returns 400 with body echoing a token → error has no token).
  - `TestManager_SweepFallsBackAndSkipsRevoked`.
  - `TestManager_RevokeAllAfterPanic`: create 2, then `func(){ defer m.RevokeAll(ctx); panic("x") }()` recovered; fake server saw 2 DELETEs.
  - `TestManager_VerifyNoneLeft`.
  - `TestManager_RevokeAllSkipsAlreadyRevoked`: `Revoke(id1)` then `RevokeAll` → only one DELETE for id1; and a fake that answers 400 `token not found or already revoked` with `revoked_at` set on GET → no error, no leftover.
  - `TestManager_CreateRawSharesPacer`: Create then CreateRaw with an injected `sleep` → sleep called with the pace between them.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `go test ./tools/scoperig/tokens/... -race` PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/tokens/ && git commit -m "feat(scoperig): token manager with sweep, pacing and guaranteed revoke"`

---

### Task 12: Config, preflight and capability probe

**Depends on:** T7, T11

**Files:**
- Create: `tools/scoperig/config.go`, `preflight.go`, `config_test.go`, `preflight_test.go`

**Interfaces:**
- Consumes: `tokens.Handle`, `scenario.Vars`.
- Produces (package `main`):

```go
type Config struct {
    ServerURL, UserToken string            // GHP_SERVER_URL, GHP_USER_TOKEN (required)
    RepoA, RepoB, RepoW  string            // env > rig/config.yaml fixtures
    GHPath, Root, CAFile string            // GHP_RIG_GH, GHP_RIG_SCENARIOS (default "rig"), GHP_RIG_CA_FILE
    InstallationID       int64             // GHP_RIG_INSTALLATION_ID
    Instance             scenario.InstanceVals
    TokenCreateRate      int               // per minute, from "20/min"
    ConfigFile, Out, Only string
    SkipKnown, KeepGoing, Verbose, CreateFixtures bool
}
func LoadConfig(getenv func(string) string, configFile string) (*Config, error)
func (c *Config) HTTPClient() (*http.Client, error) // system pool + CAFile; 30s timeout
func (c *Config) String() string // never prints UserToken
type Capabilities map[string]bool  // repo_w_push repo_create github_vhost agent_installation
func Preflight(ctx context.Context, c *Config, hc *http.Client) (ghpVersion string, err error)
func ProbeCapabilities(ctx context.Context, c *Config, hc *http.Client, open tokens.Handle, v *scenario.Vars) (Capabilities, error)
```

- Preflight: `GET <server>/login` → 200 and body contains `version`; extract the version string. `GET /api/tokens` with session → 200.
- Probe (with `open`): `GET /api/v3/user` → sets `v.Login`; `GET /api/v3/repos/<W>` → `permissions.push` gives `repo_w_push`; `GET /api/v3/` → `X-OAuth-Scopes` contains `repo` or `public_repo` and W's owner equals `v.Login` → `repo_create`; `github_vhost`: TLS dial to the instance host:443 with `ServerName: "github.com"` using the same root pool, then `GET /` → any HTTP response gives true; `agent_installation`: `InstallationID > 0` and `GET /api/tokens?all=true` returns 200.

- [ ] **Step 1: Tests** — `TestLoadConfig` (missing `GHP_SERVER_URL` → error naming it; env overrides config repos; `20/min` parsed), `TestConfig_StringRedacts`, `TestPreflight` (httptest: OK; `/login` 500 → error; session 401 → error), `TestProbeCapabilities` (httptest TLS server; `github_vhost` false when the dial fails).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `go test ./tools/scoperig/ -run 'Config|Preflight|Probe'` PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/config.go tools/scoperig/preflight.go tools/scoperig/config_test.go tools/scoperig/preflight_test.go && git commit -m "feat(scoperig): config, preflight and capability probe"`

Note: a `package main` needs a `main` func to build. Add a temporary `main.go` with `func main() {}` in this task; Task 16 replaces it. Include it in this commit.

---

### Task 13: Fixtures discover and ensure

**Depends on:** T7

**Files:**
- Create: `tools/scoperig/fixtures/fixtures.go`, `fixtures_test.go`

**Interfaces:**
- Produces:

```go
package fixtures
// API is a thin client that sends REST requests through GHP (/api/v3) with a token.
type API interface { Do(ctx context.Context, method, path string, body any) (status int, resp []byte, err error) }
const (
    Label = "scoperig"; IssueTitle = "scoperig fixture issue"; Branch = "scoperig-fixture"
    PRTitle = "scoperig fixture PR"; ReleaseTag = "scoperig-fixture-v0"; FixtureFile = "fixture.txt"
)
func Discover(ctx context.Context, api API, repo string) (scenario.RepoRef, scenario.FixtureVals, error)
type Plan struct { Repo string; Create bool; Seed []string } // human-readable actions
func Ensure(ctx context.Context, api API, repo, login string, create, canCreate bool) (Plan, error)
```

- Discover: `GET /repos/{r}` (id), `GET /repos/{r}/issues?labels=scoperig&state=open` for the issue titled `IssueTitle`, `GET /repos/{r}/pulls?head=<owner>:scoperig-fixture&state=open`, `GET /repos/{r}/releases/tags/scoperig-fixture-v0`. Missing piece → error `fixture <what> missing in <repo>; run 'scoperig fixtures ensure'`.
- Safety guard: `Ensure` refuses (error, no non-GET call) unless the repo name contains `scoperig` AND its owner equals the probed login (`v.Login`). Signature becomes `Ensure(ctx, api, repo, login string, create, canCreate bool)`. `--create-fixtures` is additionally required to create a missing repo.
- Ensure: repo missing and `!create` → return the plan and error `would create <repo>; pass --create-fixtures`. `create && !canCreate` → error with the out-of-band instructions of spec §4. `create && canCreate` → `POST /user/repos {name, private: true, auto_init: true}`. Then idempotent seeding in this order: label, issue, branch (get default branch sha, `POST /git/refs`), `PUT /contents/fixture.txt` on that branch, PR, release. Each step first checks existence.

- [ ] **Step 1: Tests (fake `API` recording calls)** — `TestDiscover_OK`, `TestDiscover_MissingPR`, `TestEnsure_NoCreateFlag` (no POST /user/repos call), `TestEnsure_Idempotent` (all seeds exist → zero non-GET calls), `TestEnsure_SeedsMissing`, `TestEnsure_RefusesNonRigRepo` (table: `goodtune/ghp` → refused; `other/ghp-scoperig-a` with login `goodtune` → refused; `goodtune/ghp-scoperig-a` → allowed; refused cases make zero non-GET calls).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `go test ./tools/scoperig/fixtures/...` PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/fixtures/ && git commit -m "feat(scoperig): fixture discovery and idempotent seeding"`

---

### Task 14: REST, GraphQL and token_api executors

**Depends on:** T2, T6, T9, T11, T12, T13

**Files:**
- Create: `tools/scoperig/exec/{exec.go,rest.go,graphql.go,tokenapi.go}`, `rest_test.go`, `graphql_test.go`, `tokenapi_test.go`

**Interfaces:**
- Consumes: `tokens.Handle`, `tokens.Manager.CreateRaw`/`Revoke`, `expect.Observation`, `expect.JSONPath`, `redact`, `scenario.Expand`.
- Produces:

```go
package exec
type RunEnv struct {
    Vars     *scenario.Vars
    HTTP     *http.Client
    APIBase  string // https://<host>/api/v3
    GraphQL  string // https://<host>/api/graphql
    Mgmt     string // https://<management_host>
    Tokens   *tokens.Manager
    Open     tokens.Handle // for cleanup
    Profiles map[string]tokens.Handle
    GHPath   string
    Verbose  io.Writer // nil unless --verbose; receives redacted exchanges
}
type Executor interface {
    Kind() string
    Run(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv) (*expect.Observation, error)
}
// Result of a multi-step scenario: the observation of the last step that ran.
// A step whose own Expect fails stops the steps and returns a StepFailure (not a rig error).
type StepFailure struct { Step string; Mismatch []error }
func (StepFailure) Error() string
func RunCleanup(ctx context.Context, s *scenario.Scenario, env *RunEnv) (residue []string)
func For(kind string) (Executor, error)
```

- REST: build the URL as `APIBase + path` and set `req.URL.Opaque` to the exact expanded path (prefixed `/api/v3`) so `..`, case and `%2e` are sent verbatim. Apply `Headers` after `tok.Authorize` (BORDER-C43 overrides `Authorization`; for that scenario `profile` is `open` and the header wins). Body: JSON-encode `ExpandAny(body)`. Capture values into `Vars.Step[stepName]`. Body capped at 64 KiB, then redacted.
- GraphQL: `POST GraphQL` with `{"query":…, "variables":…}` after expansion.
- token_api: `POST Mgmt + /api/tokens` goes through `env.Tokens.CreateRaw` (ids recorded, paced). `DELETE /api/tokens/{id}` goes through `env.Tokens.Revoke(id)` so the id is marked revoked and end-of-run `RevokeAll` does not revoke it twice (LIFE-C40). Other `/api/tokens` GETs use the session token directly.
- Typed values: a body value written as the YAML string `"$int:InstallationID"` (or `$int:RepoA.ID`, `$int:RepoB.ID`, `$int:RepoW.ID`) is replaced by the typed `int64` from `Vars` before JSON encoding, so it is sent as a JSON number. Any other name after `$int:` is a validation error (add a T7-style row to `validate_test.go` in this task).
- Transport error → retry once, then return as rig error. Product responses are never retried.

- [ ] **Step 1: Tests (httptest)**
  - `TestREST_SendsPathVerbatim` (fake server uses a raw `http.HandlerFunc`, not `http.ServeMux`, which would clean the path): paths `/repos/O/R/../../B/contents/README.md`, `/repos/OWNER/NAME`, `/repos/o/r/%2e%2e/x` arrive at the server with `r.RequestURI` exactly `/api/v3` + path.
  - `TestREST_StepsCaptureAndCleanup`: step 1 returns `{"number":7}`, capture used in cleanup path `/repos/w/w/issues/7`; cleanup runs even when step 2 fails.
  - `TestREST_HeaderOverridesAuthorization`.
  - `TestREST_ObservationRedacted`: server echoes the Authorization header in the body → observation body has no `ghx_`.
  - `TestGraphQL_PostsQueryAndVariables`.
  - `TestTokenAPI_DeleteUsesManagerRevoke`: a DELETE step marks the id; a later `RevokeAll` sends no second DELETE.
  - `TestTokenAPI_TypedInstallationID`: body `{installation_id: "$int:InstallationID"}` with `Vars.InstallationID=42` → fake server receives raw JSON containing `"installation_id":42` (a number, not `"42"`).
  - `TestTokenAPI_RecordsCreatedID`, `TestTokenAPI_Poll` (fake returns 200 twice then 401 → PASS within timeout; never 401 → mismatch after timeout, with interval/timeout set to ms in the test).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `go test ./tools/scoperig/exec/... -race` PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/exec/ && git commit -m "feat(scoperig): REST, GraphQL and token API executors"`

---

### Task 15: `gh` executor

**Depends on:** T3, T14

**Files:**
- Create: `tools/scoperig/exec/gh.go`, `gh_test.go`, `testdata/fakegh/main.go` (a fake `gh` built by the test)

**Interfaces:**
- Consumes: `ghdebug.Parse`, `ghdebug.FirstDenied`, `tokens.Handle.GHEnv`, `RunEnv`.
- Produces: `type GH struct{}` implementing `Executor` (`Kind() == "gh"`); `func ghEnv(host, repo string, tok tokens.Handle, tmp string) []string`.

Behaviour (spec §2.4):
- For each scenario, `os.MkdirTemp` → `cfg/`, `cache/`, `work/`. Removed afterwards.
- Env is built from scratch (do not inherit `os.Environ()` except `PATH`, `HOME` set to tmp, `TMPDIR`): `GH_HOST=<host>`, `GH_ENTERPRISE_TOKEN` (via `GHEnv`), `GH_REPO=<host>/<owner>/<repo>` for `repo: A|B|W`, `GH_CONFIG_DIR=<tmp>/cfg`, `XDG_CACHE_HOME=<tmp>/cache`, `GH_DEBUG=api`, `GH_PROMPT_DISABLED=1`, `NO_COLOR=1`, `GH_NO_UPDATE_NOTIFIER=1`. If `CAFile` is set, add `SSL_CERT_FILE=<CAFile>`. Note: Go ignores `SSL_CERT_FILE` on macOS (it uses the system keychain), so on macOS the rig relies on the system trust store; the Homelab root CA is already trusted there. Document this in the T23 page.
- `cmd.Dir = <tmp>/work` (not a git checkout). Timeout 60 s via `exec.CommandContext`.
- Args are templated (`{{.Fixture.A.PRNumber}}`).
- Observation: `GHExit`, `Stdout` (redacted), `Stderr` with the debug log removed (redacted), `Exchanges` from `ghdebug.Parse(stderr)`. `Status` is the status of `FirstDenied` or 0.
- `exec.ErrNotFound` or a timeout → rig error.

- [ ] **Step 1: Tests** — the test builds `testdata/fakegh` with `go build` into `t.TempDir()`. The fake prints its env (excluding `GH_ENTERPRISE_TOKEN` value, which it prints as `len=N`) to stdout, writes a canned `GH_DEBUG` log with one 403 exchange to stderr, and exits 1.
  - `TestGH_Env`: `GH_HOST`, `GH_REPO=h/o/a`, `GH_CONFIG_DIR` under tmp, working dir not under the repo.
  - `TestGH_ParsesFirstDenied`: observation status 403 and the exchange path.
  - `TestGH_NoTokenInOutput`: the fake also echoes `ghx_…` in stderr → no `ghx_` in observation.
  - `TestGH_Timeout`: fake sleeps; with a 100 ms context → rig error.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `go test ./tools/scoperig/exec/... -race` PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/exec/gh.go tools/scoperig/exec/gh_test.go tools/scoperig/exec/testdata/fakegh/ && git commit -m "feat(scoperig): gh executor with isolated config and debug capture"`

---

### Task 16: CLI and run orchestration

**Depends on:** T7, T10–T15

**Files:**
- Modify: `tools/scoperig/main.go` (replace the stub)
- Create: `tools/scoperig/run.go`, `run_test.go`

**Interfaces:**
- Consumes: everything from T6–T15.
- Produces: commands `scoperig validate`, `scoperig run`, `scoperig sweep`, `scoperig fixtures ensure [--create-fixtures]` (and `oracle` in T17). Flags of spec §3.8 (`--config` default `rig/config.yaml`, `--skip-known`, `--out`, `--only`, `--keep-going` default true, `--verbose`).

```go
type exitError struct{ code int; err error }
func runRig(ctx context.Context, c *Config, deps runDeps) (*report.Report, error)
type runDeps struct {
    HTTP   *http.Client
    Now    func() time.Time
    RunID  func() string   // default: UTC "20060102T1504Z" + "-" + 4 hex chars
    Exec   func(kind string) (exec.Executor, error)
}
```

`runRig` follows spec §3.5 steps 1-9 in order. Cleanup wiring:

```go
ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
defer stop()
defer func() { leftover = mgr.RevokeAll(context.WithoutCancel(ctx)) }() // runs on panic too
```

A second signal during `RevokeAll` prints the remaining ids and exits 2. Missing `requires` → `ScenarioResult{Status: GAP, GapReason: "requires repo_w_push"}`. `--only` filters scenarios by `path.Match` after loading; sweep and cleanup still run. `--skip-known` drops scenarios with `known_issue`. Exit code via `report.ExitCode`; validation, config and preflight errors → 3.

- [ ] **Step 1: Tests (httptest fake GHP)** — the fake implements `/login`, `/api/tokens` (create/list/delete), `/api/v3/user`, `/api/v3/repos/...` for fixtures and two REST scenarios (one PASS, one FAIL), using a temp `rig/` tree written by the test.
  - `TestRun_EndToEndFake`: exit 1; report has 1 PASS, 1 FAIL; all created tokens deleted; `VerifyNoneLeft` empty.
  - `TestRun_ValidationErrorExits3`: no HTTP request made.
  - `TestRun_PreflightFailExits3`: no token created.
  - `TestRun_SignalTriggersRevoke`: cancel the context after the first scenario; all tokens deleted; remaining scenarios ERROR.
  - `TestRun_RevokeFailureExits2`: fake DELETE returns 500 → exit 2, leftover id printed, no token value in stdout.
  - `TestRun_OnlyFilter`.
  - `TestValidate_NoEnv`.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:**

```bash
go test ./tools/scoperig/... -race -count=1
CGO_ENABLED=0 go build -o /tmp/scoperig ./tools/scoperig
env -u GHP_SERVER_URL -u GHP_USER_TOKEN /tmp/scoperig validate; echo "exit $?"
make check
```
Expected: tests PASS; `validate` prints `0 errors` and exits 0 (the `rig/` tree has no scenarios yet).

- [ ] **Step 5: Commit** `git add tools/scoperig/main.go tools/scoperig/run.go tools/scoperig/run_test.go && git commit -m "feat(scoperig): run orchestration, cleanup on signal and CLI"`

Note: `validate` must not need `GHP_SERVER_URL` or `GHP_USER_TOKEN`. It loads only `rig/` and `rig/config.yaml`, with placeholder Vars. Only `run`, `sweep`, `fixtures` and the live test require the env. Test: `TestValidate_NoEnv` (empty env, `validate` on the real `rig/` tree → exit 0, no HTTP client constructed).

---

### Task 17: `scoperig oracle`

**Depends on:** T4, T16

**Files:**
- Create: `tools/scoperig/oracle.go`, `oracle_test.go`

**Interfaces:**
- Consumes: `ghdebug`, `corpus.Build`, `corpus.Marshal`, `redact.Contains`.
- Produces: `scoperig oracle [--gh-version auto] [--repo cli/cli] [--out rig/corpus/gh]`.

```go
var oracleMatrix = []struct{ Name string; Args []string }{ // capture name, gh args (read-only)
    {"repo_view", []string{"repo", "view"}}, {"pr_list", []string{"pr", "list"}},
    {"pr_view", []string{"pr", "view", "1"}}, {"pr_status", []string{"pr", "status"}},
    {"pr_checks", []string{"pr", "checks", "1"}}, {"issue_list", []string{"issue", "list"}},
    {"issue_view", []string{"issue", "view", "1"}}, {"release_list", []string{"release", "list"}},
    {"label_list", []string{"label", "list"}}, {"run_list", []string{"run", "list"}},
    {"api_graphql_viewer", []string{"api", "graphql", "-f", "query={viewer{login}}"}},
}
func runOracle(ctx context.Context, ghPath, version, repo, outRoot string) (diff string, err error)
```

- `--gh-version auto` parses `gh --version`.
- Copies only `hosts.yml` from the operator's real `gh` config dir (`gh config` location: `$GH_CONFIG_DIR` or `~/.config/gh`) into a temp `GH_CONFIG_DIR` created with mode 0700 (file mode 0600) and removed by `defer os.RemoveAll`. Fresh `XDG_CACHE_HOME`. `GH_REPO=<repo>`. Never sets `GH_HOST`. Runs against github.com: this is the single permitted exception to "never call GitHub directly".
- Uses the previous version directory (highest semver under `outRoot` below `version`) as `prev` for `corpus.Build`. Prints a diff of operation names and field names (sorted set difference). Refuses to write any file where `redact.Contains` is true.

- [ ] **Step 1: Tests** — run `runOracle` with the fake `gh` from T15 (extend it: when `GH_DEBUG=api` and arg `pr list`, emit the testdata `pr_list.txt` on stderr). Assert output file `pr_list.json` exists under `<out>/<version>/`, `Expect` copied from a seeded prev version, and diff text names a new field. `TestOracle_RemovesCredentialCopy`: after `runOracle` returns (success and error paths), the temp config dir no longer exists (inject the temp-dir creator to learn its path).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `go test ./tools/scoperig/ -run Oracle` PASS.
- [ ] **Step 5: Commit** `git add tools/scoperig/oracle.go tools/scoperig/oracle_test.go tools/scoperig/exec/testdata/fakegh/ && git commit -m "feat(scoperig): oracle mode to refresh the gh query corpus"`

---

### Task 18: Scenarios: REST, lifecycle, border, misc

**Depends on:** T8, T16

**Files:**
- Create: `rig/scenarios/{repo,perm,open,lifecycle,border,misc}.yaml`
- Modify: `tools/scoperig/scenario/rigtree_test.go` (assert scenario counts)

One scenario per row and profile of spec §7 for REPO-C05, C06, C07, C10; PERM-C11–C16; OPEN-C20, C21; LIFE-C37, C38, C40; BORDER-C43 (3 scenarios: `ghp_`, `gho_`, `github_pat_`, each with a fake 36-char suffix built from `{{.RunID}}` padding, never a real token), C44; MISC-C52. Write scenarios declare `requires: [repo_w_push]` and `cleanup`. No `known_issue` yet (that comes from the live run).

Example scenarios (copy the style for the rest):

```yaml
- id: REPO-C10.case-insensitive
  claim: REPO-C10
  doc: docs/features/token-scoping.md#repository-restrictions
  description: Repository matching is case-insensitive.
  profile: repo-A
  kind: rest
  method: GET
  path: /repos/{{upper .RepoA.Owner}}/{{upper .RepoA.Name}}
  expect: {status: 200}

- id: PERM-C12.contents-write-allows-put
  claim: PERM-C12
  doc: docs/features/token-scoping.md#permission-scoping
  description: contents:write allows creating a file on W.
  profile: perm-rw
  kind: rest
  requires: [repo_w_push]
  steps:
    - name: put
      method: PUT
      path: /repos/{{.RepoW}}/contents/scoperig-{{.RunID}}.txt
      body: {message: "scoperig {{.RunID}} C12", content: "c2NvcGVyaWcK"}
      expect: {status: 201}
      capture: {sha: "$.content.sha"}
  cleanup:
    - method: DELETE
      path: /repos/{{.RepoW}}/contents/scoperig-{{.RunID}}.txt
      body: {message: "scoperig cleanup", sha: "{{.Step.put.sha}}"}

- id: LIFE-C40.revoked-rejected
  claim: LIFE-C40
  doc: docs/how-it-works.md#token-lifecycle
  description: A revoked token is rejected within the 30 s resolution cache window.
  profile: lifecycle-revoke
  kind: token_api
  steps:
    - {name: before, method: GET, path: /api/v3/user, expect: {status: 200}}
    - {name: revoke, method: DELETE, path: "/api/tokens/{{index .ProfileIDs \"lifecycle-revoke\"}}", expect: {status_in: [200, 204]}}
    - {name: probe, method: GET, path: /api/v3/user, expect: {status: 401, body_contains: ["token has been revoked"]}}
  poll: {interval: 2s, timeout: 35s}
```

LIFE-C40 needs the profile token id in templates: add `ProfileIDs map[string]string` to `scenario.Vars` (template `{{index .ProfileIDs "lifecycle-revoke"}}`) in this task, with a test in `template_test.go`. For `token_api` steps, a path starting `/api/v3/` is sent to the proxy host with the scenario profile token; a path starting `/api/tokens` uses the session token. Update Task 7's validation to accept `/api/v3/` GETs in `token_api` scenarios and add a test row. `poll` applies to the step named `probe`.

- [ ] **Step 1:** Extend `TestRigTree`: every iteration-1 non-GAP, non-GQL, non-GH claim in spec §7 has ≥ 1 scenario; every scenario with a non-GET step has `requires: [repo_w_push]` or is `token_api`.
- [ ] **Step 2:** `go test ./tools/scoperig/scenario -run TestRigTree` → FAIL.
- [ ] **Step 3:** Write the YAML (and the `ProfileIDs` change).
- [ ] **Step 4:** `go test ./tools/scoperig/... && env -u GHP_SERVER_URL -u GHP_USER_TOKEN go run ./tools/scoperig validate` → PASS, `0 errors`.
- [ ] **Step 5: Commit** `git add rig/scenarios/repo.yaml rig/scenarios/perm.yaml rig/scenarios/open.yaml rig/scenarios/lifecycle.yaml rig/scenarios/border.yaml rig/scenarios/misc.yaml tools/scoperig/scenario/types.go tools/scoperig/scenario/template.go tools/scoperig/scenario/template_test.go tools/scoperig/scenario/validate.go tools/scoperig/scenario/validate_test.go tools/scoperig/scenario/rigtree_test.go && git commit -m "feat(scoperig): REST, lifecycle, border and misc scenarios"`

---

### Task 19: Scenarios: GraphQL and GAP probes

**Depends on:** T18

**Files:**
- Create: `rig/scenarios/graphql.yaml`, `rig/scenarios/gaps.yaml`
- Modify: `tools/scoperig/scenario/rigtree_test.go`

GraphQL: GQL-C24, C25 (repo-A deny + repo-AB control), C26 (search root, node root, viewer.repositories, aliased search: 4 scenarios), C27 (repo-W `createIssue`), C28 (variable-only, mixed: 2 scenarios; mixed is the spec §3.4 example verbatim), C29, C31 (ro deny; rw allow with a `steps:` first query for `repository{id}` captured as `rid`, then `createIssue`, cleanup REST PATCH close using captured number; `requires: [repo_w_push]`), C32, C33. All `expect` per spec §7, with `ghp_denial: true` on every 403.

GAP probes (spec §7), expectations are the **desired** behaviour; leave `known_issue` empty until the live run:
- `GAP-A1.delete-ref-contents-ro`: `perm-contents-ro-W`, `DELETE /repos/{{.RepoW}}/git/refs/heads/scoperig-absent-{{.RunID}}`, expect `{status: 403, ghp_denial: true}`.
- `GAP-A2.repositories-by-id`: `repo-A`, `GET /repositories/{{.RepoB.ID}}`, expect `{status: 403, ghp_denial: true}`.
- `GAP-A3.github-vhost-archive`: `requires: [github_vhost]`. Its REST request goes to the `github.com` vhost: add an optional `vhost: github.com` field to `Request` and `Scenario` (REST executor dials the instance with SNI and `Host: github.com`, path `/{{.RepoB}}/archive/HEAD.tar.gz`). Add a `rest_test.go` case for `vhost`. Expect `{status: 403}`.
- `GAP-A6.agent-mint`: `requires: [agent_installation]`, `kind: token_api`, `POST /api/tokens {type: agent, repositories: ["{{.RepoA}}"], installation_id: "$int:InstallationID", duration: 1h, session_id: scoperig-{{.RunID}}}`, expect `{status: 201}`. Add `InstallationID int64` to `Vars` (from `GHP_RIG_INSTALLATION_ID`). Document in the scenario comment and the T24 summary whether revoking the `gha_` record also ends the minted GitHub installation token, or whether it stays valid until its natural expiry (up to 1 h leftover exposure).
- `GAP-A7.dotdot-path`: `repo-A`, `GET /repos/{{.RepoA}}/../../{{.RepoB}}/contents/README.md`, expect `{status_in: [403, 404], body_not_contains: ["\"path\": \"README.md\"", "\"path\":\"README.md\""]}`.

- [ ] **Step 1:** Extend `TestRigTree` to require scenarios for GQL-C24…C33 (iteration-1 subset) and GAP-A1/A2/A3/A6/A7.
- [ ] **Step 2:** FAIL. **Step 3:** write YAML and the `vhost`/`InstallationID` additions. **Step 4:** `go test ./tools/scoperig/... && env -u GHP_SERVER_URL -u GHP_USER_TOKEN go run ./tools/scoperig validate` → PASS. Run `git status --short` and confirm only the files below changed.
- [ ] **Step 5: Commit** `git add rig/scenarios/graphql.yaml rig/scenarios/gaps.yaml tools/scoperig/scenario/types.go tools/scoperig/scenario/template.go tools/scoperig/scenario/template_test.go tools/scoperig/scenario/rigtree_test.go tools/scoperig/exec/rest.go tools/scoperig/exec/rest_test.go tools/scoperig/exec/tokenapi.go tools/scoperig/exec/tokenapi_test.go && git commit -m "feat(scoperig): GraphQL scenarios and GAP probes"`

---

### Task 20: Scenarios: `gh` matrix

**Depends on:** T19

**Files:**
- Create: `rig/scenarios/gh.yaml`
- Modify: `tools/scoperig/scenario/rigtree_test.go`

33 scenarios: 11 commands × profiles `open`, `perm-ro`, `repo-A`. IDs `GH-C51.<cmd-slug>.<profile>` (e.g. `GH-C51.pr-list.perm-ro`). All `repo: A`. Commands and stdout expectation:

| slug | args | stdout_contains |
|---|---|---|
| repo-view | `[repo, view]` | `{{.RepoA.Name}}` |
| pr-list | `[pr, list, --limit, "5"]` | `{{.Fixture.A.PRTitle}}` |
| pr-view | `[pr, view, "{{.Fixture.A.PRNumber}}"]` | `{{.Fixture.A.PRTitle}}` |
| pr-status | `[pr, status]` | `{{.Fixture.A.PRTitle}}` |
| pr-checks | `[pr, checks, "{{.Fixture.A.PRNumber}}"]` | none; see below |
| issue-list | `[issue, list]` | `{{.Fixture.A.IssueTitle}}` |
| issue-view | `[issue, view, "{{.Fixture.A.IssueNumber}}"]` | `{{.Fixture.A.IssueTitle}}` |
| release-list | `[release, list]` | `{{.Fixture.A.ReleaseTag}}` |
| label-list | `[label, list]` | `scoperig` |
| run-list | `[run, list]` | (none; `exit_code: 0`) |
| api-viewer | `[api, graphql, -f, "query={viewer{login}}"]` | `{{.Login}}` |

The fixture PR has no checks, so `gh pr checks` exits 1 with `no checks reported`. Add `exit_code_in: [0, 1]` to `scenario.Expect` (and `expect.Match`, with a test row in T9's table added here) and use, for every profile:

```yaml
expect:
  exit_code_in: [0, 1]
  stderr_contains: ["no checks reported"]
```

Expected PASS for `open`; scoped profiles fail differently and get triaged in T24.

Exception: `GH-C51.api-viewer.repo-A` expects `exit_code: 1` and `stderr_contains: ["must reference repository(owner, name)"]` (correct per C24).

Write it compactly: YAML anchors are fine (`&gh-base` / `<<: *gh-base`) if `yaml.v3` `KnownFields` accepts merge keys; verify with the loader test. If not, write the 33 entries out.

- [ ] **Step 1:** Extend `TestRigTree`: exactly 33 scenarios with claim `GH-C51`, each `kind: gh`, `repo: A`.
- [ ] **Step 2:** FAIL. **Step 3:** write YAML. **Step 4:** `go test ./tools/scoperig/... && env -u GHP_SERVER_URL -u GHP_USER_TOKEN go run ./tools/scoperig validate` → PASS.
- [ ] **Step 5: Commit** `git add rig/scenarios/gh.yaml tools/scoperig/scenario/rigtree_test.go tools/scoperig/scenario/types.go tools/scoperig/expect/expect.go tools/scoperig/expect/expect_test.go && git commit -m "feat(scoperig): gh command matrix scenarios"`

---

### Task 21: Makefile, CI, live-tagged test, `.gitignore`

**Depends on:** T5, T16

**Files:**
- Modify: `Makefile` (add `scoperig`, `scoperig-validate` to `.PHONY` and as targets)
- Modify: `.github/workflows/test.yml` (add a `scoperig validate` step after unit tests)
- Modify: `.gitignore` (append `rig/reports/` and `/scoperig`)
- Create: `tools/scoperig/live_test.go`

Makefile:

```make
## scoperig: build the scope regression rig (operator tool, not shipped)
scoperig:
	CGO_ENABLED=0 go build -o scoperig ./tools/scoperig

## scoperig-validate: offline validation of rig/ scenarios
scoperig-validate:
	env -u GHP_SERVER_URL -u GHP_USER_TOKEN go run ./tools/scoperig validate
```

CI step (in the Go job, after `go test ./...`): `run: make scoperig-validate`. CI sets no GHP_* secrets; validate must pass without them. The corpus test already runs in `go test ./...`.

`live_test.go`:

```go
//go:build scoperig_live

// TestLive runs the full rig against GHP_SERVER_URL. Skips when the env is not set.
func TestLive(t *testing.T)
```

It skips with `t.Skip` when `GHP_SERVER_URL` or `GHP_USER_TOKEN` is empty, otherwise calls `runRig` with `--out` set to `t.TempDir()` and fails on exit code ≥ 2.

- [ ] **Step 1 (test first):** `go test ./tools/scoperig -run TestLive -v` without the tag → `testing: warning: no tests to run` (must stay so after the file is added).
- [ ] **Step 2:** Implement the four file changes.
- [ ] **Step 3: Verify**

```bash
make check
make scoperig-validate
make scoperig && ls -l scoperig && rm scoperig
go vet -tags scoperig_live ./tools/scoperig/...
go test ./tools/scoperig -run TestLive -v   # no tests to run
gofmt -l internal tools
git status --short   # scoperig binary not listed
```
Expected: all PASS, gofmt prints nothing, `validate` reports `0 errors`. If `golangci-lint` is installed, also `make lint` → clean.

- [ ] **Step 4: Commit** `git add Makefile .github/workflows/test.yml .gitignore tools/scoperig/live_test.go && git commit -m "build(scoperig): make targets, CI validation and live test tag"`

---

### Task 22: Claude Code skills `scope-rig-run` and `scope-rig-extend`

**Depends on:** T16–T20

**Files:**
- Create: `.claude/skills/scope-rig-run/SKILL.md`
- Create: `.claude/skills/scope-rig-extend/SKILL.md`

Follow superpowers:writing-skills (`/Users/gary/.claude/plugins/cache/claude-plugins-official/superpowers/7.0.0/skills/writing-skills/SKILL.md`): frontmatter with only `name` and `description`; description in third person, starts "Use when", lists triggers only and does not summarise the workflow; sections Overview, When to Use, Quick Reference (commands table), Implementation (numbered steps), Common Mistakes. Keep each under ~400 words. Write in the same plain style as spec §9.

Frontmatter (exact):

```yaml
---
name: scope-rig-run
description: Use when running the GHP scope regression rig, reading its report, or triaging a FAIL, KNOWN-FIXED or KNOWN-CHANGED result into a GitHub issue
---
```

```yaml
---
name: scope-rig-extend
description: Use when adding a scope-rig scenario for a documented GHP claim, refreshing the gh query corpus after a gh upgrade, or adding GraphQL analyzer table entries that the corpus test reports
---
```

Content: spec §9 steps, with these exact commands: `CGO_ENABLED=0 go build -o /tmp/scoperig ./tools/scoperig`; `/tmp/scoperig validate`; `/tmp/scoperig run --out /tmp/ghp-rig/reports/$(date -u +%Y%m%dT%H%MZ).json`; `/tmp/scoperig run --only '<scenario id>'`; `gh issue list -R goodtune/ghp --search "<claim id>" --state all`; `gh issue create -R goodtune/ghp --label scoperig --title "scoperig: <claim id> <claim> fails" --body-file <file>`; `/tmp/scoperig oracle --gh-version auto`; `go test ./internal/proxy -run GHCorpus -count=1`. Exit-code table from spec §3.7. Issue body template from spec §9 step 6. Common mistakes to list: echoing `GHP_USER_TOKEN`; filing a product issue for an exit-2 ERROR; adding a field to `alwaysAllowedFields` to make the corpus pass (point to CLAUDE.md "GraphQL Scope Mapping"); write scenarios outside W; forgetting `observed:` with `known_issue`; checking in reports.

GREEN check for skills (writing-skills TDD): dispatch one subagent per skill with only the skill text and the repo, asking: (run) "the report shows `GQL-C33.unknown-object-field FAIL want 403, got 200`; what do you do?" and (extend) "gh 2.103 added a field `mergeQueueEntry` and the corpus test fails; what do you do?". Pass if the answers follow the skill's steps (reproduce with `--only`, search issues, file, set `known_issue` + `observed:`; respectively run oracle, pick the stricter table per CLAUDE.md, add the unit test, update corpus). Record the answer summary in the commit message body.

- [ ] **Step 1:** Write both files.
- [ ] **Step 2:** Run the two subagent checks above; fix wording if an answer skips a step.
- [ ] **Step 3:** `grep -nE 'gh[opsurx]_[A-Za-z0-9]{8,}|ghpr_[A-Za-z0-9]' .claude/skills/scope-rig-*/SKILL.md` → no output.
- [ ] **Step 4: Commit** `git add .claude/skills/scope-rig-run/SKILL.md .claude/skills/scope-rig-extend/SKILL.md && git commit -m "docs(skills): add scope-rig-run and scope-rig-extend skills"`

---

### Task 23: Docs page and nav

**Depends on:** T16–T21

**Files:**
- Create: `docs/development/scope-regression-rig.md`
- Modify: `mkdocs.yml` nav (line ~58): change `- Development: development.md` to

```yaml
  - Development:
    - Overview: development.md
    - Scope Regression Rig: development/scope-regression-rig.md
```
- Modify: `docs/development.md` (one-paragraph link to the new page)
- Modify: `CLAUDE.md` "Project Structure" block: add `tools/scoperig/  Scope regression rig (operator tool, not shipped)` and `rig/  Rig claims, profiles, scenarios and gh query corpus`

Page sections (match the code; check every flag against `scoperig --help`):
1. What it is (spec §1 intent, three sentences) and what it is not (iteration-1 non-goals).
2. Requirements: Go 1.24, `gh` on `PATH` or `GHP_RIG_GH`, an admin session token, fixture repos.
3. Environment table (spec §3.8) and `rig/config.yaml`.
4. Fixtures: `scoperig fixtures ensure` and `--create-fixtures` (state that it creates private repos on the owner's account and is the only command that does).
5. Running: `make scoperig-validate`; the live invocation:

```bash
export GHP_SERVER_URL=https://ghp.touchtechnology.network
export GHP_USER_TOKEN=...   # from 'ghp auth login'; never paste it into issues or logs
make scoperig
./scoperig run --out /tmp/ghp-rig/reports/run.json
```
6. Reading the report: statuses, exit codes (§3.7), confidence formula, coverage gaps.
7. Safety: side-effect table (spec §8), cleanup guarantees, what to do with leftover token ids (`scoperig sweep`).
8. Corpus test and `scoperig oracle`.
9. Known limitations: no git smart-HTTP, no agent tokens, no expiry-after-wait, `gh` must run outside a github.com checkout (CONS §B4), closed issues and PRs accumulate in W.
10. Links to the two skills.

Also add one line to `docs/features/token-scoping.md` known-limitations: "The scope regression rig tracks open scoping gaps; see Development → Scope Regression Rig." (CLAUDE.md Documentation rule.)

- [ ] **Step 1:** Write the page and nav change.
- [ ] **Step 2: Verify** `uvx --with mkdocs-shadcn==0.10.2 mkdocs build --strict 2>&1 | tail -5` (command from `.github/workflows/pages.yml`). Expected: build succeeds, no warnings about the new page.
- [ ] **Step 3:** For each flag named on the page, `go run ./tools/scoperig <cmd> --help | grep -- '--<flag>'` returns a line.
- [ ] **Step 4: Commit** `git add docs/development/scope-regression-rig.md docs/development.md docs/features/token-scoping.md mkdocs.yml CLAUDE.md && git commit -m "docs: add scope regression rig operator guide"`

---

### Task 24: First live run and triage

**Depends on:** all

**Side effect warning.** This task runs `fixtures ensure --create-fixtures`. It is the one opt-in side effect: it may create three **private** repositories on the operator's GitHub account (`goodtune/ghp-scoperig-a`, `-b`, `-w`) and seed them with a label, issue, branch, PR and release. It also creates and revokes rig tokens on the live instance and writes closed issues/PRs to W. Get explicit confirmation from the human before Step 2.

Requires: `GHP_SERVER_URL`, `GHP_USER_TOKEN` (admin session; obtain from the `ghp` CLI config via `ghp auth login`; never echo it), `gh` 2.102.0 on `PATH`, network access to `https://ghp.touchtechnology.network`.

**Files:**
- Modify: `rig/scenarios/*.yaml` (add `known_issue` + `observed:` from triage)
- Modify: `rig/corpus/gh/2.102.0/*.json` only if triage shows a corpus expectation is wrong
- No report files are added to git.

- [ ] **Step 1: Build and validate**

```bash
CGO_ENABLED=0 go build -o /tmp/scoperig ./tools/scoperig
mkdir -p /tmp/ghp-rig/reports
/tmp/scoperig validate
```
Expected: `0 errors`, exit 0.

- [ ] **Step 2: Fixtures (opt-in side effect)**

```bash
/tmp/scoperig fixtures ensure                     # dry run: prints the plan, exit 3 if repos are missing
/tmp/scoperig fixtures ensure --create-fixtures   # only after human confirmation
/tmp/scoperig fixtures ensure                     # second run: no changes, exit 0
```

- [ ] **Step 3: Run**

```bash
/tmp/scoperig run --out /tmp/ghp-rig/reports/$(date -u +%Y%m%dT%H%MZ)-first.json | tee /tmp/ghp-rig/reports/first.txt; echo "exit ${PIPESTATUS[0]}"
grep -nE 'gh[opsurx]_[A-Za-z0-9]{8,}|ghpr_[A-Za-z0-9]|github_pat_' /tmp/ghp-rig/reports/* ; echo "leak grep exit $?"
```
Expected: the report ends with `tokens: N created, N revoked, 0 leftover`; leak grep exit 1. Exit 1 is expected on a first run (predicted FAILs).

- [ ] **Step 4: Triage** (follow `.claude/skills/scope-rig-run/SKILL.md`)
  - Exit 2/ERROR rows: rig bugs. Fix in the rig (separate commit with a test), re-run. Do not file product issues for them.
  - Predicted KNOWN rows (spec §7): set `known_issue` and `observed:` (the behaviour seen): GH-C51 perm-ro/repo-A cells → #297 (unpinned) or #298 (unmapped) per the first denied exchange; GAP-A1 → #290; GAP-A2 → #291; GAP-A3 → #292; GAP-A6 → #294; GAP-A7 → #295 only if B content is returned (else it PASSes; comment the result on #295).
  - Any other FAIL: reproduce with `/tmp/scoperig run --only '<id>'`; search `gh issue list -R goodtune/ghp --search "<claim id>" --state all`; comment on a matching issue or file a new one with the skill's template and label `scoperig`; then set `known_issue` + `observed:`.
  - GAP rows from unmet `requires`: list them in the summary; no action.
- [ ] **Step 5: Confirm** `/tmp/scoperig run --out /tmp/ghp-rig/reports/$(date -u +%Y%m%dT%H%MZ)-second.json; echo $?` → exit 0, no FAIL, no KNOWN-CHANGED, `0 leftover`. Record the confidence line.
- [ ] **Step 6:** `go test ./tools/scoperig/... && make scoperig-validate` → PASS.
- [ ] **Step 7: Commit** `git add rig/scenarios/ && git commit -m "test(scoperig): record known issues from first live run"` (body: run id, confidence line, list of issues filed or commented). Add corpus files to the same `git add` only if changed.

---

## Self-review notes

- Spec coverage: §2.1 (T16, T21), §2.2 (T6, T10), §2.3 (T11, T16), §2.4 (T15), §2.5 (T13, T24), §2.6 (T4, T5), §2.7 (T10), §2.8 (T22), §3.2a (T8, T12), §3.5 (T16), §5 oracle (T17), §6 (T1, T5), §7 (T18–T20), §8 (T7, T11, T16), §10 docs (T23). Iteration 2+ items are excluded.
- Deviation recorded: `graphQLDecision.Stage` replaced by `Analyzed` + `AnalysisDuration` (T1); same handler metrics.
- Spec §10 names `docs/development/scope-rig.md`; the brief fixes `docs/development/scope-regression-rig.md`, used here.
