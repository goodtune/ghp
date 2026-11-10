# Scope rig batch 5: #360, GIT-C48, PERM-C18, LIFE-C39, git credential helper

Rig-only change (tools/scoperig, rig/, rig skills). No product code.

## #360 latency budget and first-appearance series

Problem 1. The `total` p99 budget (15ms) fails on every run because `total`
includes `request_body_read`, the time a GraphQL client takes to upload its
body. That is client time, not GHP overhead.

Design. Keep the raw `total` row (no budget, so it never flags). Add a
derived row `total_excl_body_read` per token type that carries the 15ms
budget. Histograms cannot be subtracted per request, so the row is an
estimate:

- mean: exact, `(sum(total) - sum(request_body_read)) / count(total)`;
- quantiles: `q(total) - q(request_body_read padded)`, clamped at 0. The
  body-read distribution is padded with zero observations up to the total
  count, because requests that read no body (REST, open tokens) have no
  `request_body_read` sample. The estimate is exact when slow totals are the
  slow body reads (the observed case) and never negative.

The rendered report marks the row "(est.)" with a footnote. The row is
built only when total and request_body_read come from the same source
(both increase(), or both raw first-appearance values, see below);
otherwise it is omitted with a latency note.

Problem 2. A series that first appears inside the run window (for example
the first `token_type="agent"` samples after a deploy) shows 0 samples:
`increase()` needs two samples and never counts a series' first value.

Design. Query `_count` by (stage, token_type) at the run start. For every
key that had no series at the start, use the raw cumulative values at the
end (buckets, sum, count) instead of `increase()`: a series that did not
exist at the start began at zero. Same for the end-to-end histogram.
Limitation: a counter reset inside the window for such a series is not
detected (it would undercount), and with several GHP instances behind one
selector a key is "new" only if no instance had it.

## GIT-C48: `kind: git`

New scenario kind `git` with `git_op: clone | push`, `repo: A | B | W` and,
for push, `branch` (templated). The executor runs the system `git` with a
throwaway HOME, `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`, against
`https://github.com/<owner>/<repo>.git`, with
`-c http.curloptResolve=github.com:<port>:<instance address>` so the
connection goes to the instance with SNI and Host github.com (the same
vhost dialing the rest `vhost:` requests use). The token goes in an
`http.extraHeader` Basic credential (`x-access-token:<token>`) written to a
0600 gitconfig file in the throwaway HOME (`GIT_CONFIG_GLOBAL`), never on
the command line or in the environment. `http.followRedirects=false` keeps
the header from following a redirect to another host.
`GHP_RIG_CA_FILE` becomes `GIT_SSL_CAINFO`.

The observation: exit code, redacted stdout/stderr, and `status` parsed from
git's "The requested URL returned error: NNN" line (0 when absent).
A transport failure is retried for clone (read-only) and never for push.

Validation (deny by default): `git_op` must be clone or push; push only to
W, with `branch` containing `{{.RunID}}`, `requires: [github_vhost,
repo_w_push]`, and a cleanup that deletes `refs/heads/<branch>` on W. Clone
needs `requires: [github_vhost]`. Never a write to A or B.

Scenarios: clone A with `repo-A-perm-ro` (exit 0); clone B with
`repo-A-perm-ro` (403); push to W with `perm-contents-ro-W` (403); push to W
with a new `perm-contents-rw-W` profile (exit 0, branch
`scoperig-{{.RunID}}-push`, deleted in cleanup).

## PERM-C18

The CLI embeds no list; the web UI reads `GET /api/github/permissions`
(session auth), which returns permission -> max level. token_api may now
GET that path. Scenario: the response has `$.pull_requests == write`, and
creating a token with `scopes: pull_requests:write` returns 201 (the
manager revokes it).

## LIFE-C39

The instance does not expose `tokens.allow_no_expiry`. New operator-declared
config `instance.allow_no_expiry` (true/false; unset = unknown). Capability
`no_expiry_disallowed` is true only when it is declared `false`. Scenario:
`POST /api/tokens {duration: never}` returns 400 with "not allowed". GAP
(`requires no_expiry_disallowed`) when undeclared. A 201 is revoked by the
manager.

## Git credential helper: `kind: git_credential`, claim CRED-C55

New claim CRED-C55 (docs/features/git-credential-helper.md). The executor
runs `ghp auth git-credential` (binary from `GHP_RIG_GHP`, else `ghp` on
PATH; capability `ghp_cli` when `<ghp> auth git-credential --help` exits 0)
with a throwaway HOME, `GHP_SERVER_URL`/`GHP_USER_TOKEN` in the environment
(no config file, so no dotvault), `--cache-backend file`, `--type agent`
and `--app <agent app record id>` (never the default app). Flow, for repo W:

1. list tokens; `get`; list again: the new token id (session
   `git-credential:*`, repositories [W]).
2. `get` again: same password, no new token on the server (cache hit).
3. the token reads W (`GET /api/v3/repos/W`) and is refused on A.
4. `erase` with that credential: the server shows the token revoked.
5. `get` (mints a new token), `clear`: the server shows it revoked.

The executor returns a JSON summary the scenario asserts on with `json:`
matchers. Every token id it found is revoked in a deferred backstop through
the token manager. Requires `agent_installation` and `ghp_cli`.

## Expected confidence

Base grows from 60 to 61 (CRED-C55). GIT-C48, PERM-C18 and CRED-C55 should
PASS; LIFE-C39 is GAP until the operator declares
`instance.allow_no_expiry: false`. From 53/60 that is about 56/61 (57/61
with the declaration).
