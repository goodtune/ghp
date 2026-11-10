# Rig scenarios for ENT-C50 and BORDER-C46: design

## Goal

Cover two claims that today have no scenario and report GAP:

- ENT-C50 (docs/admin/github-app.md#enterprise-restriction): the
  `sec-GitHub-allowed-enterprise` header is injected, and each exception
  type behaves as documented (header omitted, identity substituted, team
  denied, unauthenticated denied).
- BORDER-C46 (docs/how-it-works.md#blocking-anonymous-git-traffic): with
  `block.anonymous_git`, an unauthenticated request carrying `Git-Protocol`
  returns 401.

Both need instance configuration that the usual rig instance does not have.
The repo owner runs them on a separate enterprise deployment, so they must
be opt-in, run alone in one command, and give a short result to paste back.

## What the rig can observe from outside

The enterprise header goes to GitHub, never back to the client. GitHub only
acts on it when the caller's account is outside the enterprise, and the
operator's own account is normally inside it. So the response alone cannot
show the header. The rig uses GHP's own Prometheus counters, read directly
from the instance's metrics listener (`metrics.listen`, default `:9136`)
before and after each request:

| Behaviour | Observable signal |
|---|---|
| Policy evaluated (header set unless an exception omits it) | `ghp_proxy_decision_duration_seconds_count{stage="enterprise_exception"}` rises by at least 1, and `ghp_enterprise_exception_total` for `header_omitted` and `identity_substituted` does not rise |
| Header omitted | `ghp_enterprise_exception_total{outcome="header_omitted"}` rises |
| Team denied | `outcome="team_denied"` rises, `header_omitted` does not |
| Identity substituted | `outcome="identity_substituted"` rises, `identity_error` does not; response 200 |
| Unauthenticated denied | `outcome="unauthenticated_denied"` rises, `identity_substituted` does not (anonymous request on the github.com vhost) |
| Anonymous git 401 | Response: 401, GHP message `Anonymous git access is not permitted`, `WWW-Authenticate: Basic realm="GitHub"` |

Not observable from outside:

- The header bytes on the wire and the slug value. The stage counter shows
  that the policy ran with a slug configured (`NewEnterprisePolicy` returns
  nil without one, and then no stage sample is recorded), and the outcome
  counters show which branch ran. That the branch then sets or deletes the
  header is covered by `internal/proxy/enterprise_test.go`, not by the rig.
- That GitHub rejects off-enterprise accounts. That is GitHub's behaviour.
- Which identity GitHub saw on a substituted request. The rig checks the
  counter and a 200 only.
- Counters are instance-wide. Other traffic during the run can raise a
  counter: a "min 1" check can then pass by coincidence and a "max 0" check
  can fail. The runbook asks for a quiet instance.

## Design

Operator-declared configuration, no probing, as `border_block` does today:

```yaml
instance:
  anonymous_git: true
  metrics_url: http://ghp.internal:9136/metrics
  enterprise_restriction:
    restricted_repo: owner/repo     # matches no exception
    omit_repo: owner/repo           # plain exception
    team_denied_repo: owner/repo    # team-gated, operator not in the teams
    identity_repo: owner/repo       # identity exception, operator in its teams (if any)
    unauthenticated_repo: owner/repo # identity exception without teams
```

Capabilities (all false when undeclared, so scenarios report GAP):
`anonymous_git`, `ghp_metrics` (metrics_url set), `enterprise_restriction`
(metrics_url and restricted_repo), and `enterprise_exception_omit`,
`_team_denied`, `_identity`, `_unauthenticated` (each also needs
`enterprise_restriction`).

Scenario schema gains `metric_delta`: a list of `{name, labels, min, max}`.
The rig scrapes `metrics_url` before and after the scenario and sums every
sample of `name` whose labels include `labels`. A scenario that would PASS
on its response becomes FAIL when a delta is out of range. A scrape failure
is ERROR. Validation requires `ghp_metrics` in `requires` for any scenario
with `metric_delta`. Templates get `.Enterprise.*` for the configured repos.

An empty header value in a rest request removes that header, so a scenario
can send `Authorization: ""` for an anonymous request.

`run --claims ENT-C50,BORDER-C46` selects the scenarios of those claims,
limits the table and JSON report to them, and prints a one-line
`scoperig-result: {...}` JSON summary to paste back. `--only` also accepts
a comma-separated list of globs.

New content goes in new files where possible (`rig/scenarios/enterprise.yaml`,
`tools/scoperig/deployment.go`, `tools/scoperig/scenario/deployment.go`,
`docs/development/scope-regression-rig-enterprise.md`) to avoid conflicts
with concurrent rig scenario work.

## Tests

Offline, with the existing fake instance: config parsing and validation,
capability derivation, scrape parsing, delta checks, GAP when undeclared,
PASS with a fake metrics endpoint, FAIL when the counter does not move,
`--claims` selection and the paste-back line, anonymous header removal.
