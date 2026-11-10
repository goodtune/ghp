# Rig runbook: enterprise deployment (ENT-C50, BORDER-C46)

Use this runbook to check two claims on a GHP deployment that has the
enterprise restriction and anonymous git blocking turned on:

- **ENT-C50**: GHP injects the enterprise restriction header, and each
  exception type does what [Enterprise Restriction](../admin/github-app.md#enterprise-restriction) says.
- **BORDER-C46**: with `block.anonymous_git`, an unauthenticated git request
  that carries `Git-Protocol` gets `401`. The rig sends anonymous GET
  requests for the public repository `octocat/Hello-World` through the
  deployment's `github.com` virtual host. If an egress policy blocks that
  request to GitHub, the control scenario (without `Git-Protocol`) fails.

The run sends only GET requests to GitHub. It changes nothing on GitHub. On GHP's management API it creates and revokes one rig token (POST and DELETE).

## What the rig can and cannot see

GHP sends the enterprise header to GitHub, not back to the client. So the
rig reads GHP's own metrics before and after each request:

- `ghp_proxy_decision_duration_seconds_count{stage="enterprise_exception"}`
  shows that the enterprise policy ran on the request.
- `ghp_enterprise_exception_total{outcome=...}` shows which exception
  branch ran: `header_omitted`, `team_denied`, `identity_substituted` or
  `unauthenticated_denied`. GHP also counts `team_denied` when it cannot
  resolve the caller's login, not only when the caller is outside the teams.

The rig cannot see the header bytes, the slug value, GitHub's own decision,
or which identity GitHub saw. Unit tests in `internal/proxy` cover those
parts. The counters are for the whole instance. The rig narrows the stage
count to the request's virtual host and token type, and expects each
counter to rise by exactly one. If a counter rises by more, other traffic
reached the instance during the request, and the scenario reports ERROR,
not PASS. The rig cannot detect a defect that exactly one concurrent
matching request hides: it catches only rises above one. Run it when the
instance is quiet.

## Steps

1. **Check the prerequisites.**
    - Go 1.26 or later (the toolchain in go.mod is downloaded automatically) and a checkout of the `ghp` repository.
    - The GHP deployment has `github.enterprise_slug` set and
      `block.anonymous_git: true`.
    - The GHP metrics listener (`metrics.listen`, default `:9136`) is
      reachable from your machine over plain HTTP or HTTPS.
    - The deployment serves the `github.com` virtual host, and your machine
      trusts its certificate. If it uses a private CA, set
      `GHP_RIG_CA_FILE` to that CA's PEM file.
    - You have an admin session token (`ghpr_...`) for the deployment, from
      `ghp auth login`.

2. **Choose one repository for each exception type.** Each repository
   except `restricted_repo` must match an entry in the deployment's
   `github.enterprise_exceptions`; `restricted_repo` must match none. You
   can leave out any type; its scenario then reports GAP.

    | Field | The repository must be |
    |---|---|
    | `restricted_repo` | Matched by no exception. Required for any ENT-C50 scenario. |
    | `omit_repo` | Matched by an exception with no `teams` and no `identity`. |
    | `team_denied_repo` | Matched by an exception with `teams` that do **not** include you. |
    | `identity_repo` | Matched by an exception with an `identity` app installed on its owner. If it has `teams`, you must be in one. |
    | `unauthenticated_repo` | Matched by an exception with an `identity` and **no** `teams`. |

3. **Write the config.** Copy the example and edit it:

    ```bash
    cp rig/config.example.yaml rig/config.yaml
    ```

    Set these fields in `rig/config.yaml`. Replace each placeholder.

    ```yaml
    instance:
      host: ""                        # leave empty: taken from GHP_SERVER_URL
      anonymous_git: true
      metrics_url: http://GHP-HOST:9136/metrics
      enterprise_restriction:
        restricted_repo: ENT-ORG/ENT-REPO
        omit_repo: EXT-OWNER/OMIT-REPO
        team_denied_repo: EXT-OWNER/TEAM-REPO
        identity_repo: EXT-OWNER/IDENTITY-REPO
        unauthenticated_repo: EXT-OWNER/ANON-REPO
    fixtures:
      repo_a: YOUR-LOGIN/ghp-scoperig-a
      repo_b: YOUR-LOGIN/ghp-scoperig-b
      repo_w: YOUR-LOGIN/ghp-scoperig-w
    ```

    These claims do not use the fixture repositories, and they need not
    exist. But `repo_w` must be under your own GitHub login and its name must
    contain `scoperig`, or the run stops before it starts.

4. **Set the environment.** Do not print the token or paste it anywhere.

    ```bash
    export GHP_SERVER_URL=https://GHP-HOST
    export GHP_USER_TOKEN=ghpr_...
    ```

5. **Run the command.**

    ```bash
    make scoperig
    ./scoperig run --claims ENT-C50,BORDER-C46 --out /tmp/ghp-rig/reports/enterprise.json
    ```

    The run takes less than one minute.

6. **Send back the result.** Copy the last line of the output, which starts
   with `scoperig-result:`, and the exit code (`echo $?`). The line holds
   only:
    - the run id, the GHP version, the exit code and the token counts;
    - a status for each claim;
    - for each scenario: its id, its status, and reasons that the rig builds
      from a fixed list. The reasons are `http_status want=... got=...`,
      `ghp_denial want=... got=...`, `body_contains mismatch`,
      `body_not_contains mismatch`, `header <name> mismatch`,
      `metric <name>{<labels>} want_delta... got_delta=...` (names and labels
      from the scenario file only), `capability_missing <name>`,
      `transport_error`, `metrics_scrape_error`, `interference ...` and
      `other`. A line with `other` adds the note "see the JSON report
      locally".

    The line holds no response text, error message, host, address,
    repository name or token. As a second safeguard, the rig also replaces
    any configured host, IP address or repository name in it. The full
    detail is only in the local JSON file (`--out`). Do not paste that file.

## What the run creates and removes

- At the start, it revokes rig tokens left by earlier runs (session ids that
  start with `scoperig-`).
- It creates one unrestricted `ghx_` token, and revokes it at the end, also
  on failure or Ctrl-C. The `tokens:` field must show `0 leftover`. If it
  does not, run `./scoperig sweep`.
- The identity scenario makes GHP mint one GitHub App installation token
  for `identity_repo`. GitHub expires it after one hour.
- It sends no write request to GitHub.

## Reading the result

| Status | Meaning |
|---|---|
| PASS | The scenario saw the documented behaviour. |
| FAIL | It did not. The detail names the metric or the response field. Metric names in the detail have no `ghp_` prefix. |
| ERROR | The rig could not decide, for example `metrics_url` did not answer, or other traffic moved a counter during the request. Rerun when the instance is quiet. |
| GAP | A field in step 2 or 3 is empty, or the `github.com` virtual host did not answer. The detail names the missing capability. |

A FAIL that names an outcome counter that must not move (`want change <=
0`) can come from other traffic. Rerun once on a quiet instance before you
treat it as a defect.

Exit codes:

- 0: no FAIL, KNOWN-CHANGED or ERROR.
- 1: a FAIL or KNOWN-CHANGED.
- 2: an ERROR, cleanup residue, or a token left live.
- 3: the run could not start.

A run with both a FAIL and an ERROR exits 1.
