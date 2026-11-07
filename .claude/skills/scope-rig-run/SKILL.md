---
name: scope-rig-run
description: Use when running the GHP scope regression rig, reading its report, or triaging a FAIL, KNOWN-FIXED or KNOWN-CHANGED result into a GitHub issue
---

# Run the scope regression rig

## Overview

`scoperig` mints real tokens on a live GHP instance and checks each documented scope claim (`rig/claims.yaml`) against scenarios in `rig/scenarios/`. A FAIL is a product bug until shown otherwise. The ledger of known issues is the `known_issue:` field on scenarios (`grep -n known_issue rig/scenarios/*.yaml`) and in the gh corpus (`rig/corpus/gh/<version>/*.json`).

## When to Use

- Periodic or pre-release check of an instance.
- After a scoping fix, to confirm KNOWN-FIXED.
- A report shows FAIL, KNOWN-CHANGED or KNOWN-FIXED.

## Quick Reference

| Step | Command |
|---|---|
| Build | `CGO_ENABLED=0 go build -o /tmp/scoperig ./tools/scoperig` |
| Static check | `/tmp/scoperig validate` |
| Fixtures | `/tmp/scoperig fixtures ensure` (creates and revokes one `open` token even when it changes nothing; `--create-fixtures` only to create missing repos, which usually fails for lack of `repo_create`: create `ghp-scoperig-{a,b,w}` by hand with `gh repo create --private`) |
| Full run | `/tmp/scoperig run --out /tmp/ghp-rig/reports/$(date -u +%Y%m%dT%H%MZ).json` |
| One scenario | `/tmp/scoperig run --only '<scenario id>'` (glob) |
| Leftover tokens | `/tmp/scoperig sweep` |
| Find issue | `gh issue list -R goodtune/ghp --search "<claim id>" --state all` |

| Exit | Meaning | Action |
|---|---|---|
| 0 | No FAIL, no ERROR | Done |
| 1 | FAIL or KNOWN-CHANGED | Triage each |
| 2 | ERROR (no FAIL), incl. cleanup failure | Rig problem: fix the rig, no product issue |
| 3 | Could not start (config, validation, instance, session token) | Fix config or instance |

## Implementation

1. If `rig/config.yaml` does not exist, `cp rig/config.example.yaml rig/config.yaml` and replace `OWNER` in the fixtures. Needs `gh` and `git` on PATH. Export `GHP_SERVER_URL` and `GHP_USER_TOKEN` from the `ghp` CLI config (`~/.config/ghp/config.yaml`: `server_url`, `user_token`). If that config has a `dotvault:` stanza, the token is the Vault field named by `dotvault.fields.user_token`, under service `dotvault.service`, read with the dotvault client config `dotvault.config` (default path when empty); read it straight into the variable. Optional: `GHP_RIG_REPO_A/B/W` override `rig/config.yaml`. Never echo them. The live run does not use your `gh` login (gh gets the minted token); only `oracle` does, and it needs it in `hosts.yml` or the macOS keychain (no Linux Secret Service).
2. Validate, ensure fixtures, run with `--out` under `/tmp/ghp-rig/reports/`. `--skip-known` skips known scenarios.
3. Read the report: KNOWN-CHANGED rows are at the top; then per-claim results; the confidence line is `PASS/(base-KNOWN)`.
4. FAIL: reproduce with `--only '<id>'`. Search issues. If none, write the body and run `gh issue create -R goodtune/ghp --label bug [--label security] --title "scoping: <claim id> <claim> fails" --body-file <file>`. Add `--label security` when the result lets the token do more than its scope allows. Then set `known_issue: <issue URL>` and an `observed:` block (today's behaviour, same shape as `expect:`) on the scenario; re-run `--only` and confirm KNOWN.
5. KNOWN-FIXED: remove `known_issue` and `observed:`; confirm PASS.
6. KNOWN-CHANGED: comment the new observation on the issue, update `observed:` and matching corpus entries (corpus: `current`), confirm KNOWN.
7. Open a PR for scenario changes. A small clear fix goes in a separate PR that removes `known_issue`.

Issue body (sections as issues #290-#299):

```
## Summary
<claim id>: <one-line claim> (<doc link>) does not hold.
## Evidence
Scenario <id>, profile <name> (no token values). Expected: <expect>.
Observed: <status>, GHP message, first denied gh exchange.
Instance version <v>, run id <id>.
## Impact
<bypass: the token can do more than its scope allows (security), or over-denial: a scoped action is refused>
## Proposed fix
Code pointer: <file:line>.
## Verification
/tmp/scoperig run --only '<id>' passes.
```

## Common Mistakes

- Echoing or pasting `GHP_USER_TOKEN` or any minted token.
- Filing a product issue for an exit-2 ERROR.
- `known_issue` without `observed:`.
- Committing reports; they stay in `/tmp/ghp-rig/reports/`.
- `--create-fixtures` by default; it is the one opt-in side effect.
