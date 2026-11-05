---
name: scope-rig-extend
description: Use when adding a scope-rig scenario for a documented GHP claim, refreshing the gh query corpus after a gh upgrade, or adding GraphQL analyzer table entries that the corpus test reports
---

# Extend the scope regression rig

## Overview

Scenarios (`rig/scenarios/*.yaml`) test claims (`rig/claims.yaml`) with token profiles (`rig/profiles.yaml`). The gh corpus (`rig/corpus/gh/<version>/`) records the GraphQL queries gh sends, with a `verdict` per profile; `internal/proxy/graphql_ghcorpus_test.go` checks the analyzer against it. `validate` (no network) enforces the safety rules.

## When to Use

- A documented claim has no scenario, or a new claim was added.
- gh was upgraded.
- The corpus test reports a denied field, or "fixed; remove known_issue".

## Quick Reference

| Task | Command |
|---|---|
| Build | `CGO_ENABLED=0 go build -o /tmp/scoperig ./tools/scoperig` |
| Validate | `/tmp/scoperig validate` |
| Try one | `/tmp/scoperig run --only '<scenario id>'` |
| Capture gh | `/tmp/scoperig oracle --gh-version auto` (see `scoperig oracle --help`) |
| Import captures | `go run ./tools/scoperig/corpus/importghdebug -in <dir> -out rig/corpus/gh/<ver> -gh-version <ver> -owner cli -repo cli` |
| Corpus test | `go test ./internal/proxy -run GHCorpus -count=1` |

## Implementation

**New scenario**
1. Find the claim in `rig/claims.yaml`; add it with its doc anchor if missing.
2. Pick an existing profile; add one only if none fits.
3. Copy the closest scenario. Id is `<claim>.<slug>`, e.g. `PERM-C11.contents-read-blocks-put`. Set `kind` (`rest`, `graphql`, `gh`, `token_api`), `requires`, `expect`.
4. Writes target `{{.RepoW}}` only, with run-unique names (`scoperig-{{.RunID}}-...`) and a `cleanup:` block.
5. `gh` writes may use only flags in `ghFlagTable` (`tools/scoperig/scenario/ghcheck.go`); read-only subcommands are in `ghReadOnly`.
6. A GraphQL mutation with an unrestricted profile needs a reviewed entry in `mutationWriteAllowlist` (`gqlcheck.go`), like the `GQL-C31.*` pair.
7. `validate` must print `0 errors`; then run `--only`.

**gh upgrade**
1. Run `oracle` (or capture with `GH_DEBUG=api` and run the importer); expectations already in the directory are kept.
2. Review the diff. For each new denied field, follow CLAUDE.md "GraphQL Scope Mapping": pick the table, prefer the stricter mapping.
3. Set `verdict` per profile; where today differs, add `known_issue` and `current`. Run the corpus test.

**Analyzer fix**
1. Add the entry to `internal/proxy/graphql.go` (alphabetical) and the unit test in `graphql_test.go` that CLAUDE.md requires.
2. Run the corpus test. For each "fixed; remove known_issue and current" failure, remove both from that entry.
3. Remove the matching scenario `known_issue`/`observed:` once the instance runs the fix.

## Common Mistakes

- Adding a field to `alwaysAllowedFields` to make the corpus pass. That table is metadata only; see CLAUDE.md "GraphQL Scope Mapping".
- Write scenarios outside W, or without `cleanup`.
- `known_issue` without `observed:`.
- Committing run reports.
