---
name: precommit-review
description: Dispatch a five-persona pre-push code review (security, architecture, cross-platform, test & correctness, docs & DX) against the current branch's unpushed changes. Use BEFORE every `git push` of new commits on a feature branch so findings drive a single clean commit series instead of a noisy round-trip with CI reviewers. Skip only when the user explicitly opts out for the current push, or when the push is purely administrative (rebase pointer update, tag, etc.) and touches no code.
---

# precommit-review

Running five review personas locally before the push collapses
the review loop: findings are addressed in-place and the
resulting commit series tells a clear story, instead of a noisy
comment round-trip on the PR after CI reviewers arrive one
commit behind the author.

## When to invoke

Invoke before every `git push` of new commits on a feature
branch. Skip only when:

- The user has explicitly said to skip review for this push, or
- The push is purely administrative (an existing commit being
  re-pushed after a rebase that doesn't change the diff, a tag,
  a branch pointer update).

If you are unsure, run it. The cost is bounded (five short
agent calls) and missing a finding has a real cost (a
public-PR comment loop the author has to babysit).

## How

### 1. Determine what's about to be pushed

```sh
# Unpushed commit summaries on the current branch:
git log --oneline @{upstream}..HEAD 2>/dev/null || git log --oneline origin/main..HEAD

# Full diff to brief the personas with:
git diff @{upstream}..HEAD 2>/dev/null || git diff origin/main...HEAD
```

If the branch has no upstream and `origin/main` doesn't exist
either, fall back to `git status` and `git diff HEAD` so the
personas see at least the uncommitted changes.

### 2. Dispatch the five personas in parallel

Issue **one** message containing five `Agent` tool calls. Each
uses `subagent_type=general-purpose` (or `Explore` if the
persona only needs read-only file inspection — security and
architecture often benefit from `Explore`'s read-window-aware
approach when the change is small).

Brief each persona with:

- Branch name and unpushed-commit summary
- The diff (paste inline for small diffs; for large diffs give
  the exact `git diff` command to run so every persona reviews
  the identical range)
- The persona's lens (see below)
- The relevant `CLAUDE.md` sections to keep the bar consistent
- An instruction: **report in under 250 words** with concrete
  `file:line` references and a severity tag
  (`blocker` / `major` / `minor` / `nit`). Suppress
  "no findings" filler — return a single line saying so if
  there is nothing to report.

### 3. Triage findings

| Severity | Action |
|----------|--------|
| `blocker` | Address before pushing. No exceptions. |
| `major`   | Address before pushing, or push a commit message that explains the deliberate decision to defer. |
| `minor`   | Fix if cheap. Otherwise mention in the commit message. |
| `nit`     | Fix only if trivially co-located with other changes. |

When you decline a `major` finding, the commit message that
declines it should reference the specific persona / finding so a
future reader knows the trade-off was deliberate.

### 4. Push

`git push -u origin <branch>`.

## Persona briefs

Each persona reviews the same diff but applies a different
review lens.

### Security

> Review the diff with a security lens. Cover: credential
> handling (ghx_/gha_ token resolution, AES-256-GCM encrypted
> GitHub tokens, Vault tokens, OAuth client secrets, App
> private keys — never logged, never echoed in error bodies);
> scope enforcement staying deny-by-default (REST endpoint
> scope tables, the GraphQL analyzer's four tables — never
> widen analyzer defaults); token hashes vs raw tokens in the
> database; SSRF / open-egress vectors (forward proxy targets,
> client-supplied URLs or headers reaching outbound dials);
> HTTP header injection (CR/LF) and hop-by-hop header
> hygiene on the passthrough paths; Authorization header
> leakage to redirect targets or mirrors; web UI rules from
> CLAUDE.md (no inline JS handlers, `esc()` is not JS-safe,
> CSRF on admin mutations); SQL injection (parameterised
> queries only); secrets appearing in slog output even at
> Debug level; enterprise header injection bypasses.

### Architecture

> Review the diff with an architectural lens. Cover: package
> boundaries (`internal/proxy`, `auth`, `token`, `server`,
> `database`, `github`, `gitcache`, `web`, `metrics`,
> `crypto`, `config`); the `Store` interface contract kept
> semantically identical across SQLite, Postgres, and Vault
> (sentinel `ErrNotFound` conventions, (nil, nil) reads,
> RETURNING on upserts); AppRegistry / provider lifecycle
> rules from CLAUDE.md (reset on reload, dynamic references,
> no stale providers); migrations parity between
> `postgres/` and `sqlite/` including ON DELETE behaviour and
> uniqueness enforced at the database level; decision-pipeline
> instrumentation (every new decision point timed, bounded
> label cardinality, ObserveDecision/ObserveProxyRequest
> helpers); mutex coverage and atomic swap patterns for
> hot-reloaded state; goroutine lifecycle / context
> propagation tied to the server lifecycle context; duplicated
> logic that should live in one package.

### Cross-platform / portability

> Review the diff for portability and deployment-surface
> behaviour. Cover: `CGO_ENABLED=0` invariant (pure Go — no
> C-backed dependencies creeping in); build tags
> (`signal_unix.go` / `signal_windows.go` split); systemd
> socket activation and unix-socket listener paths; SQLite
> (modernc.org) vs Postgres (pgx) driver behaviour differences
> (time formatting, UUID handling, error strings matched in
> code); Vault KV semantics vs SQL semantics for any new store
> method (withRelogin wrapping, context propagation, no
> float64 round-trips on int64 fields); packaging drift
> (`packaging/` systemd units, default config, goreleaser /
> Dockerfiles) when config or binary behaviour changes; env
> var naming consistency (`GHP_` prefix, koanf mapping).

### Test & correctness

> Review the diff for test coverage and behavioural
> correctness. Cover: tests for the changed code
> (table-driven with `t.Run()`); store contract tests running
> against all backends with every model field asserted, valid
> UUIDs for missing-record probes, `errors.Is(ErrNotFound)`
> paths; handler tests using mux routes or `SetPathValue`
> (bare `r.PathValue()` calls panic); metric tests for every
> new metric; flake risk (sleeps, time-of-day, scheduling or
> randomness dependencies — bound probabilistic assertions);
> data-race hazards under `go test -race` (shared maps,
> counters, reload paths); missing edge cases the diff implies
> (empty slices vs nil, zero weights, malformed input);
> whether assertions are load-bearing (would fail if the
> production change were reverted) rather than vacuous.

### Docs & DX

> Review the diff for docs and developer-experience drift.
> Cover: `CLAUDE.md` alignment (metrics tables, stage lists,
> conventions the diff introduces or violates);
> `docs/admin/configuration.md` env-var table and full YAML
> reference including any new config fields;
> `docs/how-it-works.md` and `docs/features/*` accuracy
> (documented flags/fields/UI elements must actually exist in
> code — verify wiring); mkdocs nav entries for new pages;
> known-limitations sections kept honest as behaviour changes;
> JSON API field naming rules (no ambiguous `app_id`-style
> collisions, list endpoints returning `[]` not `null`);
> comments describing code that no longer exists; `make test`
> / `make build` behaviour; error message quality (actionable,
> consistent casing).

## Anti-patterns this skill exists to avoid

- **Push-then-review.** Findings arriving as PR comments after
  the push force either a rebase (rewriting history other
  reviewers had already commented on) or layered fix commits
  (noisy PR). Pre-push review fixes once, pushes once.
- **Repeated dispatch in a tight loop.** If your last push
  was less than ~5 minutes ago and you're pushing a one-line
  fix that an earlier review explicitly flagged, the personas
  will not have new context. Skip review and reference the
  earlier finding in the commit message instead.
- **Asking the personas to fix things.** Personas review and
  report. The fix is the author's; the personas don't run
  with write access.
