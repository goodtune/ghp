# #294: agent-token repositories sent to `access_tokens` as `owner/repo`

## Problem

Agent (`gha_`) tokens store repository restrictions as `owner/repo`. The proxy
passes that list unchanged to `POST /app/installations/{id}/access_tokens`.
GitHub's `repositories` field takes bare repository names that belong to the
installation's account (`repository_ids` takes numeric IDs). The current body is
therefore wrong: GitHub either rejects the mint or does not narrow the token.
Runtime behaviour is not yet verified (rig, #306).

## Options

- **(a) Strip the owner.** Check that every owner equals the installation's
  account login, then send bare names.
- **(b) Resolve `repository_ids`.** Needs a repository lookup per name (an extra
  GitHub round trip per repository, or a cached installation repository list).

## Decision: (a)

The installation account is known at mint time from
`GET /app/installations/{id}` (`account.login`), with the App JWT. GHP already
calls this endpoint for permission diagnostics. Option (a) needs one cached
lookup per installation; option (b) needs per-repository resolution and adds
no extra safety, because an installation can only reach repositories of its own
account.

### Account login

- `AppTokenProvider.InstallationAccountLogin(ctx, installationID)` reads
  `account.login` from `GET /app/installations/{id}`.
- Cached per installation ID for one hour (the account of an installation does
  not change; a deleted installation fails at mint anyway).
- Not stored at app registration: one app has many installations, and the
  token only records the installation ID.

### Mint time (`GetInstallationToken`)

- Empty / nil repository list: no `repositories` field (no narrowing), as today.
- Entries with an owner (`owner/repo`): the owner must equal the account login
  under `asciiutil.EqualFold` (#317). The body carries the bare name.
- Entries without an owner (bare names, used by enterprise exception identity
  substitution, which already pins the owner by installation lookup): passed
  through unchanged.
- Account lookup fails, an owner mismatches, or an entry is malformed: return
  an error and send no request. GHP never sends an unnarrowed or wrongly
  narrowed request. Fail closed.

### Creation time (API)

`POST /api/tokens` (type `agent`) and `PATCH /api/tokens/{id}` (agent tokens,
when `repositories` is set) resolve the account login for the token's app and
installation and reject:

- an entry that is not `owner/repo` → 400;
- an owner that is not the installation account → 400 naming the repository;
- account lookup failure → 502 (cannot verify; token not created);
- no app provider available to verify → 503.

### Unchanged

Proxy-side `owner/repo` allowlist enforcement is unchanged. GitHub-side
narrowing is defence in depth.

## Tests

- `internal/github`: httptest fake GitHub records the exact `access_tokens`
  body: bare names; owner mismatch rejected with no POST; mixed-case owner
  accepted; empty list sends no `repositories`; account lookup failure sends
  no POST; account login cached.
- `internal/server`: create and PATCH handler tests for the 400/502 paths and
  the happy path.

## Needs runtime verification (#306)

That GitHub accepts the bare-name body and that the minted token is narrowed
(a request to a repository outside the list returns 404/403 with the
installation token).
