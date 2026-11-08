# Git credential helper with a secure local token cache

## Intent

Coding agents and humans run `git` against repositories that are proxied by
ghp. Today they paste a long-lived `ghx_`/`gha_` token into a credential store
or an environment variable. This feature adds a git credential helper to the
`ghp` binary, in the shape of `gh auth git-credential`: git asks the helper for
a credential, the helper mints a short-lived, repository-scoped token from the
ghp client API, and it caches that token on the local machine so that a
`git fetch` loop does not mint a new token on every call.

The cache favours a TPM when one is reachable, and otherwise lives in a
user-only path. We do not defend against a user who can become `root` on a
shared machine. Use of the helper is optional; each user makes that call.

## Goals

- `git clone`, `fetch`, `pull`, and `push` over HTTPS through ghp work with no
  stored long-lived credential, using tokens minted on demand.
- One token per (server, token type, app, repository, scopes) is reused until
  it is close to expiry. The helper does not mint on every git call.
- The user can pick which GitHub App mints the credential: a command-line flag
  in the gitconfig helper line, or the environment variable `GHP_GIT_CM_APP`.
  When neither is given, the server's default app wins.
- The cached secret material is protected by a TPM when one is reachable,
  else by the best OS facility available without cgo, else by file permissions
  alone, and the user can see which tier is active.
- One command configures git (`ghp auth setup-git`), mirroring `gh auth
  setup-git`.

## Non-goals

- No change to server-side authorisation policy. Agent (`gha_`) tokens stay
  admin-only on the server; proxy (`ghx_`) tokens stay available to every
  authenticated user. The helper reports the server's answer clearly.
- No Secret Service (D-Bus) backend in this iteration. Linux without a usable
  TPM falls back to the file tier. This is a documented follow-up.
- No Secure Enclave on macOS (not reachable without cgo). macOS uses the login
  keychain through `/usr/bin/security`.
- No git-lfs support. LFS endpoints are not mapped on the `github.com` vhost.
- No refresh of the user's `ghpr_` ghp session. When it expires (30 days), the
  helper tells the user to run `ghp auth login`.
- No git `authtype`/`capability[]` protocol extensions. Basic auth with
  `x-access-token` is what the passthrough accepts and it works on every git.

## Anti-goals (would make this a failure even if it works)

- Silently downgrading protection: a cache written under the TPM tier must
  never be rewritten under the file tier because the TPM was momentarily
  unavailable.
- Minting a token wider than the request needs: tokens are always pinned to
  the single `owner/repo` git asked about.
- Leaking tokens to stderr, logs, or `status` output.
- Breaking users who do not opt in. Nothing changes for anyone who does not
  run `ghp auth setup-git` or add the helper to their gitconfig.

## Constraints

- Pure Go, `CGO_ENABLED=0`, single binary. Targets (goreleaser): linux/amd64,
  linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64. Every
  new file must cross-compile for all six.
- Reuse the CLI config layering (`loadCLIConfig` for files + env, then the
  dotvault stanza) so `server_url`, `user_token`, env overrides, and dotvault
  keep working. The helper must never trigger dotvault's interactive login:
  it uses `AuthenticateCached` (see decision 3) because stdin/stdout belong to
  the git protocol and an agent has no terminal.
- Compare GitHub owner/repo/login names with `asciiutil.EqualFold`.
- Tests colocated, table-driven, `httptest` fake server for the ghp API, as in
  `cmd/ghp/main_test.go`.

## Background facts the design relies on

- Clone URLs are the normal `https://github.com/owner/repo.git`; DNS points
  `github.com` at ghp. The helper therefore sees `host=github.com` and must
  mint against the separately configured management `server_url`.
- `POST /api/tokens` (bearer `ghpr_`) creates tokens. Body fields: `type`
  (`proxy`|`agent`), `repositories` (array), `scopes` (comma string),
  `duration` (Go duration), `session_id` (≤128 chars), and for agent tokens
  `app_record_id` and `installation_id`. Response 201 `{token, id, type,
  repositories, scopes, expires_at}`. Rate limit 20/min per IP. Agent type
  returns 403 for non-admins. `app_record_id` on a proxy token returns 400.
- `GET /api/apps` (admin) returns `[{id, name, app_id, is_default, ...}]`.
  `GET /api/apps/{id}/installations` (admin) returns `[{id, account:{login}}]`.
- `DELETE /api/tokens/{id}` revokes (owner or admin).
- The `github.com` vhost accepts Basic auth with username `x-access-token`
  and a `ghx_`/`gha_` password. `git-upload-pack` needs `contents:read`,
  `git-receive-pack` needs `contents:write`. The URL must end in `.git`.
  Invalid or expired tokens get 401; scope denials get 403. On a 401 for a
  request that already carried a credential, git calls the helper's `erase`
  and **fails that git command**; the next git command calls `get` again. A
  revoked or stale cached token therefore costs exactly one failed operation.
- GitHub's `POST /app/installations/{id}/access_tokens` takes `repositories`
  as **bare repository names**. When this design was written, ghp's
  `AppTokenProvider.GetInstallationToken` forwarded the token's `owner/repo`
  entries unchanged. The default path of this feature depends on repo-scoped
  agent tokens working at use time. ghp has to send bare names for that to
  work. The fix landed separately on main in #358 (see decision 7); this
  branch carries no server change.
- go-tpm v0.9.8 (`tpm2`, `tpm2/transport/linuxtpm`, `tpm2/transport/windowstpm`)
  is cgo-free and is already an indirect dependency. `golang.org/x/sys/windows`
  exposes DPAPI (`CryptProtectData`/`CryptUnprotectData`) without cgo.

## Decisions

### 1. Command surface

- `ghp auth git-credential <operation>` is the helper git invokes. Operations
  `get`, `store`, `erase` follow the git credential protocol (stdin
  `key=value` lines to a blank line or EOF; stdout `key=value` lines for
  `get`). Unknown operations exit 0 with no output, as git requires.
- Two extra operations are for humans, never sent by git: `status` prints the
  cache tier in use, cache path, and each entry's repository, token type, app,
  token prefix, and expiry (never the token); `clear` removes every cached
  entry and best-effort revokes each token.
- `ghp auth setup-git [--host github.com]... [--app NAME] [--type proxy]`
  configures the global gitconfig exactly as `gh auth setup-git` does: for
  each host, `git config --global --replace-all credential.https://HOST.helper ""`
  to sever the existing chain, then `--add credential.https://HOST.helper
  "!<ghp> auth git-credential [--host HOST]... [--app NAME] [--type proxy]"`,
  then `git config --global credential.https://HOST.useHttpPath true`.
  Default host list is `github.com`. `<ghp>` is the bare word `ghp` when
  `exec.LookPath("ghp")` resolves to the same file as `os.Executable()`
  (so Homebrew/asdf/nix upgrades do not strand the gitconfig on a versioned
  path), otherwise the unresolved `os.Executable()` path. Every word in the
  helper line passes through a strict shell quoter: unchanged only when it
  matches `^[A-Za-z0-9@%+=:,./_-]+$`, otherwise single-quoted with `'`
  escaped as `'\''`; values containing a newline, carriage return or NUL
  are rejected. An app name is chosen by an admin and copied by users, so it
  must never become shell. It prints what it wrote and warns that any
  previous helper for those hosts (for example `gh`) has been replaced.

### 2. Selecting the token type and the app

| Setting | Flag | Env | Default |
|---|---|---|---|
| App | `--app` | `GHP_GIT_CM_APP` | server default app |
| Token type | `--type` | `GHP_GIT_CM_TYPE` | `agent` |
| Scopes | `--scopes` | `GHP_GIT_CM_SCOPES` | `contents:write` |
| Token lifetime | `--ttl` | `GHP_GIT_CM_TTL` | `1h` |
| Cache tier | `--cache-backend` | `GHP_GIT_CM_CACHE_BACKEND` | `auto` |

Flag beats env beats default. The flags live on `ghp auth git-credential` so
they can be baked into the gitconfig helper line, and the env vars let a user
switch per shell or per invocation (`GHP_GIT_CM_APP=other git push`).

- `--app` accepts either the app record UUID or the app `name` as returned by
  `GET /api/apps` (compared with `asciiutil.EqualFold`). `--app` given as a
  flag together with `--type proxy` is an error. An app that arrives only via
  `GHP_GIT_CM_APP` while `--type proxy` came from the helper line is ignored,
  so an exported env var cannot break a proxy-configured gitconfig.
- `--type agent` (default): the helper lists apps, picks the one matching
  `--app` or, when `--app` is absent, the one with `is_default: true`, or the
  only app when exactly one exists. It then lists that app's installations and
  picks the one whose `account.login` equals the repository owner. It mints
  with `type: agent`, `app_record_id`, `installation_id`, `repositories:
  ["owner/repo"]`. Resolution failures (no apps, no default among several, no
  installation for the owner, 403 because the user is not an admin) are
  reported on stderr in one line that names the thing missing. The 403 for a
  non-admin arrives at `GET /api/apps` (it is `RequireAdmin`), not at the
  mint; the helper's message for a 403 from any of the agent-path calls
  suggests `--type proxy`.
- **Effective scopes for agent tokens.** The installation list already
  carries `permissions` (for example `{"contents": "read"}`). When the scopes
  were *defaulted*, the helper lowers each requested level to what the
  installation grants (`contents:write` becomes `contents:read` when the
  installation has only read) and uses the lowered scopes for the mint and
  stores them on the cache entry. The cache key uses the *requested* scopes
  (decision 3) so a cache hit needs no API call. When the user passed `--scopes`/`GHP_GIT_CM_SCOPES` explicitly
  and the installation cannot grant them, the helper fails at mint time with a
  one-line message naming the permission and the level the installation has.
  Without this, GitHub returns 422 for the installation token, ghp turns that
  into a 401, git erases, and every retry mints another unusable token.
- The existing `resolveAppByName`, `resolveDefaultAppID` and
  `resolveInstallationByLogin` helpers in `cmd/ghp/token.go` use
  `strings.EqualFold`. The helper's resolution code lives in `internal/gitcred`
  and uses `asciiutil.EqualFold`; the three `token.go` call sites are switched
  to `asciiutil.EqualFold` in the same change (CLAUDE.md rule, #317).
- `--type proxy`: the helper mints `type: proxy`, `repositories:
  ["owner/repo"]`, no app fields. The token is backed by the user's own
  GitHub identity, so pushes are attributed to them. This is the path for
  users without the ghp admin role.
- Scopes default to `contents:write` because git cannot tell the helper
  whether a `get` is for a fetch or a push, and git retries only on 401, not
  on 403. Scope strings are validated client-side with
  `token.ParseScopeString`.
- `session_id` is set to `git-credential:<hostname>` (truncated to 128) so
  the tokens are recognisable in `ghp token list` and the admin UI.

### 3. The `get` operation

1. Read the request. Require `protocol=https`. Require `path`; strip a
   leading `/`, take the first two segments as `owner/repo`, strip a trailing
   `.git` from `repo`. If `path` is missing or has fewer than two segments,
   print one stderr line telling the user to run `ghp auth setup-git` (which
   sets `useHttpPath`), exit 1 with no stdout. Git then falls through to the
   next helper or prompts.
2. Load the CLI config in two phases so a cache hit never touches dotvault:
   - Phase A: `loadCLIConfig()` (system file, user file, env). This is cheap
     and never prompts.
   - Phase B (only on a cache miss, or when phase A left `server_url`
     empty): resolve the dotvault stanza non-interactively. The dotvault
     reader gains an `AuthenticateCached` path; `ErrLoginRequired` is
     reported as "dotvault login required: run `ghp auth status` in a
     terminal to log in", exit 1. If after phase B `server_url` or
     `user_token` is empty, print "not logged in: run ghp auth login",
     exit 1.
3. Compute the cache key: SHA-256 over `server_url` (from phase A, or phase B
   when A had none; trailing `/` trimmed), an **identity** value, `type`, the
   app selector string as given (`--app` value or empty), `owner/repo`
   lower-cased with `asciiutil.ToLower`, and the normalised requested scopes
   (before any lowering in decision 2; the lowered scopes are stored on the
   entry). The identity is the hex SHA-256 of phase A's `user_token` when it
   is non-empty, else the literal `dotvault`. It is also stored on the entry
   and a hit whose identity differs is a miss. Without it two ghp sessions on
   one OS account (an admin's dotvault token next to a non-admin's
   `GHP_USER_TOKEN`) would share cached `gha_` tokens and bypass the server's
   admin-only rule.
4. Take the file lock, read the cache, release the lock. If an entry exists
   for the key and `expires_at` is more than `minRemaining = 5m` away, return
   it. The lock is never held across a network call: a cold
   `git clone --recurse-submodules -j8` must not serialise eight mints behind
   one 10-second lock.
5. Otherwise run phase B if it has not run, mint (section 2) with no lock
   held, then take the lock again, re-read, store `{token, token_id, type,
   app_record_id, app_name, owner/repo, scopes (effective), expires_at,
   minted_at, identity}` under the key (overwriting whatever another process
   stored meanwhile; a rare double mint costs one extra short-lived token and
   is accepted), commit, release, and return the token just minted. If the
   lock cannot be taken within 10 s at either point, print one stderr line
   and continue without the cache (exit 0 with the minted token). Tokens with
   no expiry (`expires_at: null`) are never requested; `--ttl never` is
   rejected client-side.
7. The helper also takes a repeatable `--host` flag (default `github.com`).
   A request whose `host` is not in that list is refused with one stderr
   line, exit 1, so a helper line placed under a generic `credential.helper`
   cannot hand a ghp token to an arbitrary https host. `setup-git` bakes
   `--host X` into the helper line only for non-default hosts.
6. Output: `username=x-access-token`, `password=<token>`,
   `password_expiry_utc=<unix seconds>` (git ≥ 2.41 skips expired entries on
   its own; older gits ignore the line). Never `quit=true`.

Mint failures print a one-line stderr message and exit 1. A 401 from
`/api/tokens` is reported as "ghp session expired or invalid: run ghp auth
login". A 429 is reported as rate limited with the retry hint. The server's
`POST /api/tokens` limit (20/min per IP) is unchanged in this iteration: the
cache keeps a warm machine far below it, and a cold cache with more than
twenty submodules, or many agents behind one NAT, surfaces as a clear 429
message. A per-user or configurable limit is a follow-up.

### 4. `store` and `erase`

- `store` is a no-op (exit 0). The helper is the source of truth.
- `erase` computes the same key from the request and, under the lock,
  deletes the entry only when git sent no `password` or the `password`
  equals the cached token (an erase of a stale token must not delete a
  fresher one another process just minted). It commits, releases the lock,
  and then best-effort calls `DELETE /api/tokens/{token_id}` for the deleted
  entry. `clear` likewise snapshots, deletes, commits, releases, then
  revokes. Failures to revoke are logged to stderr at one line and do not
  change the exit code (always 0). Git sends `erase` after a 401 and then calls `get` again, which
  mints a fresh token.

### 5. The cache

- Location: `filepath.Dir(userCLIConfigPath())/git-credential/`, which is
  `$HOME/.config/ghp/git-credential/` on every OS (the CLI does not use
  `os.UserConfigDir()`). Files: `cache.enc` (the envelope), `cache.lock`, and
  `tier` (see below). Directory 0700, files 0600, writes via temp file +
  rename. Existing files with looser permissions are tightened on write.
- Locking: an exclusive advisory lock on `cache.lock` around every
  read-modify-write (`flock` via `golang.org/x/sys/unix`; `LockFileEx` via
  `golang.org/x/sys/windows`), 10 s timeout then fail with a stderr line. Git
  runs helpers concurrently (parallel submodule fetch), and without the lock
  two processes would both mint and one would overwrite the other.
- Envelope (JSON): `{version: 1, backend: "tpm"|"dpapi"|"keychain"|"file",
  wrapped_key: <bytes>, nonce, ciphertext}`. `ciphertext` is AES-256-GCM of
  the JSON entry map under a random 32-byte data-encryption key (DEK), with
  the header fields (`version`, `backend`, `wrapped_key`) as additional
  authenticated data. `wrapped_key` is the DEK as protected by the backend.
- Backend interface (`internal/securestore`):
  `type KeyProtector interface { Name() string; Wrap(dek []byte) ([]byte, error); Unwrap(wrapped []byte) ([]byte, error) }`
  plus `Available(name) error` probes and `Select(preference string)
  (KeyProtector, error)`.
- Tiers, probed in order under `auto`:
  1. `tpm` (linux, windows): open `/dev/tpmrm0` (fallback `/dev/tpm0`) or the
     Windows TBS. Probe `TPM_PT_PERMANENT.ownerAuthSet`, `inLockout`, and
     `TPM_PT_STARTUP_CLEAR.shEnable`; any of those set wrongly means "not
     available". `Wrap` creates the ECC SRK (`tpm2.ECCSRKTemplate`, owner
     hierarchy, empty auth, never persisted), `TPM2_Create` of a keyedHash
     sealed object holding the DEK (FixedTPM, FixedParent, UserWithAuth,
     NoDA, no PCR policy), flushes, and returns the marshalled public+private
     blobs. `Unwrap` recreates the SRK, loads, unseals, flushes. A
     `TPM_RC_INTEGRITY` on load means the blob belongs to another TPM; the
     cache is discarded. No PCR binding: a token cache gains nothing from
     boot-state gating and would break on every firmware update.
  2. `dpapi` (windows): `CryptProtectData` of the DEK with
     `CRYPTPROTECT_UI_FORBIDDEN`, user scope, a fixed application entropy
     string.
  3. `keychain` (darwin): the DEK, base64, stored as a generic password with
     `service=ghp-git-credential`, `account=<cache dir path hash>` through
     `/usr/bin/security -i` (secret on stdin, never argv). `wrapped_key`
     holds the account name.
  4. `file` (all): `wrapped_key` is the DEK itself. Documented honestly: this
     tier protects against nothing beyond the 0600 permission bits. The
     helper prints a one-time stderr notice when it first writes a cache
     under this tier ("cache protected by file permissions only; see docs").
- Tier strength order: `tpm` > `dpapi` > `keychain` > `file`.
- The chosen tier is recorded twice: in the envelope (so `Unwrap` knows how
  to read it) and in the plain-text file `tier` in the cache directory,
  which is the **minimum tier** for this cache directory. `tier` survives
  `clear`, a `TPM_RC_INTEGRITY` discard, and envelope corruption, so a TPM
  that is briefly unavailable can never cause an `auto` run to create a
  `file` cache on a machine that has used the TPM before.
- Under `auto`: on a write with no envelope, probe tiers strongest first and
  pick the first available one that is **not weaker than `tier`**; if its
  `Wrap` fails (a macOS keychain that is locked in a headless session), move
  on to the next tier that still satisfies the minimum; if none qualifies,
  mint without caching and print one stderr line. On read, an envelope whose
  recorded backend is weaker than `tier` is discarded, never used or
  rewritten. On every open, existing `cache.enc`, `cache.lock` and `tier`
  are chmod'ed to 0600. When the tier is raised, the `tier` file is written
  before the new envelope is renamed into place. On a write with
  an existing envelope, if a tier stronger than the envelope's is available,
  re-create the envelope under it (entries are only a cache; dropping them is
  fine) and raise `tier`. Otherwise keep the envelope's tier.
- If `Unwrap` fails on a later run (keychain locked in an SSH session, TPM
  unavailable), the helper mints without caching for that invocation and
  prints one stderr line; it never rewrites the envelope under a weaker
  tier.
- `--cache-backend none` disables caching for that invocation and leaves
  the files alone. `--cache-backend <tier>` is an explicit, informed choice:
  if that tier is unavailable the helper fails rather than falling back; if
  it differs from the envelope's tier the envelope is re-created under it
  and `tier` is set to it, with a stderr notice when this is a downgrade.
- Cache entries are keyed as in section 3; `clear` snapshots the entries,
  removes the file, releases the lock, and then revokes what it can (decision
  4).

### 6. Threat model (goes in the docs verbatim or near it)

- Protects: tokens at rest against another local user without root, against
  copies of the home directory (TPM, DPAPI and keychain tiers only), and
  against the long-lived credential sprawl of pasting a `gha_` token into a
  plaintext store. Tokens are short-lived (1h default) and pinned to one
  repository.
- Does not protect: against `root` or an administrator on the same machine,
  against malware running as the same user while the user is logged in, or
  against the user's own `ghpr_` session token in `~/.config/ghp/config.yaml`,
  which this feature does not move. Those are explicit non-goals.
- The file tier is file permissions only; the docs say so, `status` says so.

### 7. Server fix: bare repository names for installation tokens

The server fix landed separately on main in #358; this branch carries no
server change. #358 reads the installation's account login from GitHub and
requires every agent-token `owner/repo` entry's owner to equal it (ASCII case
fold). It sends GitHub the bare names. It fails closed: an owner mismatch, a
malformed entry or a failed account lookup means no installation token is
minted. `POST /api/tokens` (and `PATCH` of an agent token's repositories)
returns 400 naming the repository when its owner is not the installation
account. The helper prints that server message. The scope rig should gain a
live clone with a repo-scoped agent token as a follow-up.

### 8. Documentation

- New page `docs/features/git-credential-helper.md`: what it does, setup
  (`ghp auth setup-git`), picking an app (`GHP_GIT_CM_APP`, gitconfig
  variants), token type for non-admins, the cache tiers and how to check
  them, the threat model, and known limitations: clone URLs must end in
  `.git`, `useHttpPath` is required, LFS unsupported, agent tokens are
  admin-only, `ghpr_` session expires in 30 days, git ≥ 2.41 for
  `password_expiry_utc`, Linux TPM access needs membership of the `tss`
  group, macOS keychain is locked in non-GUI sessions, Windows standard
  users rely on the TBS allow list, a revoked or stale token costs one
  failed git command before the next one mints afresh, and the server's
  20/min token-creation limit applies to cold caches.
- `docs/cli/auth.md` gains `git-credential` and `setup-git` sections;
  `docs/cli/index.md` env var table gains the `GHP_GIT_CM_*` variables;
  `mkdocs.yml` nav gains the feature page.
- `CLAUDE.md` project structure gains `internal/gitcred/` and
  `internal/securestore/`.

### 9. Testing

- Protocol parsing/formatting, path → owner/repo, key derivation, envelope
  round trip with a fake `KeyProtector`, lock contention (two goroutines),
  cache reuse vs re-mint around the 5-minute margin, `erase` revokes and
  deletes, `store` is a no-op, unknown op is silent.
- Helper end-to-end against an `httptest` ghp API fake covering: agent path
  with `--app` by name and by id, default app, single app, no default among
  two, no installation for owner, installation with `contents: read`
  lowering the defaulted scopes, explicit `--scopes` exceeding the
  installation failing, 403 from `GET /api/apps` suggesting proxy, proxy
  path, 401 session expired message, 429, dotvault `ErrLoginRequired`
  message, cache hit without any dotvault call.
- Tier state: `auto` refuses a weaker tier than `tier`; `auto` upgrades when
  a stronger tier becomes available; explicit `--cache-backend` re-creates
  and records; `clear` keeps `tier`.
- `setup-git` against a temporary `GIT_CONFIG_GLOBAL` file, asserting the
  exact config lines written.
- TPM: a test gated on `GHP_TEST_SWTPM=<unix socket path>` that seals and
  unseals through `tpm2/transport/linuxudstpm` against `swtpm`; the CI test
  workflow installs `swtpm` on the Linux runner and sets the variable.
  Without the variable the test is skipped with a message.
- Cross-compilation check in `make check` or CI: `go vet ./...` under
  `GOOS=windows GOARCH=amd64`, `GOOS=windows GOARCH=arm64` and `GOOS=darwin
  GOARCH=arm64` so the build-tagged files cannot rot.

## Left to the builder

- Exact Go package/file split inside `internal/gitcred` and
  `internal/securestore` (the plan fixes it).
- Error message wording, as long as each failure is one stderr line that
  names the missing thing and the remedy.
- Whether `status` output is a table or key/value lines.
- Retry behaviour for transient TPM return codes (`TPM_RC_RETRY`,
  `TPM_RC_YIELDED`): a short bounded retry is fine.

## Follow-ups (not in scope)

- Scope rig scenario: live `git clone` and `git push` with a repo-scoped
  `gha_` token after decision 7.
- Per-user or configurable `POST /api/tokens` rate limit.
- Secret Service backend for Linux desktops without a TPM.
- A non-admin "list apps I may use" endpoint and per-user app authorisation,
  if agent tokens are to be opened beyond admins.
- Moving the `ghpr_` session token into the same protected cache.
- Export dotvault's cgo-free TPM `securestore` so ghp can depend on it rather
  than carry its own port.
