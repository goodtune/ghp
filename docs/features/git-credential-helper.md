# Git Credential Helper

`ghp auth git-credential` is a git credential helper built into the `ghp`
binary. It works like `gh auth git-credential`. When git needs a credential
for a repository, the helper mints a short-lived ghp token for that one
repository and gives it to git. You do not store a long-lived `ghx_` or
`gha_` token anywhere.

The helper is optional. Nothing changes for a user who does not run
`ghp auth setup-git` or add the helper to their git config.

## What it does

When git runs `git clone`, `fetch`, `pull` or `push` over HTTPS, it asks the
helper for a credential and sends the repository path. The helper then:

1. Reads `owner/repo` from the path git sent.
2. Mints a token on the ghp server (`POST /api/tokens`). The token is pinned
   to that one `owner/repo`. By default it has the scope `contents:write`
   and lives for 1 hour.
3. Saves the token in an encrypted cache on the local machine.
4. Gives git the username `x-access-token` and the token as the password.

On the next git command for the same repository, the helper returns the
cached token. It reuses a token until 5 minutes before it expires, then
mints a new one. A `git fetch` loop therefore mints about one token per
hour per repository, not one per command.
A cache hit never contacts the ghp server. When `server_url` comes from a
config file or `GHP_SERVER_URL`, a cache hit does not contact dotvault
either.

The helper mints against the ghp management server in your CLI config
(`server_url`), not against the host git talks to. Clone URLs stay the
normal `https://github.com/owner/repo.git`.

The cache is keyed per ghp session identity, as well as by server, token
type, app, repository and requested scopes. The identity is a hash of the
`user_token` found in the config files or `GHP_USER_TOKEN`. When the token
comes only from dotvault, the identity is the word `dotvault`. When a
dotvault stanza overrides a `user_token` that is also in a config file or
`GHP_USER_TOKEN`, the identity is still the hash of that file or
environment token, not of the dotvault token. Two ghp sessions on one OS
account with different file or environment tokens (for example an admin
session and a non-admin session) never share cached tokens. Sessions that
differ only in their dotvault token do share them.

Each token carries the session ID `git-credential:<hostname>`, so you can
find it in the SESSION column of `ghp token list` and in the web UI.

## Setup

Sign in to ghp, then configure git:

    ghp auth login
    ghp auth setup-git

`ghp auth setup-git` takes these flags:

    ghp auth setup-git [--host HOST]... [--app NAME] [--type proxy]

For each host (default `github.com`), it runs three commands against your
global git config:

    git config --global --replace-all credential.https://github.com.helper ""
    git config --global --add credential.https://github.com.helper "!ghp auth git-credential"
    git config --global credential.https://github.com.useHttpPath true

Then it prints what it wrote:

```
Configured https://github.com:
  credential.https://github.com.helper = !ghp auth git-credential
  credential.https://github.com.useHttpPath = true
warning: replaced any existing credential helper for github.com (for example gh)
```

- The empty `helper` value stops git from asking any helper configured
  before it. **This replaces any previous helper for those hosts**, for
  example `gh auth git-credential`.
- `useHttpPath` makes git send the repository path. The helper needs the
  path to pin the token to one repository.
- The helper command is the bare word `ghp` when `ghp` on your `PATH` is
  the binary you ran `setup-git` with. Otherwise it is that binary's
  absolute path. The bare word keeps working after Homebrew, asdf or nix
  upgrades move the binary to a new versioned path.
- For a host other than `github.com`, the helper line also gets
  `--host HOST`. The helper refuses a request for any host that is not in
  its `--host` list, so a ghp token never goes to an unrelated https host.
- `--app NAME` and `--type proxy` are written into the helper line. See
  the next section.
- If a git command fails after the first one for a host, that host is left
  with an empty helper chain. The error ends with
  `; re-run ghp auth setup-git`. Run it again to finish the setup.

Every word in the helper line is shell-quoted, because git runs a helper
that starts with `!` through the shell. See
[`ghp auth setup-git`](../cli/auth.md#ghp-auth-setup-git) for the rule.

## Choosing the app and token type

| Setting | Flag | Environment variable | Default |
|---|---|---|---|
| App | `--app` | `GHP_GIT_CM_APP` | the server's default app |
| Token type | `--type` | `GHP_GIT_CM_TYPE` | `agent` |
| Scopes | `--scopes` | `GHP_GIT_CM_SCOPES` | `contents:write` |
| Token lifetime | `--ttl` | `GHP_GIT_CM_TTL` | `1h` |
| Cache tier | `--cache-backend` | `GHP_GIT_CM_CACHE_BACKEND` | `auto` |
| Hosts served | `--host` (repeatable) | none | `github.com` |

A flag beats its environment variable, which beats the default. The flags
are flags of `ghp auth git-credential`, so you put them in the gitconfig
helper line. The environment variables let you change a setting for one
shell or one command:

    GHP_GIT_CM_APP=other git push

### Agent tokens (default)

With `--type agent`, the helper mints a `gha_` token from a GitHub App:

1. It lists the apps on the server. It picks the app whose name or record
   ID matches `--app` (ASCII case-insensitive). Without `--app`, it picks
   the default app, or the only app when there is exactly one.
2. It picks the app's installation whose account login matches the
   repository owner.
3. It mints the token for that installation, pinned to `owner/repo`.

When the scopes are defaulted, the helper lowers each requested level to
what the installation grants. For example, `contents:write` becomes
`contents:read` when the installation has only read access to contents.
When you set `--scopes` or `GHP_GIT_CM_SCOPES` yourself and the
installation cannot grant them, the helper fails with a message that names
the permission and the level the installation has. An installation that
does not grant the permission at all is an error in both cases.

To use another app for every repository, run `setup-git` with `--app`:

    ghp auth setup-git --app ci-bot

This writes `!ghp auth git-credential --app ci-bot`. To use another app in
one repository only, set the helper in that repository's local config. The
empty value clears the helper from your global config for this repository:

    git config --local --replace-all credential.https://github.com.helper ""
    git config --local --add credential.https://github.com.helper "!ghp auth git-credential --app other"

### Proxy tokens (no admin role)

The ghp server lets only admins create agent tokens. If you do not have the
ghp admin role, the agent path fails with this message:

```
ghp git-credential: the ghp server refused the agent-token request (agent tokens need the ghp admin role); use --type proxy or set GHP_GIT_CM_TYPE=proxy
```

Use proxy tokens instead:

    ghp auth setup-git --type proxy

A proxy (`ghx_`) token is backed by your own GitHub identity, so GitHub
attributes your pushes to you, not to an app. The helper makes no app or
installation lookups for proxy tokens.

`--app` together with `--type proxy` is an error. There is one exception:
when the helper line says `--type proxy`, a `GHP_GIT_CM_APP` value in the
environment is ignored. An exported `GHP_GIT_CM_APP` therefore cannot
break a proxy-configured helper line. The exception applies only to
`--type proxy` on the helper line. `GHP_GIT_CM_TYPE=proxy` together with
an exported `GHP_GIT_CM_APP` is an error; unset `GHP_GIT_CM_APP`.

### Scopes and lifetime

Scopes default to `contents:write`. Git does not tell the helper whether a
request is for a fetch or a push, and git retries only after a 401, not
after a 403. A read-only token would make every push fail.

`--ttl` takes a Go duration such as `1h` or `90m`. `never` is refused,
because a cached token must expire. Keep the lifetime well above 5 minutes:
the helper does not reuse a token that has 5 minutes or less left, so a
lifetime of 5 minutes or less mints a new token on every git command.

## Cache tiers

The cache lives in `~/.config/ghp/git-credential/` on every OS (on Windows,
under `%USERPROFILE%`). It holds three files:

| File | Contents |
|---|---|
| `cache.enc` | The encrypted tokens |
| `cache.lock` | The lock file for concurrent git processes |
| `tier` | The minimum tier for this cache directory |

The directory has mode `0700` and the files have mode `0600`. The helper
sets these modes each time it opens the cache. It writes the cache and
tier files through a temporary file and a rename.

On Windows the mode bits do not apply. The files are protected by the
access control list they inherit from your profile directory. DPAPI is the
effective tier there.

Git can run several helpers at once, for example for a parallel submodule
fetch. The helper holds an exclusive lock on `cache.lock` only while it
reads or writes the cache, never while it talks to the server. If it cannot
get the lock within 10 seconds, it prints one line and continues without
the cache for that command.

The tokens are encrypted with AES-256-GCM under a random data key. A key
protector, or tier, protects the data key. The tiers, strongest first:

| Tier | Platform | How it protects the data key |
|---|---|---|
| `tpm` | Linux, Windows | Sealed by the machine's TPM 2.0 (`/dev/tpmrm0`, else `/dev/tpm0`, on Linux; TPM Base Services on Windows) |
| `dpapi` | Windows | Windows DPAPI, current user scope |
| `keychain` | macOS | A generic password in the login keychain, service `ghp-git-credential`, set through `/usr/bin/security` |
| `file` | All | Stored as is in `cache.enc`. **File permissions only** |

With `--cache-backend auto` (the default), the helper uses the strongest
tier that is available now and not weaker than the minimum tier:

- The `tier` file records the strongest tier this cache directory has
  used. It survives `clear`. A TPM that is unavailable for a moment can
  never cause the helper to write a `file` cache on a machine that used
  the TPM before.
- If the chosen tier fails to wrap the key (for example a locked macOS
  keychain), the helper tries the next tier that is still not weaker than
  the minimum. If no tier qualifies, it gives git the token without caching
  it and prints one line:
  `no cache tier at least as strong as "tpm" is available; token not cached (use --cache-backend <tier> to accept a weaker tier)`.
- When a stronger tier becomes available, the helper re-encrypts the cache
  under it on its next write and raises the `tier` file.
- A cache written under a tier weaker than the `tier` file is ignored and
  replaced on the next write.
- A cache whose key can never be unwrapped is dropped and rebuilt, still
  at or above the minimum tier. This covers a TPM cache sealed by another
  TPM (or before the TPM was cleared) or with a corrupt sealed blob, a
  keychain cache whose keychain item is gone or corrupt, and a DPAPI cache
  that Windows rejects as invalid data or a bad key state (for example
  after an administrator reset the user's password, or a copied profile).

Other values of `--cache-backend`:

- `none` turns the cache off for that command and leaves the files alone.
- `tpm`, `dpapi`, `keychain` or `file` is an explicit choice. If that tier
  is unavailable, the helper fails; it does not fall back. If the cache was
  written under another tier, the helper re-creates it under the chosen
  tier and sets the `tier` file to it. When this lowers the tier, it
  prints `cache tier lowered from "tpm" to "file" at your request`. Use
  an explicit tier to accept a weaker tier when the `tier` file names one
  this machine can no longer provide.

The first time the helper writes a cache under the `file` tier, it prints:

```
ghp git-credential: cache protected by file permissions only; see docs
```

It prints this again on the first write after `clear`.

### Checking and clearing the cache

`ghp auth git-credential status` shows the cache path, the tier of the
current cache, the minimum tier, the protection, whether each tier is
available on this machine, and each entry. It shows at most the first
8 characters of a token. It does not contact the server and always uses
`auto`, whatever `--cache-backend` says. Sample output on Linux with a TPM:

```
Cache path:     /home/alice/.config/ghp/git-credential/cache.enc
Cache backend:  tpm
Minimum tier:   tpm
Protection:     sealed by this machine's TPM
Tier tpm:       available
Tier dpapi:     unavailable (securestore: protector unavailable: the dpapi tier is Windows only)
Tier keychain:  unavailable (securestore: protector unavailable: the keychain tier is macOS only)
Tier file:      available
Entries:        2
  acme/api  agent  app=ci-bot  token=gha_AbCd...  expires=2026-11-08T05:12:09Z (in 42m)
  acme/web  proxy  app=-  token=ghx_1a2B...  expires=2026-11-08T04:58:30Z (in 28m)
```

For a `file` cache, the protection line reads
`file permissions only (0600); see docs` (on Windows, read this as the
inherited access control list). `Cache backend: none` means there is no
usable cache: either no cache file yet, or one the helper ignored (weaker
than the minimum tier, sealed by another TPM, or corrupt). The next write
replaces it.

`ghp auth git-credential clear` removes every cached entry, then revokes
each token on the server (best effort):

```
Cleared 2 cached credentials; revoked 2.
```

`clear` keeps the `tier` file. On macOS it also keeps the keychain item
(one item per cache directory).

`clear` and `erase` revoke with the same credentials that `get` mints
with: the server URL and user token after dotvault is applied. They fall
back to the config files and environment only when dotvault fails, and
then print one line that says so.

## Threat model

- **Protects** tokens at rest against another local user without root,
  against copies of the home directory (TPM, DPAPI and keychain tiers
  only; for keychain and DPAPI, as strong as the user's login password),
  and against the long-lived credential sprawl of pasting a `gha_`
  token into a plaintext store. Tokens are short-lived (1 hour by default)
  and pinned to one repository.
- **Does not protect** against `root` or an administrator on the same
  machine, against malware running as the same user while the user is
  logged in, or against the user's own `ghpr_` session token in
  `~/.config/ghp/config.yaml`, which this feature does not move. Those are
  explicit non-goals.
- **The `file` tier is file permissions only.** Anyone who can read
  `cache.enc` can read the tokens. `status` says so on its protection
  line.
- **No tier stops processes running as the same user.** On macOS this
  needs no prompt because `/usr/bin/security` is the trusted application
  for the keychain item, so any process running as the same user can read
  the key. The keychain tier protects against copies of the home directory
  and against other users.

## Known limitations

- **Clone URLs must end in `.git`.** ghp's `github.com` passthrough maps
  only `/{owner}/{repo}.git/...` git paths.
- **`useHttpPath` is required.** Without it git sends no path, and the
  helper fails with
  `git did not send a repository path; run ghp auth setup-git (it sets credential.useHttpPath)`.
  `setup-git` sets it.
- **No Git LFS.** LFS endpoints are not mapped on the `github.com` vhost.
- **Agent tokens are admin-only.** Users without the ghp admin role must
  use `--type proxy`.
- **The `ghpr_` session expires after 30 days.** The helper does not
  refresh it. When it expires, the helper prints
  `ghp session expired or invalid: run ghp auth login`.
- **dotvault login is never interactive.** git owns stdin and stdout, so
  the helper uses only a cached dotvault token. When dotvault needs a
  login, it prints
  ``dotvault login required: run `ghp auth status` in a terminal to log in``.
- **git 2.41 or later uses `password_expiry_utc`.** Older git ignores the
  line.
- **Linux TPM access needs the `tss` group.** Without membership of `tss`
  (or without a TPM), the helper uses the `file` tier and prints the
  file-tier notice.
- **The `/dev/tpm0` fallback has no resource manager.** On kernels without
  `/dev/tpmrm0`, the helper opens `/dev/tpm0` directly. If the helper is
  killed in the middle of a TPM operation, a transient handle can stay
  loaded until reboot. After a few such leaks the TPM has no free
  transient slots and the `tpm` tier is unavailable until reboot.
- **There is no Secret Service backend yet.** Linux without a usable TPM
  uses the `file` tier.
- **The macOS keychain is locked in non-GUI sessions** (SSH, headless).
  Each `/usr/bin/security` call has a 10 second timeout. While the
  keychain is locked, the helper cannot read a keychain cache: it prints
  `cannot read the credential cache (...); continuing without it (run ghp auth git-credential clear if this persists)`
  and mints without caching. For a new cache, it uses the next tier that is
  not weaker than the minimum tier, or gives git the token without
  caching it.
- **Windows: the TPM tier is usually unavailable.** Provisioning normally
  sets the owner hierarchy auth, so DPAPI is the effective tier. `status`
  shows which tier is in use. Standard users depend on the TPM Base
  Services allow list for TPM access.
- **A revoked or stale cached token costs one failed git command.** git
  gets a 401, calls `erase` and fails that command. The next git command
  calls `get` and the helper mints a new token.
- **Cold caches can hit the server's rate limit.** `POST /api/tokens` is
  limited to 20 tokens per minute per IP. A cold cache with many
  submodules fetched in parallel, or many agents behind one NAT, can
  reach it. The helper then prints
  `ghp server rate limited token creation (20 per minute per IP); retry in 60s`
  (the delay comes from the server's `Retry-After` header).
- **An unreadable cache stays unreadable.** A cache written under a tier
  this build does not have (for example a DPAPI cache copied to Linux), or
  a key the protector cannot unwrap for now (for example a locked
  keychain or a TPM that does not answer), is reported on every call as
  `cannot read the credential cache (...); continuing without it (run ghp auth git-credential clear if this persists)`.
  The helper never rewrites it, because the failure can be temporary. If
  it persists, run `ghp auth git-credential clear`. If the `tier` file
  still names a tier this machine cannot provide, also run one command
  with an explicit `--cache-backend` to accept a weaker tier. A key that
  can never be unwrapped (a corrupt blob or keychain item) is not
  reported: the cache is dropped and rebuilt.
- **`workflows:read` logs a deprecation warning.** With
  `--scopes workflows:read`, the helper logs an unprefixed `WARN` line on
  stderr on every call, and the server logs the same warning. Use
  `actions:read` instead.
- **Not every failure is exactly one line.** Every failure of an
  operation is one stderr line that starts with `ghp git-credential: `.
  There are three exceptions. Usage errors from a bad helper line (an
  unknown flag, a missing operation) are printed by the command parser
  without the prefix, for example `unknown flag: --bogus`. CLI config
  warnings (insecure permissions, malformed YAML) are printed before a
  failure, one prefixed line each. A cache warning
  (`could not use the credential cache (...)` or the
  `cannot read the credential cache (...)` notice) can come before a
  failure to mint a token, as one more prefixed line.
- **Agent-token repositories must belong to the installation account.**
  With `--type agent`, every repository must be owned by the account the
  chosen installation belongs to (compared case-insensitively, ASCII only).
  Otherwise ghp refuses to create the token with `400 Bad Request`, naming
  the repository, and the helper prints that server message. If ghp cannot
  read the installation's account login, it does not create the token
  (`502`, or `503` when no GitHub App is loaded). See
  [Token Scoping](token-scoping.md#agent-tokens-gha_).
