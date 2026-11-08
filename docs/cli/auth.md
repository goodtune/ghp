# ghp auth

Authenticate to the ghp server.

## Subcommands

### ghp auth login

    ghp auth login

Sign in to the ghp server using a device-authorization flow. The CLI never
contacts GitHub directly: GitHub OAuth is the identity provider for the ghp
web UI, but `ghp auth login` only talks to your ghp server.

The flow:

1. The CLI requests a fresh sign-in from the ghp server and prints a URL on
   the **ghp server** (not github.com) along with a short verification code:

   ```
   Open this URL in a browser to authorize the CLI:
     https://your-ghp.example/cli/auth?user_code=ABCD-EFGH

   Confirm this code matches what the page displays:
     ABCD-EFGH

   Waiting for approval (Ctrl-C to cancel)...
   ```

2. Open the URL in a browser. If you are not already signed in to ghp, you
   will be sent through GitHub OAuth first and returned to the verification
   page automatically.

3. Confirm that the user code shown in the browser matches the one printed
   by your CLI, then click **Authorize** (or **Deny**).

4. The CLI polls the server, picks up the issued session token, and saves
   it to `~/.config/ghp/config.yaml`. Run `ghp auth status` to verify.

The verification code is short-lived (10 minutes) and tied to a specific CLI
sign-in attempt; if the code expires before approval, run `ghp auth login`
again to get a new one.

#### Headless / SSH usage

If the browser cannot be opened automatically (for example in an SSH session
without X forwarding), copy the URL printed by the CLI and open it on
another machine. The verification page is served over HTTPS by your ghp
server and works from any browser that can reach it.

### ghp auth set-token

    ghp auth set-token <token>

Save a session token to the local config file at `~/.config/ghp/config.yaml`.
This is normally done automatically by `ghp auth login`; use this command
only if you are pasting in a token obtained another way (e.g. from a teammate
or a session created via the web UI). The token must start with `ghpr_`.

After saving, verify with `ghp auth status`.

### ghp auth status

    ghp auth status

Show current authentication status — displays your username and role if
authenticated.

### ghp auth git-credential

    ghp auth git-credential [flags] <get|store|erase|status|clear>

A git credential helper. For each repository git asks about, it mints a
short-lived ghp token pinned to that `owner/repo` and keeps it in an
encrypted local cache until 5 minutes before it expires. Git runs this
command itself; configure it with [`ghp auth setup-git`](#ghp-auth-setup-git).
See [Git Credential Helper](../features/git-credential-helper.md) for how
it works, the cache tiers and the threat model.

Operations:

| Operation | Description |
|-----------|-------------|
| `get` | Answer a credential request from git on stdin |
| `store` | Accepted and ignored (the helper is the source of truth) |
| `erase` | Drop the cached token for the requested repository and revoke it |
| `status` | Show the cache tier, path and entries (never the tokens) |
| `clear` | Remove every cached entry and revoke its token (best effort) |

Git sends `get`, `store` and `erase`. `status` and `clear` are for you. An
unknown operation exits 0 with no output, as git requires.

Flags:

| Flag | Environment variable | Default | Description |
|------|----------------------|---------|-------------|
| `--app` | `GHP_GIT_CM_APP` | the server's default app | GitHub App name or record ID (agent tokens only) |
| `--type` | `GHP_GIT_CM_TYPE` | `agent` | Token type: `agent` or `proxy` |
| `--scopes` | `GHP_GIT_CM_SCOPES` | `contents:write` | Requested token scopes |
| `--ttl` | `GHP_GIT_CM_TTL` | `1h` | Token lifetime (a Go duration; `never` is refused) |
| `--cache-backend` | `GHP_GIT_CM_CACHE_BACKEND` | `auto` | Cache tier: `auto`, `none`, `tpm`, `dpapi`, `keychain` or `file` |
| `--host` | none | `github.com` | Host this helper serves; repeat for several |

A flag beats its environment variable, which beats the default. A
`GHP_GIT_CM_APP` value is ignored when `--type proxy` is given as a flag.

Every failure of an operation is one stderr line that starts with
`ghp git-credential: ` and names the remedy. Stdout stays empty on failure.
For example:

    ghp git-credential: not logged in: run ghp auth login

There are three exceptions. Usage errors from a bad helper line (an unknown
flag, a missing operation) are printed without the prefix, for example
`unknown flag: --bogus`. CLI config warnings (insecure permissions,
malformed YAML) are printed before a failure, one prefixed line each. A
cache warning (`could not use the credential cache (...)` or the
`cannot read the credential cache (...)` notice) can come before a failure
to mint a token, as one more prefixed line.

### ghp auth setup-git

    ghp auth setup-git [--host HOST]... [--app NAME] [--type agent|proxy]

Configure git to use `ghp auth git-credential` as the credential helper for
each host, in your global git config.

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `github.com` | Host to configure; repeat for several. A host name with an optional `:port` |
| `--app` | the server's default app | GitHub App name or record ID for the helper |
| `--type` | `agent` | Token type for the helper: `agent` or `proxy` |

`--app` with `--type proxy` is an error.

For every host, `setup-git` runs:

    git config --global --replace-all credential.https://HOST.helper ""
    git config --global --add credential.https://HOST.helper "!ghp auth git-credential ..."
    git config --global credential.https://HOST.useHttpPath true

The empty helper value stops git from asking any helper configured before
it, so any previous helper for these hosts (for example `gh`) is replaced.
`useHttpPath` makes git send the repository path, so the helper can pin the
token to that repository. `setup-git` prints each value it wrote, then a
warning that it replaced any existing helper.

The helper line is built like this:

- The command is the bare word `ghp` when `ghp` on your `PATH` resolves to
  the binary you are running. Otherwise it is that binary's absolute path.
- `--host HOST` is added only for a host other than `github.com`.
- `--app NAME` is added when you pass `--app`, and `--type proxy` when you
  pass `--type proxy`.

Git runs a helper that starts with `!` through the shell, so every word is
quoted. A word is left as it is only when it matches
`^[A-Za-z0-9@%+=:,./_-]+$`. Any other word is wrapped in single quotes,
with each `'` written as `'\''`. A value that contains a newline, a
carriage return or a NUL byte is refused. For example:

    $ ghp auth setup-git --app "Acme CI's bot"
    Configured https://github.com:
      credential.https://github.com.helper = !ghp auth git-credential --app 'Acme CI'\''s bot'
      credential.https://github.com.useHttpPath = true
    warning: replaced any existing credential helper for github.com (for example gh)

## Configuration

Requires `GHP_SERVER_URL` to be set (or `server_url` in
`~/.config/ghp/config.yaml`).
