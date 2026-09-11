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

## Configuration

Requires `GHP_SERVER_URL` to be set (or `server_url` in
`~/.config/ghp/config.yaml`).
