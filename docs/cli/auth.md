# ghp auth

Authenticate with the ghp server.

## Subcommands

### ghp auth login

    ghp auth login

Start a GitHub OAuth login flow. The command contacts the ghp server to obtain
a GitHub authorization URL, then attempts to open it in your default browser.

If the browser does not open (e.g. in an SSH session or headless environment),
copy the printed URL and open it manually. After authenticating with GitHub,
the page will display a JSON payload containing your session token:

```json
{"session_token":"ghpr_...","username":"your-github-username"}
```

Copy the `session_token` value and save it with:

    ghp auth set-token <session_token>

Or export it as an environment variable:

    export GHP_USER_TOKEN=<session_token>

### ghp auth set-token

    ghp auth set-token <token>

Save a session token (obtained from `ghp auth login`) to the local config file
at `~/.config/ghp/config.yaml`. The token must start with `ghpr_`.

    ghp auth set-token ghpr_abc123...

After saving, verify with `ghp auth status`.

### ghp auth status

    ghp auth status

Show current authentication status — displays your username and role if
authenticated.

## Configuration

Requires `GHP_SERVER_URL` to be set (or `server_url` in
`~/.config/ghp/config.yaml`).
