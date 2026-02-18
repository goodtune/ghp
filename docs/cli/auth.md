# ghp auth

Authenticate with the ghp server.

## Subcommands

### ghp auth login

    ghp auth login

Authenticate via GitHub OAuth. Opens a browser to the ghp server's GitHub
OAuth flow. After authenticating, save the returned token:

    export GHP_USER_TOKEN=<token>

Or add it to `~/.config/ghp/config.yaml`.

### ghp auth status

    ghp auth status

Show current authentication status — displays your username and role if
authenticated.

## Configuration

Requires `GHP_SERVER_URL` to be set (or `server_url` in
`~/.config/ghp/config.yaml`).
