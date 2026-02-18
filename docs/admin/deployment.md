# Deployment

## TLS Termination (Recommended)

ghp terminates TLS directly and uses SNI to select the right certificate for
each virtualhost. This is the recommended production mode.

### TLS Certificates

You need certificates covering:

- `api.github.com` and `github.com`
- `*.githubcopilot.com`
- Your management host (e.g. `ghp.example.com`)

These can be separate certificates or combined using SANs. Configure them in
`server.yaml`:

```yaml
tls:
  certificates:
    - cert_file: "/etc/ghp/tls/github.pem"
      key_file: "/etc/ghp/tls/github-key.pem"
    - cert_file: "/etc/ghp/tls/copilot.pem"
      key_file: "/etc/ghp/tls/copilot-key.pem"
    - cert_file: "/etc/ghp/tls/mgmt.pem"
      key_file: "/etc/ghp/tls/mgmt-key.pem"
```

### DNS

Point the GitHub hostnames at your ghp server on the network(s) where your
agents run. This can be done via split-horizon DNS, `/etc/hosts`, or a local
DNS resolver:

```
api.github.com      → <ghp-server-ip>
github.com          → <ghp-server-ip>
*.githubcopilot.com → <ghp-server-ip>
```

Agents then connect to ghp transparently — no client configuration beyond
`GH_TOKEN` is needed.

### Run Migrations

    ghp migrate --config /etc/ghp/server.yaml

### Systemd Unit

Create `/etc/systemd/system/ghp.service`:

```ini
[Unit]
Description=ghp — GitHub Proxy for Coding Agents
After=network.target postgresql.service

[Service]
Type=notify
ExecStart=/usr/local/bin/ghp serve --config /etc/ghp/server.yaml
User=ghp
Group=ghp
Restart=on-failure
WatchdogSec=30

Environment=GHP_ENCRYPTION_KEY=<your-key>

AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ghp /var/log/ghp
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Start the service:

    systemctl daemon-reload
    systemctl enable --now ghp.service

Verify:

    curl -s https://ghp.example.com/auth/status

## Reverse Proxy Mode (Alternative)

If you prefer to run ghp behind a reverse proxy (e.g. Caddy, nginx) instead of
having it terminate TLS directly, omit the `https_listen`, `http_listen`, and
`tls` settings and use the legacy `listen` option:

```yaml
server:
  listen: "unix:///run/ghp/ghp.sock"
  base_url: "https://ghp.example.com"
```

Then configure your reverse proxy to forward traffic to the socket. The reverse
proxy handles TLS and routes the relevant Host headers to ghp.
