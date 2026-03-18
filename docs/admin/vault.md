# Vault Storage Backend

ghp supports HashiCorp Vault as a storage backend, using the KV v2 secrets
engine with AppRole authentication. All data — users, tokens, apps, and
credentials — is stored as versioned secrets within a configurable keyspace.

Vault provides encryption at rest natively, so the `GHP_ENCRYPTION_KEY`
setting is not required when using this backend.

## Prerequisites

- HashiCorp Vault 1.12+ with the KV v2 secrets engine enabled
- AppRole auth method enabled
- A dedicated policy granting ghp access to its keyspace

## Vault Setup

### 1. Enable the KV v2 Secrets Engine

If you are using the default `secret/` mount (enabled by default in dev mode),
skip this step. Otherwise, enable a dedicated mount:

```bash
vault secrets enable -path=ghp-data -version=2 kv
```

### 2. Enable AppRole Authentication

```bash
vault auth enable approle
```

### 3. Create the GHP Policy

ghp needs full CRUD access to its data path and read/list/delete access to
metadata (used for key listing and version cleanup):

```bash
vault policy write ghp - <<'POLICY'
# Data operations — create, read, update, delete secrets
path "secret/data/ghp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Metadata operations — list keys and delete secret versions
path "secret/metadata/ghp/*" {
  capabilities = ["read", "list", "delete"]
}
POLICY
```

Adjust `secret` and `ghp` to match your `vault_mount` and `vault_path`
configuration if you are not using the defaults.

!!! warning "Least privilege"
    The policy above grants ghp full control over its keyspace. Do not widen
    the paths beyond `ghp/*` — ghp does not need access to any other Vault
    secrets.

### 4. Create the AppRole Role

```bash
vault write auth/approle/role/ghp \
  policies="ghp" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0 \
  token_num_uses=0
```

| Parameter | Recommended | Description |
|-----------|-------------|-------------|
| `policies` | `"ghp"` | The policy created above |
| `token_ttl` | `1h` | How long each issued token is valid before renewal |
| `token_max_ttl` | `4h` | Maximum lifetime before re-authentication is required |
| `secret_id_ttl` | `0` (no expiry) or org policy | How long the secret ID remains valid |
| `token_num_uses` | `0` (unlimited) | ghp makes many Vault calls per request |

ghp automatically re-authenticates when its token expires (up to
`token_max_ttl`), so short TTLs are safe and recommended.

### 5. Retrieve Credentials

```bash
# Get the role ID (stable, not secret)
vault read auth/approle/role/ghp/role-id

# Generate a secret ID (treat as a secret — store securely)
vault write -f auth/approle/role/ghp/secret-id
```

For development, you can set fixed credentials instead:

```bash
vault write auth/approle/role/ghp/role-id role_id="my-role-id"
vault write auth/approle/role/ghp/custom-secret-id secret_id="my-secret-id"
```

## GHP Configuration

=== "Environment Variables"

    ```bash
    export GHP_DATABASE_DRIVER=vault
    export GHP_DATABASE_VAULT_ADDR=https://vault.example.com:8200
    export GHP_DATABASE_VAULT_MOUNT=secret       # KV v2 mount path
    export GHP_DATABASE_VAULT_PATH=ghp            # key prefix within the mount
    export GHP_DATABASE_VAULT_ROLE_ID=<role-id>
    export GHP_DATABASE_VAULT_SECRET_ID=<secret-id>
    ```

=== "YAML"

    ```yaml
    database:
      driver: vault
      vault_addr: https://vault.example.com:8200
      vault_mount: secret    # KV v2 mount path
      vault_path: ghp        # key prefix within the mount
      vault_role_id: ""      # set via GHP_DATABASE_VAULT_ROLE_ID env var
      vault_secret_id: ""    # set via GHP_DATABASE_VAULT_SECRET_ID env var
    ```

| Field | Env Var | Default | Description |
|-------|---------|---------|-------------|
| `vault_addr` | `GHP_DATABASE_VAULT_ADDR` | — | Vault server address (required) |
| `vault_mount` | `GHP_DATABASE_VAULT_MOUNT` | `secret` | KV v2 secrets engine mount path |
| `vault_path` | `GHP_DATABASE_VAULT_PATH` | `ghp` | Key prefix within the mount |
| `vault_role_id` | `GHP_DATABASE_VAULT_ROLE_ID` | — | AppRole role ID (required) |
| `vault_secret_id` | `GHP_DATABASE_VAULT_SECRET_ID` | — | AppRole secret ID (required) |

!!! tip "No encryption key needed"
    When using `driver: vault`, the `GHP_ENCRYPTION_KEY` setting is ignored.
    Vault encrypts all data at rest using its own seal mechanism.

## Keyspace Layout

ghp organizes data under the configured `vault_path` prefix. With the default
settings (`mount=secret`, `path=ghp`), the keyspace looks like:

```
secret/data/ghp/
├── apps/
│   └── {app-id}                          # App record (name, keys, config)
├── users/
│   ├── {user-id}                         # User record
│   └── by-github-id/
│       └── {github-id}                   # Index: GitHub ID → user ID
├── github-tokens/
│   ├── {token-id}                        # Encrypted OAuth token pair
│   └── by-user/
│       └── {user-id}                     # Index: user ID → token ID
└── proxy-tokens/
    ├── {token-id}                        # Proxy token record
    ├── by-hash/
    │   └── {token-hash}                  # Index: SHA-256 hash → token ID
    └── by-user/
        └── {user-id}/
            └── {token-id}               # Index: user's tokens
```

Index entries are lightweight secrets that store only a pointer (ID) to the
actual record. Lookups that use an index require two Vault reads: one for the
index and one for the record.

## Migrations

The Vault backend does not use SQL migrations. There is no schema to manage —
data is stored as JSON within KV v2 secrets and the structure evolves with the
application. The `ghp migrate` command is not applicable when using Vault.

## Token Lifecycle and Re-authentication

ghp authenticates to Vault using AppRole at startup. The issued Vault token
has a limited TTL (configured via `token_ttl` on the role). When the token
expires:

1. The next Vault operation returns a 403 (permission denied)
2. ghp automatically re-authenticates using the stored role ID and secret ID
3. The failed operation is retried with the new token

This is transparent to users and requires no manual intervention. The only
scenario requiring operator action is if the **secret ID itself expires**
(controlled by `secret_id_ttl` on the role) — in that case, generate a new
secret ID and update the `GHP_DATABASE_VAULT_SECRET_ID` environment variable.

## High Availability

### Single Instance

A single ghp instance with Vault works without any special configuration.
In-process caches (token resolution, GitHub credentials) reduce Vault round
trips on the hot path.

### Multi-Instance Deployments

Multiple ghp instances can share the same Vault backend. Each instance
authenticates independently with its own AppRole token.

!!! note "Concurrency limitations"
    Vault KV v2 does not support atomic read-modify-write operations. While
    ghp uses in-process mutexes to protect concurrent access within a single
    instance, cross-instance operations on the same key can race. In practice
    this only affects scenarios where two instances modify the same record
    simultaneously (e.g., revoking the same token from two admin sessions).
    Token resolution (reads) and proxy operations are safe for concurrent
    multi-instance use.

## Monitoring

ghp instruments all Vault operations through the standard proxy decision
pipeline metrics. The `github_token_resolution` stage timing includes Vault
read latency, making it visible in the
`ghp_proxy_decision_duration_seconds` histogram.

Monitor your Vault server's own metrics and audit log for:

- Authentication failures (indicates expired or revoked credentials)
- High read/write latency (may indicate Vault overload or network issues)
- Policy denials (indicates misconfigured policy paths)

## Backup and Recovery

Vault's own backup mechanisms apply. ghp does not provide Vault-specific
backup tooling. Recommended approaches:

- **Vault snapshots** (`vault operator raft snapshot save`) for integrated
  storage backends
- **KV export** via the Vault CLI or API for the ghp keyspace
- **Vault replication** (Enterprise) for disaster recovery

To migrate data between backends (e.g., SQLite to Vault), there is currently
no built-in migration tool. The data would need to be exported and imported
via the ghp API.

## Development Setup

A Docker Compose environment is provided for local development with Vault.
See the [Development Guide](../development.md#docker-compose-with-vault) for
step-by-step instructions.
