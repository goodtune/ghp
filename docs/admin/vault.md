# Vault Storage Backend

ghp supports HashiCorp Vault as a storage backend, using the KV v2 secrets
engine. All data — users, tokens, apps, and credentials — is stored as
versioned secrets within a configurable keyspace.

Vault provides encryption at rest natively, so the `GHP_ENCRYPTION_KEY`
setting is not required when using this backend.

ghp can authenticate to Vault using one of two methods:

- **AppRole** (default) — role ID and secret ID credentials are provisioned
  out-of-band and supplied via configuration. Suitable for VMs, bare metal,
  or any deployment where a Kubernetes-issued JWT is not available.
- **Kubernetes** — ghp uses the pod's projected service account JWT to
  authenticate directly to Vault's kubernetes auth backend. Recommended for
  Kubernetes deployments because it eliminates the need to manage role-id /
  secret-id credentials and removes Vault Secret Operator (VSO) from the
  authentication path.

## Prerequisites

- HashiCorp Vault 1.12+ with the KV v2 secrets engine enabled
- One of: AppRole auth method enabled, or kubernetes auth method enabled and
  bound to the cluster ghp runs in
- A dedicated policy granting ghp access to its keyspace

## Vault Setup

### 1. Enable the KV v2 Secrets Engine

If you are using the default `secret/` mount (enabled by default in dev mode),
skip this step. Otherwise, enable a dedicated mount:

```bash
vault secrets enable -path=ghp-data -version=2 kv
```

### 2. Enable an Authentication Method

Choose one of the following based on where ghp runs:

=== "AppRole"

    ```bash
    vault auth enable approle
    ```

=== "Kubernetes"

    ```bash
    vault auth enable kubernetes
    # Or, for multi-cluster setups, mount the backend at a per-cluster path:
    vault auth enable -path=kubernetes/my-cluster kubernetes
    ```

    Configure the auth backend so Vault can validate JWTs issued by the
    cluster's API server. Write to `auth/<mount>/config` matching the path
    you enabled above. The recommended pattern is to use Vault's own
    service account to call the TokenReview API:

    ```bash
    # Default mount:
    vault write auth/kubernetes/config \
      kubernetes_host="https://kubernetes.default.svc:443" \
      kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

    # Custom mount (matching `-path=kubernetes/my-cluster` above):
    vault write auth/kubernetes/my-cluster/config \
      kubernetes_host="https://kubernetes.default.svc:443" \
      kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    ```

    See the [Vault kubernetes auth docs][k8s-auth] for full setup details
    and alternative configurations (e.g. validating JWTs locally without
    contacting the API server).

[k8s-auth]: https://developer.hashicorp.com/vault/docs/auth/kubernetes

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

### 4. Create the Vault Role

=== "AppRole"

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

=== "Kubernetes"

    Bind the Vault role to the Kubernetes service account that ghp's pod
    uses. Update `bound_service_account_names` and
    `bound_service_account_namespaces` to match your deployment.

    ```bash
    vault write auth/kubernetes/role/ghp \
      bound_service_account_names=ghp \
      bound_service_account_namespaces=ghp \
      policies=ghp \
      token_ttl=1h \
      token_max_ttl=4h
    ```

    | Parameter | Recommended | Description |
    |-----------|-------------|-------------|
    | `bound_service_account_names` | `ghp` | Service account names allowed to assume this role |
    | `bound_service_account_namespaces` | `ghp` | Namespaces those service accounts must live in |
    | `policies` | `"ghp"` | The policy created above |
    | `token_ttl` | `1h` | How long each issued token is valid before renewal |
    | `token_max_ttl` | `4h` | Maximum lifetime before re-authentication is required |

    If you mounted the kubernetes backend at a per-cluster path (e.g.
    `kubernetes/my-cluster`), substitute that path in the command above.

ghp automatically re-authenticates when its token expires (up to
`token_max_ttl`), so short TTLs are safe and recommended.

### 5. Retrieve Credentials

=== "AppRole"

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

=== "Kubernetes"

    No credential retrieval is required. ghp authenticates directly using
    the projected service account JWT mounted into its pod by Kubernetes
    at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

    Ensure the pod runs as the service account bound to the Vault role:

    ```yaml
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: ghp
      namespace: ghp
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: ghp
      namespace: ghp
    spec:
      template:
        spec:
          serviceAccountName: ghp
          # ...
    ```

    #### Custom JWT audience

    If the Vault role binds an `audience` (or `audiences`) — for example
    if you set `audience=vault` on `auth/kubernetes/role/ghp` — the
    default service account token will not work. The auto-mounted token
    at `/var/run/secrets/kubernetes.io/serviceaccount/token` carries the
    API server audience (`https://kubernetes.default.svc.cluster.local`),
    not the audience your role expects, so Vault's login response is:

    ```
    invalid audience (aud) claim: audience claim does not match any expected audience
    ```

    The fix is to mount a **projected service account token** with the
    desired audience and point ghp at that path. This is the same
    mechanism Vault Agent uses, and it works without any code changes
    in ghp:

    ```yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: ghp
      namespace: ghp
    spec:
      template:
        spec:
          serviceAccountName: ghp
          containers:
            - name: ghp
              # ...
              env:
                - name: GHP_DATABASE_VAULT_K8S_TOKEN_PATH
                  value: /var/run/secrets/vault/token
              volumeMounts:
                - name: vault-token
                  mountPath: /var/run/secrets/vault
                  readOnly: true
          volumes:
            - name: vault-token
              projected:
                sources:
                  - serviceAccountToken:
                      audience: vault          # match `audience` on the Vault role
                      expirationSeconds: 3600
                      path: token
    ```

    The kubelet rotates the projected token before it expires. ghp re-reads
    the file from disk on every (re-)login, so rotation is handled
    transparently without restarts.

## GHP Configuration

=== "AppRole — Environment Variables"

    ```bash
    export GHP_DATABASE_DRIVER=vault
    export GHP_DATABASE_VAULT_ADDR=https://vault.example.com:8200
    export GHP_DATABASE_VAULT_MOUNT=secret       # KV v2 mount path
    export GHP_DATABASE_VAULT_PATH=ghp            # key prefix within the mount
    export GHP_DATABASE_VAULT_AUTH_METHOD=approle # default; can be omitted
    export GHP_DATABASE_VAULT_ROLE_ID=<role-id>
    export GHP_DATABASE_VAULT_SECRET_ID=<secret-id>
    ```

=== "AppRole — YAML"

    ```yaml
    database:
      driver: vault
      vault_addr: https://vault.example.com:8200
      vault_mount: secret              # KV v2 mount path
      vault_path: ghp                  # key prefix within the mount
      vault_auth_method: approle       # default
      vault_role_id: ""                # set via GHP_DATABASE_VAULT_ROLE_ID env var
      vault_secret_id: ""              # set via GHP_DATABASE_VAULT_SECRET_ID env var
    ```

=== "Kubernetes — Environment Variables"

    ```bash
    export GHP_DATABASE_DRIVER=vault
    export GHP_DATABASE_VAULT_ADDR=https://vault.example.com:8200
    export GHP_DATABASE_VAULT_MOUNT=secret
    export GHP_DATABASE_VAULT_PATH=ghp
    export GHP_DATABASE_VAULT_AUTH_METHOD=kubernetes
    export GHP_DATABASE_VAULT_K8S_ROLE=ghp
    # Optional — override only if you mounted the auth backend at a non-default path:
    # export GHP_DATABASE_VAULT_K8S_MOUNT=kubernetes/my-cluster
    # Optional — override only if your projected token is at a non-standard path
    # (the default is /var/run/secrets/kubernetes.io/serviceaccount/token):
    # export GHP_DATABASE_VAULT_K8S_TOKEN_PATH=/var/run/secrets/projected/ghp-token
    ```

=== "Kubernetes — YAML"

    ```yaml
    database:
      driver: vault
      vault_addr: https://vault.example.com:8200
      vault_mount: secret
      vault_path: ghp
      vault_auth_method: kubernetes
      vault_k8s_role: ghp
      # vault_k8s_mount: kubernetes        # default; override for multi-cluster mounts
      # vault_k8s_token_path: /var/run/secrets/projected/ghp-token  # default is /var/run/secrets/kubernetes.io/serviceaccount/token
    ```

| Field | Env Var | Default | Description |
|-------|---------|---------|-------------|
| `vault_addr` | `GHP_DATABASE_VAULT_ADDR` | — | Vault server address (required) |
| `vault_mount` | `GHP_DATABASE_VAULT_MOUNT` | `secret` | KV v2 secrets engine mount path |
| `vault_path` | `GHP_DATABASE_VAULT_PATH` | `ghp` | Key prefix within the mount |
| `vault_auth_method` | `GHP_DATABASE_VAULT_AUTH_METHOD` | `approle` | Auth method: `approle` or `kubernetes` |
| `vault_role_id` | `GHP_DATABASE_VAULT_ROLE_ID` | — | AppRole role ID (required when method=`approle`) |
| `vault_secret_id` | `GHP_DATABASE_VAULT_SECRET_ID` | — | AppRole secret ID (required when method=`approle`) |
| `vault_k8s_role` | `GHP_DATABASE_VAULT_K8S_ROLE` | — | Vault role name (required when method=`kubernetes`) |
| `vault_k8s_mount` | `GHP_DATABASE_VAULT_K8S_MOUNT` | `kubernetes` | Auth mount path for the kubernetes backend |
| `vault_k8s_token_path` | `GHP_DATABASE_VAULT_K8S_TOKEN_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Path to the projected service account JWT. Override when the Vault role binds a custom audience — see [Custom JWT audience](#custom-jwt-audience). |

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

ghp authenticates to Vault at startup using the configured method. The
issued Vault token has a limited TTL (configured via `token_ttl` on the
role). When the token expires:

1. The next Vault operation returns a 403 (permission denied)
2. ghp automatically re-authenticates using the stored credentials
3. The failed operation is retried with the new token

This is transparent to users and requires no manual intervention.

### AppRole

The only scenario requiring operator action is if the **secret ID itself
expires** (controlled by `secret_id_ttl` on the role) — in that case,
generate a new secret ID and update the `GHP_DATABASE_VAULT_SECRET_ID`
environment variable.

### Kubernetes

Kubernetes projects a service account token into the pod and rotates it
periodically (typically every hour, controlled by `--service-account-extend-token-expiration`
on the API server). On every re-authentication, ghp **re-reads the token
file from disk** before calling `auth/<mount>/login`, so rotated tokens
are picked up automatically without restarting the pod.

No operator action is required for the kubernetes method beyond the initial
role binding. If the bound service account is deleted or the kubernetes auth
backend's API server CA changes, ghp's next re-authentication will fail —
investigate via the Vault audit log and the `ghp_proxy_decision_duration_seconds`
metric for elevated `github_token_resolution` latency.

!!! warning "`invalid audience (aud) claim` at startup"
    If the Vault role binds an audience and the pod still mounts the default
    service account token, login fails with `invalid audience (aud) claim:
    audience claim does not match any expected audience`. The default token's
    `aud` is the cluster API server, not the Vault role's audience. Mount a
    projected service account token with the matching audience and set
    `vault_k8s_token_path` to that file — see
    [Custom JWT audience](#custom-jwt-audience).

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
