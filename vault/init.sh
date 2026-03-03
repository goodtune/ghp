#!/bin/sh
# Vault initialization script for local development.
# Enables kv2 and transit engines, creates ghp policy and AppRole.
# This script is idempotent and safe to re-run.
set -e

DATA_DIR="/vault/data"
UNSEAL_FILE="$DATA_DIR/unseal_key"
TOKEN_FILE="$DATA_DIR/root_token"
CREDENTIALS_FILE="$DATA_DIR/credentials"

# Development-only fixed secret-id for the ghp AppRole.
# Do NOT use this value in production.
GHP_DEV_SECRET_ID="ghp-dev-secret-id-for-local-testing"

# Wait for Vault to be fully ready (healthcheck should handle this, but be safe).
echo "Waiting for Vault to be ready..."
until vault status 2>&1 | grep -q "Initialized"; do
  sleep 1
done

# Initialize Vault if not already initialized.
if vault status 2>&1 | grep -q "Initialized.*false"; then
  echo "Initializing Vault..."
  INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1)
  echo "$INIT_OUTPUT" | grep "Unseal Key 1:" | awk '{print $NF}' > "$UNSEAL_FILE"
  echo "$INIT_OUTPUT" | grep "Initial Root Token:" | awk '{print $NF}' > "$TOKEN_FILE"
  echo "Vault initialized."
else
  echo "Vault already initialized."
fi

# Unseal Vault if sealed.
if vault status 2>&1 | grep -q "Sealed.*true"; then
  echo "Unsealing Vault..."
  vault operator unseal "$(cat "$UNSEAL_FILE")"
  echo "Vault unsealed."
else
  echo "Vault already unsealed."
fi

# Authenticate with root token.
export VAULT_TOKEN="$(cat "$TOKEN_FILE")"

# Enable kv-v2 secrets engine if not already enabled.
if ! vault secrets list -format=json | grep -q '"secret/"'; then
  echo "Enabling kv-v2 secrets engine at secret/..."
  vault secrets enable -path=secret kv-v2
  echo "kv-v2 enabled."
else
  echo "kv-v2 already enabled."
fi

# Enable transit secrets engine if not already enabled.
if ! vault secrets list -format=json | grep -q '"transit/"'; then
  echo "Enabling transit secrets engine..."
  vault secrets enable transit
  echo "Transit enabled."
else
  echo "Transit already enabled."
fi

# Write ghp policy.
echo "Writing ghp policy..."
vault policy write ghp /vault/config/ghp-policy.hcl

# Enable AppRole auth if not already enabled.
if ! vault auth list -format=json | grep -q '"approle/"'; then
  echo "Enabling AppRole auth method..."
  vault auth enable approle
  echo "AppRole enabled."
else
  echo "AppRole already enabled."
fi

# Create ghp AppRole role.
echo "Creating ghp AppRole role..."
vault write auth/approle/role/ghp \
  policies=ghp \
  token_ttl=1h \
  token_max_ttl=4h

# Retrieve role-id.
ROLE_ID=$(vault read -field=role_id auth/approle/role/ghp/role-id)

# Register a fixed custom secret-id for development convenience.
# This is idempotent: re-registering the same secret-id updates its metadata only.
vault write auth/approle/role/ghp/custom-secret-id \
  secret_id="$GHP_DEV_SECRET_ID" > /dev/null

# Write credentials to file for use by tests and developers.
cat > "$CREDENTIALS_FILE" <<EOF
VAULT_ADDR=$VAULT_ADDR
VAULT_APPROLE_ROLE_ID=$ROLE_ID
VAULT_APPROLE_SECRET_ID=$GHP_DEV_SECRET_ID
EOF

echo ""
echo "=== Vault setup complete ==="
echo "VAULT_ADDR=$VAULT_ADDR"
echo "VAULT_APPROLE_ROLE_ID=$ROLE_ID"
echo "VAULT_APPROLE_SECRET_ID=$GHP_DEV_SECRET_ID"
echo "Credentials written to $CREDENTIALS_FILE"
