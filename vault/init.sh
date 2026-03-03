#!/bin/sh
# Vault initialization script for local development (dev mode).
# Enables transit engine, creates ghp policy and AppRole.
# Dev mode auto-initializes, auto-unseals, and enables kv-v2 at secret/.
# This script is idempotent and safe to re-run.
set -e

# Development-only fixed secret-id for the ghp AppRole.
# Do NOT use this value in production.
GHP_DEV_SECRET_ID="ghp-dev-secret-id-for-local-testing"

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
vault write auth/approle/role/ghp/custom-secret-id \
  secret_id="$GHP_DEV_SECRET_ID" > /dev/null

echo ""
echo "=== Vault setup complete ==="
echo "VAULT_ADDR=$VAULT_ADDR"
echo "VAULT_APPROLE_ROLE_ID=$ROLE_ID"
echo "VAULT_APPROLE_SECRET_ID=$GHP_DEV_SECRET_ID"
