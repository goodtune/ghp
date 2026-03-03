# Policy for the ghp AppRole.
# Grants access to kv-v2 secrets at secret/ghp/* and transit operations.

# kv-v2 secrets engine: full access under secret/ghp/
path "secret/data/ghp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/ghp/*" {
  capabilities = ["read", "list", "delete"]
}

# transit secrets engine: encrypt and decrypt
path "transit/encrypt/*" {
  capabilities = ["update"]
}

path "transit/decrypt/*" {
  capabilities = ["update"]
}

path "transit/keys/*" {
  capabilities = ["create", "update", "read"]
}
