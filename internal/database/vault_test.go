package database

import (
	"context"
	"encoding/json"
	"testing"

	vault "github.com/hashicorp/vault/api"
	tcvault "github.com/testcontainers/testcontainers-go/modules/vault"
)

const vaultDevRootToken = "test-root-token"

// newTestVaultStore spins up a Vault dev container via testcontainers, configures
// AppRole auth and KV v2, and returns a VaultStore connected to it.
func newTestVaultStore(t *testing.T) *VaultStore {
	t.Helper()
	ctx := context.Background()

	vaultContainer, err := tcvault.Run(ctx, "hashicorp/vault:1.21",
		tcvault.WithToken(vaultDevRootToken),
	)
	if err != nil {
		t.Fatalf("start vault container: %v", err)
	}
	t.Cleanup(func() {
		if err := vaultContainer.Terminate(ctx); err != nil {
			t.Logf("terminate vault container: %v", err)
		}
	})

	addr, err := vaultContainer.HttpHostAddress(ctx)
	if err != nil {
		t.Fatalf("vault host address: %v", err)
	}

	// Build a root client to configure Vault.
	cfg := vault.DefaultConfig()
	cfg.Address = addr
	rootClient, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	rootClient.SetToken(vaultDevRootToken)

	// Enable AppRole auth method.
	if _, err := rootClient.Logical().WriteWithContext(ctx, "sys/auth/approle", map[string]interface{}{
		"type": "approle",
	}); err != nil {
		t.Fatalf("enable approle: %v", err)
	}

	// Write ghp policy for KV v2 access.
	if _, err := rootClient.Logical().WriteWithContext(ctx, "sys/policy/ghp", map[string]interface{}{
		"policy": `
			path "secret/data/ghp/*"     { capabilities = ["create","read","update","delete","list"] }
			path "secret/metadata/ghp/*"  { capabilities = ["read","list","delete"] }
		`,
	}); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Create ghp AppRole role.
	if _, err := rootClient.Logical().WriteWithContext(ctx, "auth/approle/role/ghp", map[string]interface{}{
		"policies":      "ghp",
		"token_ttl":     "1h",
		"token_max_ttl": "4h",
	}); err != nil {
		t.Fatalf("create approle role: %v", err)
	}

	// Read role-id.
	roleResp, err := rootClient.Logical().ReadWithContext(ctx, "auth/approle/role/ghp/role-id")
	if err != nil {
		t.Fatalf("read role-id: %v", err)
	}
	roleID := roleResp.Data["role_id"].(string)

	// Generate a secret-id.
	secretResp, err := rootClient.Logical().WriteWithContext(ctx, "auth/approle/role/ghp/secret-id", nil)
	if err != nil {
		t.Fatalf("generate secret-id: %v", err)
	}
	secretID := secretResp.Data["secret_id"].(string)

	// Authenticate via AppRole.
	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	loginResp, err := client.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		t.Fatalf("AppRole login: %v", err)
	}
	if loginResp.Auth == nil {
		t.Fatal("AppRole login returned no auth token")
	}
	client.SetToken(loginResp.Auth.ClientToken)

	return NewVaultStoreFromClient(client, "secret", "ghp")
}

// TestVaultStoreContract runs the shared store contract tests against Vault.
func TestVaultStoreContract(t *testing.T) {
	store := newTestVaultStore(t)
	testStoreContract(t, store)
}

// TestKVVersionOf covers the shapes Vault's client can hand back for the KV
// v2 version field. Getting this wrong would silently turn every
// compare-and-set write into `cas: 0` (create-only), breaking the
// read-modify-write paths that depend on it.
func TestKVVersionOf(t *testing.T) {
	tests := []struct {
		name string
		meta map[string]interface{}
		want int64
	}{
		{"nil metadata", nil, 0},
		{"missing version", map[string]interface{}{"created_time": "now"}, 0},
		{"json.Number", map[string]interface{}{"version": json.Number("7")}, 7},
		{"float64", map[string]interface{}{"version": float64(7)}, 7},
		{"int64", map[string]interface{}{"version": int64(7)}, 7},
		{"int", map[string]interface{}{"version": 7}, 7},
		{"string", map[string]interface{}{"version": "7"}, 7},
		{"unparseable string", map[string]interface{}{"version": "seven"}, 0},
		{"unexpected type", map[string]interface{}{"version": []int{7}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kvVersionOf(tt.meta); got != tt.want {
				t.Errorf("kvVersionOf(%v) = %d, want %d", tt.meta, got, tt.want)
			}
		})
	}
}
