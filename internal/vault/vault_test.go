// Package vault provides integration tests for Vault connectivity using AppRole auth.
// Tests use testcontainers to spin up a Vault dev server automatically.
package vault

import (
	"context"
	"fmt"
	"testing"

	vault "github.com/hashicorp/vault/api"
	tcvault "github.com/testcontainers/testcontainers-go/modules/vault"
)

const devRootToken = "test-root-token"

// startVault starts a Vault dev container, configures transit + AppRole via the
// API, and returns a client authenticated with AppRole credentials.
func startVault(t *testing.T) *vault.Client {
	t.Helper()
	ctx := context.Background()

	vaultContainer, err := tcvault.Run(ctx, "hashicorp/vault:1.21",
		tcvault.WithToken(devRootToken),
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
	rootClient.SetToken(devRootToken)

	// Enable transit secrets engine.
	if _, err := rootClient.Logical().WriteWithContext(ctx, "sys/mounts/transit", map[string]interface{}{
		"type": "transit",
	}); err != nil {
		t.Fatalf("enable transit: %v", err)
	}

	// Enable AppRole auth method.
	if _, err := rootClient.Logical().WriteWithContext(ctx, "sys/auth/approle", map[string]interface{}{
		"type": "approle",
	}); err != nil {
		t.Fatalf("enable approle: %v", err)
	}

	// Write ghp policy.
	if _, err := rootClient.Logical().WriteWithContext(ctx, "sys/policy/ghp", map[string]interface{}{
		"policy": `
			path "secret/data/ghp/*"    { capabilities = ["create","read","update","delete","list"] }
			path "secret/metadata/ghp/*" { capabilities = ["read","list","delete"] }
			path "transit/encrypt/*"     { capabilities = ["update"] }
			path "transit/decrypt/*"     { capabilities = ["update"] }
			path "transit/keys/*"        { capabilities = ["create","update","read"] }
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
	return client
}

// TestAppRoleAuth verifies that AppRole authentication succeeds and returns a valid token.
func TestAppRoleAuth(t *testing.T) {
	client := startVault(t)

	if client.Token() == "" {
		t.Error("expected non-empty client token after AppRole login")
	}
}

// TestKV2WriteRead verifies that kv-v2 write and read operations work via AppRole auth.
func TestKV2WriteRead(t *testing.T) {
	client := startVault(t)

	ctx := context.Background()
	path := "secret/data/ghp/test-key"
	want := map[string]interface{}{
		"username": "test-agent",
		"token":    "ghp_abc123",
	}

	// Write the secret.
	_, err := client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"data": want,
	})
	if err != nil {
		t.Fatalf("KV2 write: %v", err)
	}

	// Read the secret back.
	got, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		t.Fatalf("KV2 read: %v", err)
	}
	if got == nil {
		t.Fatal("KV2 read returned nil")
	}

	data, ok := got.Data["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("KV2 read: unexpected data shape: %v", got.Data)
	}

	for k, wantVal := range want {
		gotVal, ok := data[k]
		if !ok {
			t.Errorf("KV2 read: missing key %q", k)
			continue
		}
		if fmt.Sprintf("%v", gotVal) != fmt.Sprintf("%v", wantVal) {
			t.Errorf("KV2 read: key %q = %v, want %v", k, gotVal, wantVal)
		}
	}
}

// TestTransitEncryptDecrypt verifies that the transit secrets engine encrypt/decrypt
// round-trip works via AppRole auth.
func TestTransitEncryptDecrypt(t *testing.T) {
	client := startVault(t)
	ctx := context.Background()

	keyName := "ghp-test"
	plaintext := "aGVsbG8gd29ybGQ=" // base64("hello world")

	// Ensure the transit key exists (create if not present); idempotent.
	_, err := client.Logical().WriteWithContext(ctx, fmt.Sprintf("transit/keys/%s", keyName), nil)
	if err != nil {
		t.Fatalf("transit create key: %v", err)
	}

	// Encrypt using transit engine.
	encResp, err := client.Logical().WriteWithContext(ctx, fmt.Sprintf("transit/encrypt/%s", keyName), map[string]interface{}{
		"plaintext": plaintext,
	})
	if err != nil {
		t.Fatalf("transit encrypt: %v", err)
	}

	ciphertext, ok := encResp.Data["ciphertext"].(string)
	if !ok || ciphertext == "" {
		t.Fatalf("transit encrypt: no ciphertext in response: %v", encResp.Data)
	}

	// Decrypt using transit engine.
	decResp, err := client.Logical().WriteWithContext(ctx, fmt.Sprintf("transit/decrypt/%s", keyName), map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		t.Fatalf("transit decrypt: %v", err)
	}

	decoded, ok := decResp.Data["plaintext"].(string)
	if !ok || decoded == "" {
		t.Fatalf("transit decrypt: no plaintext in response: %v", decResp.Data)
	}

	if decoded != plaintext {
		t.Errorf("transit round-trip: got %q, want %q", decoded, plaintext)
	}
}
