// Package vault provides integration tests for Vault connectivity using AppRole auth.
// Tests are skipped unless GHP_TEST_VAULT_ADDR is set.
package vault

import (
"context"
"fmt"
"os"
"testing"

vault "github.com/hashicorp/vault/api"
)

// newTestVaultClient creates a Vault client authenticated via AppRole.
// Tests are skipped when GHP_TEST_VAULT_ADDR is not set.
func newTestVaultClient(t *testing.T) *vault.Client {
t.Helper()

addr := os.Getenv("GHP_TEST_VAULT_ADDR")
if addr == "" {
t.Skip("GHP_TEST_VAULT_ADDR not set; skipping Vault tests")
}

roleID := os.Getenv("GHP_TEST_VAULT_ROLE_ID")
if roleID == "" {
t.Fatal("GHP_TEST_VAULT_ROLE_ID must be set when GHP_TEST_VAULT_ADDR is set")
}

secretID := os.Getenv("GHP_TEST_VAULT_SECRET_ID")
if secretID == "" {
t.Fatal("GHP_TEST_VAULT_SECRET_ID must be set when GHP_TEST_VAULT_ADDR is set")
}

cfg := vault.DefaultConfig()
cfg.Address = addr

client, err := vault.NewClient(cfg)
if err != nil {
t.Fatalf("vault.NewClient: %v", err)
}

// Authenticate via AppRole.
resp, err := client.Logical().WriteWithContext(context.Background(), "auth/approle/login", map[string]interface{}{
"role_id":   roleID,
"secret_id": secretID,
})
if err != nil {
t.Fatalf("AppRole login: %v", err)
}
if resp.Auth == nil {
t.Fatal("AppRole login returned no auth token")
}

client.SetToken(resp.Auth.ClientToken)
return client
}

// TestAppRoleAuth verifies that AppRole authentication succeeds and returns a valid token.
func TestAppRoleAuth(t *testing.T) {
client := newTestVaultClient(t)

if client.Token() == "" {
t.Error("expected non-empty client token after AppRole login")
}
}

// TestKV2WriteRead verifies that kv-v2 write and read operations work via AppRole auth.
func TestKV2WriteRead(t *testing.T) {
client := newTestVaultClient(t)

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
client := newTestVaultClient(t)
ctx := context.Background()

keyName := "ghp-test"
plaintext := "aGVsbG8gd29ybGQ=" // Vault transit requires base64-encoded plaintext; this is base64("hello world")

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
