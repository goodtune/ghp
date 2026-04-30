package database

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeVault is a minimal HTTP stand-in for Vault that records login requests
// and returns canned responses. It supports both AppRole and kubernetes auth
// login endpoints and a single KV v2 read used to confirm token usage.
type fakeVault struct {
	t      *testing.T
	server *httptest.Server

	// Captured kubernetes login fields.
	gotRole atomic.Value // string
	gotJWT  atomic.Value // string

	// Number of times the kubernetes login endpoint was hit.
	loginCount atomic.Int32

	// Canned response token returned by the next login.
	loginToken atomic.Value // string

	// Whether the next KV read should return 403 to force a re-login.
	forceKVForbidden atomic.Bool
}

func newFakeVault(t *testing.T, mountPath string) *fakeVault {
	t.Helper()
	fv := &fakeVault{t: t}
	fv.loginToken.Store("ghp-vault-token-1")

	mux := http.NewServeMux()

	loginPath := "/v1/auth/" + strings.Trim(mountPath, "/") + "/login"
	mux.HandleFunc(loginPath, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		role, _ := body["role"].(string)
		jwt, _ := body["jwt"].(string)
		fv.gotRole.Store(role)
		fv.gotJWT.Store(jwt)
		fv.loginCount.Add(1)

		token, _ := fv.loginToken.Load().(string)
		writeAuthResponse(w, token)
	})

	mux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		if fv.forceKVForbidden.CompareAndSwap(true, false) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"hello":"world"}}}`))
	})

	fv.server = httptest.NewServer(mux)
	t.Cleanup(fv.server.Close)
	return fv
}

func writeAuthResponse(w http.ResponseWriter, clientToken string) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token":   clientToken,
			"renewable":      true,
			"lease_duration": 3600,
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func TestNewVaultStoreKubernetesLogin(t *testing.T) {
	mount := "kubernetes/test-cluster"
	fv := newFakeVault(t, mount)

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("initial-jwt\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	store, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:         fv.server.URL,
		AuthMethod:   VaultAuthMethodKubernetes,
		K8sRole:      "ghp",
		K8sMount:     mount,
		K8sTokenPath: tokenPath,
	})
	if err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}

	if got, _ := fv.gotRole.Load().(string); got != "ghp" {
		t.Errorf("login role = %q, want %q", got, "ghp")
	}
	if got, _ := fv.gotJWT.Load().(string); got != "initial-jwt" {
		t.Errorf("login jwt = %q, want %q", got, "initial-jwt")
	}
	if got := fv.loginCount.Load(); got != 1 {
		t.Errorf("login count = %d, want 1", got)
	}

	if got := store.client.Token(); got != "ghp-vault-token-1" {
		t.Errorf("client token = %q, want ghp-vault-token-1", got)
	}
}

func TestNewVaultStoreKubernetesDefaults(t *testing.T) {
	fv := newFakeVault(t, DefaultK8sAuthMount)

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("jwt-default"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	// Omit K8sMount so the default ("kubernetes") is used.
	if _, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:         fv.server.URL,
		AuthMethod:   VaultAuthMethodKubernetes,
		K8sRole:      "ghp",
		K8sTokenPath: tokenPath,
	}); err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}
	if got := fv.loginCount.Load(); got != 1 {
		t.Errorf("login count = %d, want 1 (default mount path used)", got)
	}
}

func TestNewVaultStoreKubernetesMissingRole(t *testing.T) {
	_, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:       "http://localhost:1",
		AuthMethod: VaultAuthMethodKubernetes,
	})
	if err == nil {
		t.Fatal("expected error when k8s role is missing")
	}
	if !strings.Contains(err.Error(), "role is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewVaultStoreKubernetesMissingTokenFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:         "http://localhost:1",
		AuthMethod:   VaultAuthMethodKubernetes,
		K8sRole:      "ghp",
		K8sTokenPath: missing,
	})
	if err == nil {
		t.Fatal("expected error when token file is missing")
	}
	if !strings.Contains(err.Error(), "service account token") {
		t.Errorf("error should mention service account token, got: %v", err)
	}
}

func TestNewVaultStoreKubernetesEmptyTokenFile(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	_, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:         "http://localhost:1",
		AuthMethod:   VaultAuthMethodKubernetes,
		K8sRole:      "ghp",
		K8sTokenPath: tokenPath,
	})
	if err == nil {
		t.Fatal("expected error when token file is empty")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty token, got: %v", err)
	}
}

func TestNewVaultStoreUnsupportedAuthMethod(t *testing.T) {
	_, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:       "http://localhost:1",
		AuthMethod: "ldap",
	})
	if err == nil {
		t.Fatal("expected error for unsupported auth method")
	}
	if !strings.Contains(err.Error(), "unsupported vault auth method") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewVaultStoreAppRoleMissingRoleID(t *testing.T) {
	_, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:       "http://localhost:1",
		AuthMethod: VaultAuthMethodAppRole,
		SecretID:   "secret",
	})
	if err == nil {
		t.Fatal("expected error when approle role_id is missing")
	}
	if !strings.Contains(err.Error(), "role_id is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewVaultStoreAppRoleMissingSecretID(t *testing.T) {
	_, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:       "http://localhost:1",
		AuthMethod: VaultAuthMethodAppRole,
		RoleID:     "role",
	})
	if err == nil {
		t.Fatal("expected error when approle secret_id is missing")
	}
	if !strings.Contains(err.Error(), "secret_id is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestNewVaultStoreKubernetesMountNormalized verifies that whitespace and
// surrounding slashes in K8sMount are stripped at construction so the
// resulting login URL ("auth/<mount>/login") is well-formed even when the
// operator supplied a sloppy value.
func TestNewVaultStoreKubernetesMountNormalized(t *testing.T) {
	mount := "kubernetes/my-cluster"
	fv := newFakeVault(t, mount)

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("jwt"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if _, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:         fv.server.URL,
		AuthMethod:   VaultAuthMethodKubernetes,
		K8sRole:      "ghp",
		K8sMount:     "  /kubernetes/my-cluster/  ",
		K8sTokenPath: tokenPath,
	}); err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}
	if got := fv.loginCount.Load(); got != 1 {
		t.Errorf("login count = %d, want 1 (whitespace-trimmed mount should match the registered handler)", got)
	}
}

func TestNewVaultStoreKubernetesInvalidMount(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("jwt"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	for _, mount := range []string{"/", "//", " / "} {
		t.Run(mount, func(t *testing.T) {
			_, err := NewVaultStore(context.Background(), VaultConfig{
				Addr:         "http://localhost:1",
				AuthMethod:   VaultAuthMethodKubernetes,
				K8sRole:      "ghp",
				K8sMount:     mount,
				K8sTokenPath: tokenPath,
			})
			if err == nil {
				t.Fatalf("expected error for k8s mount %q", mount)
			}
			if !strings.Contains(err.Error(), "mount path") {
				t.Errorf("error should mention mount path, got: %v", err)
			}
		})
	}
}

// TestVaultStoreKubernetesReloginRereadsJWT verifies that after a 403 from
// Vault, withRelogin re-reads the service-account token from disk before
// calling auth/<mount>/login again. This mirrors how the kubelet rotates
// projected tokens during a pod's lifetime.
func TestVaultStoreKubernetesReloginRereadsJWT(t *testing.T) {
	mount := "kubernetes"
	fv := newFakeVault(t, mount)

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("jwt-1"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	store, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:         fv.server.URL,
		AuthMethod:   VaultAuthMethodKubernetes,
		K8sRole:      "ghp",
		K8sMount:     mount,
		K8sTokenPath: tokenPath,
	})
	if err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}
	if got, _ := fv.gotJWT.Load().(string); got != "jwt-1" {
		t.Fatalf("initial login jwt = %q, want jwt-1", got)
	}

	// Simulate kubelet rotating the projected token on disk.
	if err := os.WriteFile(tokenPath, []byte("jwt-rotated"), 0o600); err != nil {
		t.Fatalf("rewrite token: %v", err)
	}
	fv.loginToken.Store("ghp-vault-token-2")
	fv.forceKVForbidden.Store(true)

	// Trigger a KV operation; the first attempt 403s, withRelogin re-reads
	// the JWT, re-authenticates, and retries.
	if _, err := store.kvRead(context.Background(), "anything"); err != nil {
		t.Fatalf("kvRead after relogin: %v", err)
	}

	if got, _ := fv.gotJWT.Load().(string); got != "jwt-rotated" {
		t.Errorf("login jwt after relogin = %q, want jwt-rotated", got)
	}
	if got := fv.loginCount.Load(); got != 2 {
		t.Errorf("login count = %d, want 2", got)
	}
	if got := store.client.Token(); got != "ghp-vault-token-2" {
		t.Errorf("client token after relogin = %q, want ghp-vault-token-2", got)
	}
}

// TestVaultStoreReloginErrorSurfacesInnerError verifies that when the initial
// 403-triggered re-authentication itself fails (e.g. the projected SA token
// went missing), the error returned to the caller includes the re-login
// failure rather than just the original "permission denied" — otherwise
// the actionable cause is invisible to operators.
func TestVaultStoreReloginErrorSurfacesInnerError(t *testing.T) {
	mount := "kubernetes"
	fv := newFakeVault(t, mount)

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("jwt-1"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	store, err := NewVaultStore(context.Background(), VaultConfig{
		Addr:         fv.server.URL,
		AuthMethod:   VaultAuthMethodKubernetes,
		K8sRole:      "ghp",
		K8sMount:     mount,
		K8sTokenPath: tokenPath,
	})
	if err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}

	// Force a 403 on the next KV op AND make re-login fail by deleting the
	// token file from under us. The original error is "permission denied";
	// the re-login error is "service account token at <path> ... no such
	// file or directory". The returned error must include the latter.
	fv.forceKVForbidden.Store(true)
	if err := os.Remove(tokenPath); err != nil {
		t.Fatalf("remove token: %v", err)
	}

	_, err = store.kvRead(context.Background(), "anything")
	if err == nil {
		t.Fatal("expected error when re-login fails")
	}
	if !strings.Contains(err.Error(), "re-authentication") {
		t.Errorf("error should mention re-authentication: %v", err)
	}
	if !strings.Contains(err.Error(), "service account token") {
		t.Errorf("error should surface inner relogin failure (missing token file): %v", err)
	}
}
