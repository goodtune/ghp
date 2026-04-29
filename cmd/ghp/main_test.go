package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHelpOutput_Root verifies that the root help text mentions all subcommands and flags.
func TestHelpOutput_Root(t *testing.T) {
	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})
	_ = rootCmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"serve",
		"migrate",
		"auth",
		"token",
		"apptoken",
		"version",
		"--config",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("root help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_Serve verifies that "ghp serve --help" mentions all its flags.
func TestHelpOutput_Serve(t *testing.T) {
	cmd := newServeCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"--migrate"} {
		if !strings.Contains(output, want) {
			t.Errorf("serve help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_Migrate verifies that "ghp migrate --help" mentions the status subcommand.
func TestHelpOutput_Migrate(t *testing.T) {
	cmd := newMigrateCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"status"} {
		if !strings.Contains(output, want) {
			t.Errorf("migrate help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_Auth verifies that "ghp auth --help" mentions all subcommands.
func TestHelpOutput_Auth(t *testing.T) {
	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"login", "set-token", "status"} {
		if !strings.Contains(output, want) {
			t.Errorf("auth help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_AuthLogin verifies that "ghp auth login --help" describes the command correctly.
func TestHelpOutput_AuthLogin(t *testing.T) {
	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"device-authorization",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("auth login help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_AuthStatus verifies that "ghp auth status --help" describes the command correctly.
func TestHelpOutput_AuthStatus(t *testing.T) {
	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"authentication status",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("auth status help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_Token verifies that "ghp token --help" mentions create, list, and revoke subcommands.
func TestHelpOutput_Token(t *testing.T) {
	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"create", "list", "revoke"} {
		if !strings.Contains(output, want) {
			t.Errorf("token help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_TokenCreate verifies that "ghp token create --help" mentions all its flags.
func TestHelpOutput_TokenCreate(t *testing.T) {
	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"--type",
		"--repo",
		"--repos",
		"--installation-id",
		"--scope",
		"--duration",
		"--session",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("token create help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_TokenList verifies that "ghp token list --help" describes the command correctly.
func TestHelpOutput_TokenList(t *testing.T) {
	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"active tokens",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("token list help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_TokenRevoke verifies that "ghp token revoke --help" mentions the token-id argument.
func TestHelpOutput_TokenRevoke(t *testing.T) {
	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"revoke", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"token-id",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("token revoke help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestVersionCmd verifies that "ghp version" prints the version string.
func TestVersionCmd(t *testing.T) {
	cmd := newVersionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version cmd error: %v", err)
	}
	// Version is set via ldflags at build time; in tests it defaults to "dev".
	if !strings.Contains(buf.String(), "ghp version") {
		t.Errorf("expected 'ghp version' in output, got %q", buf.String())
	}
}

// TestAuthLoginCmd_NoServerURL verifies that auth login returns an error when no server URL is configured.
func TestAuthLoginCmd_NoServerURL(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no server URL is configured")
	}
	if !strings.Contains(err.Error(), "server URL not configured") {
		t.Errorf("expected 'server URL not configured' in error, got: %v", err)
	}
}

// TestAuthLoginCmd_DeviceFlow verifies that "ghp auth login" runs the device
// authorization flow against the server, displays the verification URL and
// user code, polls until the request is approved, and saves the issued token
// to the local config file.
func TestAuthLoginCmd_DeviceFlow(t *testing.T) {
	const userCode = "ABCD-EFGH"
	const deviceCode = "device-code-xyz"
	const issuedToken = "ghpr_devicetoken123"

	pollCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/cli/auth/device":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":               deviceCode,
				"user_code":                 userCode,
				"verification_uri":          "http://server.example/cli/auth",
				"verification_uri_complete": "http://server.example/cli/auth?user_code=" + userCode,
				"expires_in":                600,
				"interval":                  1,
			})
		case r.Method == "POST" && r.URL.Path == "/cli/auth/device/token":
			pollCount++
			w.Header().Set("Content-Type", "application/json")
			if pollCount < 2 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{
				"session_token": issuedToken,
				"username":      "alice",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	home := t.TempDir()
	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", home)
	t.Setenv("GHP_NO_BROWSER", "1")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("auth login error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, userCode) {
		t.Errorf("expected user code %q in output, got: %q", userCode, output)
	}
	if !strings.Contains(output, "/cli/auth?user_code="+userCode) {
		t.Errorf("expected verification URL in output, got: %q", output)
	}

	// Token should be saved to ~/.config/ghp/config.yaml.
	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.UserToken != issuedToken {
		t.Errorf("UserToken = %q, want %q", cfg.UserToken, issuedToken)
	}

	if pollCount < 2 {
		t.Errorf("expected at least 2 polls, got %d", pollCount)
	}
}

// TestAuthLoginCmd_DeviceFlowDenied verifies that the CLI surfaces an
// access_denied response from the server as a clean error.
func TestAuthLoginCmd_DeviceFlowDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cli/auth/device":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "dc",
				"user_code":        "AAAA-BBBB",
				"verification_uri": "http://server.example/cli/auth",
				"expires_in":       600,
				"interval":         1,
			})
		case r.URL.Path == "/cli/auth/device/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GHP_NO_BROWSER", "1")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when device flow is denied")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected 'denied' in error, got: %v", err)
	}
}

// TestAuthLoginCmd_ServerError verifies that auth login reports an error when
// the device-start endpoint returns a non-200 status.
func TestAuthLoginCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GHP_NO_BROWSER", "1")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when server returns 500")
	}
}

// TestAuthSetTokenCmd_Valid verifies that set-token saves a ghpr_ token to config.
func TestAuthSetTokenCmd_Valid(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GHP_SERVER_URL", "http://localhost:8080")
	t.Setenv("GHP_USER_TOKEN", "")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"set-token", "ghpr_abc123def456"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("set-token error: %v", err)
	}
	if !strings.Contains(buf.String(), "saved") {
		t.Errorf("expected 'saved' confirmation in output, got: %q", buf.String())
	}

	// Verify the token was written to the config file.
	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.UserToken != "ghpr_abc123def456" {
		t.Errorf("UserToken = %q, want %q", cfg.UserToken, "ghpr_abc123def456")
	}
}

// TestAuthSetTokenCmd_InvalidPrefix verifies that set-token rejects tokens without the ghpr_ prefix.
func TestAuthSetTokenCmd_InvalidPrefix(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"set-token", "notavalidtoken"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for token without ghpr_ prefix")
	}
}

// TestAuthStatusCmd_NoToken verifies that auth status reports unauthenticated when no token is set.
func TestAuthStatusCmd_NoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to stub server: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("auth status error: %v", err)
	}
	if !strings.Contains(buf.String(), "Not authenticated") {
		t.Errorf("expected 'Not authenticated' in output, got: %q", buf.String())
	}
}

// TestAuthStatusCmd_Authenticated verifies that auth status calls the stub server and reports the user.
func TestAuthStatusCmd_Authenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer testtoken" {
			t.Errorf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": true,
			"username":      "alice",
			"role":          "admin",
		})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("auth status error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "alice") {
		t.Errorf("expected username 'alice' in output, got: %q", output)
	}
	if !strings.Contains(output, "admin") {
		t.Errorf("expected role 'admin' in output, got: %q", output)
	}
}

// TestAuthStatusCmd_NoServerURL verifies that auth status returns an error when no server URL is configured.
func TestAuthStatusCmd_NoServerURL(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no server URL is configured")
	}
	if !strings.Contains(err.Error(), "server URL not configured") {
		t.Errorf("expected 'server URL not configured' in error, got: %v", err)
	}
}

// TestTokenCreateCmd_NoConfig verifies that token create returns an error when not configured.
func TestTokenCreateCmd_NoConfig(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--scope", "contents:read", "--repo", "owner/repo"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when not configured")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected 'not configured' in error, got: %v", err)
	}
}

// TestTokenCreateCmd_ProxyToken verifies that token create sends correct body and prints the token.
func TestTokenCreateCmd_ProxyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/tokens" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["type"] != "proxy" {
			t.Errorf("expected type 'proxy', got %v", body["type"])
		}
		if body["repository"] != "owner/repo" {
			t.Errorf("expected repository 'owner/repo', got %v", body["repository"])
		}
		if body["scopes"] != "contents:read" {
			t.Errorf("expected scopes 'contents:read', got %v", body["scopes"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghx_testproxy",
			"type":       "proxy",
			"expires_at": "2099-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--scope", "contents:read", "--repo", "owner/repo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "ghx_testproxy") {
		t.Errorf("expected token in output, got: %q", output)
	}
}

// TestTokenCreateCmd_AgentTokenMissingInstallationID verifies that agent token creation requires --installation-id.
func TestTokenCreateCmd_AgentTokenMissingInstallationID(t *testing.T) {
	// Use a real httptest server for a consistent URL (validation fails before any HTTP call).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to stub server: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--type", "agent", "--scope", "contents:read"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --installation-id is missing for agent token")
	}
	if !strings.Contains(err.Error(), "--installation-id") {
		t.Errorf("expected '--installation-id' in error, got: %v", err)
	}
}

// TestTokenCreateCmd_AgentToken verifies that a complete agent token request is sent to the server.
func TestTokenCreateCmd_AgentToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["type"] != "agent" {
			t.Errorf("expected type 'agent', got %v", body["type"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":        "gha_testagent",
			"type":         "agent",
			"repositories": []string{"owner/repo1", "owner/repo2"},
			"expires_at":   "2099-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"create",
		"--type", "agent",
		"--scope", "contents:read",
		"--repos", "owner/repo1,owner/repo2",
		"--installation-id", "12345",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create agent error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "gha_testagent") {
		t.Errorf("expected token in output, got: %q", output)
	}
}

// TestTokenListCmd verifies that token list calls the stub server and prints tokens.
func TestTokenListCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/tokens" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"token_prefix":  "ghx_abcd",
				"token_type":    "proxy",
				"repositories":  []interface{}{"owner/repo"},
				"session_id":    "sess1",
				"expires_at":    "2099-01-01T00:00:00Z",
				"request_count": float64(5),
			},
		})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token list error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "ghx_abcd") {
		t.Errorf("expected token prefix in output, got: %q", output)
	}
}

// TestTokenListCmd_Empty verifies that token list handles empty results gracefully.
func TestTokenListCmd_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token list error: %v", err)
	}
	if !strings.Contains(buf.String(), "No tokens found") {
		t.Errorf("expected 'No tokens found' in output, got: %q", buf.String())
	}
}

// TestTokenRevokeCmd verifies that token revoke calls the stub server and reports success.
func TestTokenRevokeCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.Path != "/api/tokens/ghx_abcd" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"revoke", "ghx_abcd"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token revoke error: %v", err)
	}
	if !strings.Contains(buf.String(), "ghx_abcd") {
		t.Errorf("expected token ID in output, got: %q", buf.String())
	}
}

// TestTokenRevokeCmd_ServerError verifies that token revoke reports errors from the server.
func TestTokenRevokeCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "token not found"})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"revoke", "ghx_notexist"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when server returns non-200 status")
	}
}

// TestLoadCLIConfig_EnvVars verifies that environment variables take priority over the config file.
func TestLoadCLIConfig_EnvVars(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "http://env-server:8080")
	t.Setenv("GHP_USER_TOKEN", "env-token")
	t.Setenv("HOME", t.TempDir())

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "http://env-server:8080" {
		t.Errorf("ServerURL: got %q, want %q", cfg.ServerURL, "http://env-server:8080")
	}
	if cfg.UserToken != "env-token" {
		t.Errorf("UserToken: got %q, want %q", cfg.UserToken, "env-token")
	}
}

// TestLoadCLIConfig_Defaults verifies that loadCLIConfig returns empty strings when nothing is set.
func TestLoadCLIConfig_Defaults(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "" {
		t.Errorf("ServerURL: expected empty, got %q", cfg.ServerURL)
	}
	if cfg.UserToken != "" {
		t.Errorf("UserToken: expected empty, got %q", cfg.UserToken)
	}
}

// TestLoadCLIConfig_FromFile verifies that values are loaded from the YAML config file when env vars are unset.
func TestLoadCLIConfig_FromFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")

	configDir := filepath.Join(home, ".config", "ghp")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	configContent := "server_url: http://file-server:8080\nuser_token: file-token\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "http://file-server:8080" {
		t.Errorf("ServerURL: got %q, want %q", cfg.ServerURL, "http://file-server:8080")
	}
	if cfg.UserToken != "file-token" {
		t.Errorf("UserToken: got %q, want %q", cfg.UserToken, "file-token")
	}
}

// TestLoadCLIConfig_EnvVarsPriorityOverFile verifies that env vars win when both env vars and file are set.
func TestLoadCLIConfig_EnvVarsPriorityOverFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GHP_SERVER_URL", "http://env-server:8080")
	t.Setenv("GHP_USER_TOKEN", "env-token")

	configDir := filepath.Join(home, ".config", "ghp")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	configContent := "server_url: http://file-server:9090\nuser_token: file-token\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "http://env-server:8080" {
		t.Errorf("ServerURL: got %q, want env value %q", cfg.ServerURL, "http://env-server:8080")
	}
	if cfg.UserToken != "env-token" {
		t.Errorf("UserToken: got %q, want env value %q", cfg.UserToken, "env-token")
	}
}

// TestHelpOutput_AppToken verifies that "ghp apptoken --help" describes the command correctly.
func TestHelpOutput_AppToken(t *testing.T) {
	cmd := newAppTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"installation-name",
		"installation access token",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("apptoken help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestAppTokenCmd_SingleInstallation verifies that apptoken auto-selects when there's one installation.
func TestAppTokenCmd_SingleInstallation(t *testing.T) {
	// Stub GitHub API: ListInstallations + CreateInstallationAccessToken.
	// go-github prepends /api/v3/ for non-api.github.com URLs (enterprise mode).
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/app/installations"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id": 42,
					"account": map[string]interface{}{
						"login": "myorg",
						"id":    1,
						"type":  "Organization",
					},
					"permissions":          map[string]string{},
					"repository_selection": "all",
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/app/installations/42/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_testtoken123",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	// Write a config file pointing at the stub server.
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ghp.yaml")
	cfgContent := fmt.Sprintf("github:\n  app_id: 12345\n  private_key: |\n    %s\n  base_url: %s\n",
		strings.ReplaceAll(testRSAKeyForCmd, "\n", "\n    "), ghSrv.URL)
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "apptoken"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("apptoken error: %v", err)
	}
	if !strings.Contains(buf.String(), "ghs_testtoken123") {
		t.Errorf("expected token in output, got: %q", buf.String())
	}
}

// TestAppTokenCmd_ByName verifies that apptoken selects the correct installation by name.
func TestAppTokenCmd_ByName(t *testing.T) {
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/app/installations"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 10, "account": map[string]interface{}{"login": "alpha", "id": 1, "type": "Organization"}},
				{"id": 20, "account": map[string]interface{}{"login": "beta", "id": 2, "type": "Organization"}},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/app/installations/20/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_betatoken",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ghp.yaml")
	cfgContent := fmt.Sprintf("github:\n  app_id: 12345\n  private_key: |\n    %s\n  base_url: %s\n",
		strings.ReplaceAll(testRSAKeyForCmd, "\n", "\n    "), ghSrv.URL)
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "apptoken", "beta"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("apptoken error: %v", err)
	}
	if !strings.Contains(buf.String(), "ghs_betatoken") {
		t.Errorf("expected token in output, got: %q", buf.String())
	}
}

// TestAppTokenCmd_MultipleInstallationsNoName verifies that apptoken errors when multiple installations exist and no name is given.
func TestAppTokenCmd_MultipleInstallationsNoName(t *testing.T) {
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/app/installations") {
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 10, "account": map[string]interface{}{"login": "alpha", "id": 1, "type": "Organization"}},
				{"id": 20, "account": map[string]interface{}{"login": "beta", "id": 2, "type": "Organization"}},
			})
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ghSrv.Close()

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ghp.yaml")
	cfgContent := fmt.Sprintf("github:\n  app_id: 12345\n  private_key: |\n    %s\n  base_url: %s\n",
		strings.ReplaceAll(testRSAKeyForCmd, "\n", "\n    "), ghSrv.URL)
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "apptoken"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when multiple installations and no name specified")
	}
	if !strings.Contains(err.Error(), "multiple installations") {
		t.Errorf("expected 'multiple installations' in error, got: %v", err)
	}
}

// TestAppTokenCmd_NotFound verifies that apptoken errors when installation name doesn't match.
func TestAppTokenCmd_NotFound(t *testing.T) {
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/app/installations") {
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 10, "account": map[string]interface{}{"login": "alpha", "id": 1, "type": "Organization"}},
			})
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ghSrv.Close()

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ghp.yaml")
	cfgContent := fmt.Sprintf("github:\n  app_id: 12345\n  private_key: |\n    %s\n  base_url: %s\n",
		strings.ReplaceAll(testRSAKeyForCmd, "\n", "\n    "), ghSrv.URL)
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "apptoken", "nonexistent"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when installation name not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

// testRSAKeyForCmd is the same test-only RSA key used in github/app_test.go.
var testRSAKeyForCmd = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwUAwCT0ycvVRxvwAUe4RYLbAyPk2uEEpUJIb0VNvi9WWjPVl
AfRUGuvgnDSs46BbE+cnYSSG36xMDedASH2oH+p/mJb5vSgLpFjIkv/uX8XOmtZ6
jxOX5O12WtNgU2qpCX19UnDYipjY6YylePJ64eKP9XBGMOlGPHCXmFdDY6O+0uPw
wAd211IwT5PkhN/PixGiYpKAn7LvZ3je4Y1cmxRKw0A0CyTVKvG27PlA2jo+pTeK
St8cDa5L4vA6vkFqPqrFrAKa0te33Cu0Kkz6n3tx2DTeI+4pKQid+ze+125crynq
pvu5FMAkXCmVOLCaeHFMg2R+1qXQNoQ2v7QHdQIDAQABAoIBAE8KBjuZJIuhK4/T
nPvlf4ULaiEo0MkemZvDDo6YbgyG0LsZWPUqLcYPCIBLCRVWjjm/NruEGYfdLAQZ
u5CKmFtpaUOLKFzFxrEywOJiu+e++ygYJetj66Gtv9UZFBI6EyX3Be1UizRwnHM1
W65ymnDN3exYPdUea+QndtFPi5fx+JQGrVRzHDCzwBPvqMAebR+OaZ7p3OIAqlOI
Y+RWs/I3DQFXwdRpU1cSTv18/EEcbyOJN4fJv/jk77ntqkOW2tPoZlgOMvdZPqQC
K0DTZDKmfkZGUHwxaQtPR1jnxcx4rWVEFk2dxP5RBs8zUy8BrMwGVW3A5GfB3d2N
m6FNchcCgYEA4H3boVNV37ifGIZM00LV5F51tzRC4plDgnjznp5AZk/H9bJfC/I4
k+EN4VeGjg4jgfTQyEMHBXY6bpTnth7Xh7Yr44Qyji/j5JQFdAVA2ydFc5G95/Zk
LEhqnsnZ96qSQG8jKGrq5TmZumb13I2t22K+pYPbwl8MXgktB1Ck8ucCgYEA3F/S
fmmZkbJreYyubC/ZDidTxEcuVw0GVPtK2/ITi7R+YVqVg5JczBzlQIKGEJabtUrZ
0scS45b/87iw50mzRw0VvitNk/MQ4OJhMdBk1+RWK4m1udY/SQXEHKegO/LSIZbm
LkxR+eZywXVk50lJAyeuMolybxdej3XKvJaaQ0MCgYEAo6AYrYWoWeCfVajN5k4Y
yNNwyY/2EGPVqQuvxjViizArdxID5Rkv09l93HmHQZNcniRq6Qyx2XFLNb6jBUOF
pQ1LABIjJzAQ01JwhxgtJY+CN7JK0P/uE7jUvdgyXyqcXwqifZswitNpEUxqd89s
oTNf8hQh4ZKV2RSnFWXaVJECgYBVIJ7LPjeYVHe3yGRIXmNWWFK/a0+3SMy9XyUX
uXdbbCm1qaw/2vYF0tOsC7+GAOe9LGDgTw445EeS+jE75vhd5ewUPd4F3MsUU95/
w6Rw0T+IKfYNB3oC1zteZlI7Vh1d5FCeadTw19hUaujDf0e49EcSNo4B4+EfQb1D
BFoqyQKBgAJC8ejath862GxPQB9mpkuxwYR+Odp/Uz46xfyrSJrKb0BQrn9v6Kyd
lEYYwchE0C7L13qVoxEJN9U5XtgNERUpCQi3NCHwD8ADwpyAzQP57UBLS8Bb5ByC
xARUAV0AcnOf8WgFfswT1z7K4sJABdSBhP1URlo9YBW41+FAzQbm
-----END RSA PRIVATE KEY-----`

// TestLoadCLIConfig_InsecurePerms verifies that loadCLIConfig still loads config when file has insecure permissions.
func TestLoadCLIConfig_InsecurePerms(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")

	configDir := filepath.Join(home, ".config", "ghp")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	configContent := "server_url: http://file-server:8080\nuser_token: file-token\n"
	// Write with insecure permissions (world-readable) to trigger the warning path.
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Config should still be loaded despite insecure permissions (the function warns but does not fail).
	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "http://file-server:8080" {
		t.Errorf("ServerURL: got %q, want %q", cfg.ServerURL, "http://file-server:8080")
	}
	if cfg.UserToken != "file-token" {
		t.Errorf("UserToken: got %q, want %q", cfg.UserToken, "file-token")
	}
}
