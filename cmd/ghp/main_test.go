package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// buildRootCmd constructs the root cobra.Command tree mirroring main().
func buildRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ghp",
		Short: "GitHub Proxy for Autonomous Coding Agents",
		Long:  "ghp is a GitHub API reverse proxy that issues scoped, auditable tokens to autonomous coding agents.",
	}
	rootCmd.PersistentFlags().String("config", "", "path to server configuration file (or set GHP_CONFIG)")
	rootCmd.AddCommand(
		newServeCmd(),
		newMigrateCmd(),
		newAuthCmd(),
		newTokenCmd(),
		newVersionCmd(),
		newDocCmd(rootCmd),
	)
	return rootCmd
}

// TestHelpOutput_Root verifies that the root help text mentions all subcommands and flags.
func TestHelpOutput_Root(t *testing.T) {
	rootCmd := buildRootCmd()
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

// TestHelpOutput_Auth verifies that "ghp auth --help" mentions login and status subcommands.
func TestHelpOutput_Auth(t *testing.T) {
	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"login", "status"} {
		if !strings.Contains(output, want) {
			t.Errorf("auth help: expected %q to appear in output:\n%s", want, output)
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

// TestAuthLoginCmd_WithServerURL verifies that auth login prints the authentication URL when configured.
func TestAuthLoginCmd_WithServerURL(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "http://localhost:9999")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("auth login error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "http://localhost:9999/auth/github") {
		t.Errorf("expected auth URL in output, got: %q", output)
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

// TestTokenCreateCmd_ProxyToken verifies that token create calls the stub server and prints the token.
func TestTokenCreateCmd_ProxyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/tokens" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
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

// TestTokenCreateCmd_AgentTokenMissingRepos verifies that agent token creation requires --repos.
func TestTokenCreateCmd_AgentTokenMissingRepos(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "http://localhost:9999")
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--type", "agent", "--scope", "contents:read"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --repos is missing for agent token")
	}
	if !strings.Contains(err.Error(), "--repos") {
		t.Errorf("expected '--repos' in error, got: %v", err)
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
