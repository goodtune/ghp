package main

import (
	"os"
	"path/filepath"
	"testing"
)

// setSystemConfig points systemCLIConfigPath at a temp file with the given
// contents for the duration of the test. Pass "" to leave the file absent.
func setSystemConfig(t *testing.T, contents string) {
	t.Helper()
	orig := systemConfigPathOverride
	t.Cleanup(func() { systemConfigPathOverride = orig })
	path := filepath.Join(t.TempDir(), "system-config.yaml")
	if contents != "" {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatalf("write system config: %v", err)
		}
	}
	systemConfigPathOverride = path
}

// writeUserConfig writes a user config under the HOME set for the test.
func writeUserConfig(t *testing.T, home, contents string) {
	t.Helper()
	dir := filepath.Join(home, ".config", "ghp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir user config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(contents), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}
}

func TestLoadCLIConfig_SystemFileOnly(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir()) // no user config written
	setSystemConfig(t, "server_url: http://sys-server:8080\nuser_token: sys-token\n")

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.ServerURL != "http://sys-server:8080" {
		t.Errorf("ServerURL = %q, want system value", cfg.ServerURL)
	}
	if cfg.UserToken != "sys-token" {
		t.Errorf("UserToken = %q, want system value", cfg.UserToken)
	}
}

func TestLoadCLIConfig_UserOverloadsSystem(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	setSystemConfig(t, "server_url: http://sys-server:8080\nuser_token: sys-token\n")
	// User overrides only the server_url; user_token should fall through to system.
	writeUserConfig(t, home, "server_url: http://user-server:9090\n")

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.ServerURL != "http://user-server:9090" {
		t.Errorf("ServerURL = %q, want user override", cfg.ServerURL)
	}
	if cfg.UserToken != "sys-token" {
		t.Errorf("UserToken = %q, want system value to fall through", cfg.UserToken)
	}
}

func TestLoadCLIConfig_EnvOverridesSystemAndUser(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "http://env-server:7070")
	t.Setenv("GHP_USER_TOKEN", "env-token")
	home := t.TempDir()
	t.Setenv("HOME", home)
	setSystemConfig(t, "server_url: http://sys-server:8080\nuser_token: sys-token\n")
	writeUserConfig(t, home, "server_url: http://user-server:9090\nuser_token: user-token\n")

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.ServerURL != "http://env-server:7070" {
		t.Errorf("ServerURL = %q, want env value", cfg.ServerURL)
	}
	if cfg.UserToken != "env-token" {
		t.Errorf("UserToken = %q, want env value", cfg.UserToken)
	}
}

// TestLoadCLIConfig_DotvaultStanzaFromSystem is the zero-user-config fleet
// case: the dotvault stanza is deployed in /etc and picked up with no
// ~/.config present.
func TestLoadCLIConfig_DotvaultStanzaFromSystem(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	setSystemConfig(t, `server_url: http://sys-server:8080
dotvault:
  service: ghp
  fields:
    user_token: token
`)

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.Dotvault == nil {
		t.Fatal("Dotvault stanza = nil, want it loaded from the system file")
	}
	if cfg.Dotvault.Service != "ghp" {
		t.Errorf("Dotvault.Service = %q, want ghp", cfg.Dotvault.Service)
	}
	if cfg.Dotvault.Fields["user_token"] != "token" {
		t.Errorf("Dotvault.Fields[user_token] = %q, want token", cfg.Dotvault.Fields["user_token"])
	}
}

func TestLoadCLIConfig_UserDotvaultOverridesSystem(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	setSystemConfig(t, "dotvault:\n  service: sys-service\n  fields:\n    user_token: token\n")
	writeUserConfig(t, home, "dotvault:\n  service: user-service\n  fields:\n    user_token: token\n")

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.Dotvault == nil || cfg.Dotvault.Service != "user-service" {
		t.Fatalf("Dotvault.Service = %v, want user's stanza to win", cfg.Dotvault)
	}
}

// TestLoadCLIConfig_NoSystemFile confirms a missing system file is silently
// ignored (no warning, no error) — the common case on machines without /etc
// deployment.
func TestLoadCLIConfig_NoSystemFile(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	setSystemConfig(t, "") // path set but file absent
	writeUserConfig(t, home, "server_url: http://user-server:9090\nuser_token: user-token\n")

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.ServerURL != "http://user-server:9090" || cfg.UserToken != "user-token" {
		t.Errorf("cfg = %+v, want user values with absent system file", cfg)
	}
}
