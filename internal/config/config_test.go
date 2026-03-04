package config

import (
	"os"
	"testing"
)

func TestLoadAdminsFromEnv(t *testing.T) {
	t.Setenv("GHP_ADMINS", "alice, bob , charlie")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alice", "bob", "charlie"}
	if len(cfg.Admins) != len(want) {
		t.Fatalf("expected %d admins, got %d: %v", len(want), len(cfg.Admins), cfg.Admins)
	}
	for i, w := range want {
		if cfg.Admins[i] != w {
			t.Errorf("Admins[%d] = %q, want %q", i, cfg.Admins[i], w)
		}
	}
}

func TestLoadAllowedRedirectsFromEnv(t *testing.T) {
	t.Setenv("GHP_AUTH_ALLOWED_REDIRECTS", "https://a.example.com/cb,*.internal.example.com")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://a.example.com/cb", "*.internal.example.com"}
	if len(cfg.Auth.AllowedRedirects) != len(want) {
		t.Fatalf("expected %d redirects, got %d: %v", len(want), len(cfg.Auth.AllowedRedirects), cfg.Auth.AllowedRedirects)
	}
	for i, w := range want {
		if cfg.Auth.AllowedRedirects[i] != w {
			t.Errorf("AllowedRedirects[%d] = %q, want %q", i, cfg.Auth.AllowedRedirects[i], w)
		}
	}
}

func TestLoadTLSCertFromEnv(t *testing.T) {
	t.Setenv("GHP_TLS_CERT_FILE", "/tmp/test.crt")
	t.Setenv("GHP_TLS_KEY_FILE", "/tmp/test.key")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TLS.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.TLS.Certificates))
	}
	if cfg.TLS.Certificates[0].CertFile != "/tmp/test.crt" {
		t.Errorf("CertFile = %q, want /tmp/test.crt", cfg.TLS.Certificates[0].CertFile)
	}
	if cfg.TLS.Certificates[0].KeyFile != "/tmp/test.key" {
		t.Errorf("KeyFile = %q, want /tmp/test.key", cfg.TLS.Certificates[0].KeyFile)
	}
}

func TestLoadTLSCertFromEnvPartial(t *testing.T) {
	// Only cert, no key — should not populate the slice.
	t.Setenv("GHP_TLS_CERT_FILE", "/tmp/test.crt")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TLS.Certificates) != 0 {
		t.Fatalf("expected 0 certificates when only cert is set, got %d", len(cfg.TLS.Certificates))
	}
}

func TestLoadBlockFromEnv(t *testing.T) {
	t.Setenv("GHP_BLOCK_GHO", "true")
	t.Setenv("GHP_BLOCK_GHU", "true")
	t.Setenv("GHP_BLOCK_GHS", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Block.GHO != true {
		t.Error("expected Block.GHO to be true")
	}
	if cfg.Block.GHU != true {
		t.Error("expected Block.GHU to be true")
	}
	if cfg.Block.GHS != true {
		t.Error("expected Block.GHS to be true")
	}
	// These were not set.
	if cfg.Block.GHP != false {
		t.Error("expected Block.GHP to be false")
	}
	if cfg.Block.GHR != false {
		t.Error("expected Block.GHR to be false")
	}
}

func TestIsTokenBlocked(t *testing.T) {
	tests := []struct {
		name    string
		block   BlockConfig
		token   string
		blocked bool
	}{
		{name: "ghp blocked", block: BlockConfig{GHP: true}, token: "ghp_abc123", blocked: true},
		{name: "gho blocked", block: BlockConfig{GHO: true}, token: "gho_abc123", blocked: true},
		{name: "ghu blocked", block: BlockConfig{GHU: true}, token: "ghu_abc123", blocked: true},
		{name: "ghs blocked", block: BlockConfig{GHS: true}, token: "ghs_abc123", blocked: true},
		{name: "ghr blocked", block: BlockConfig{GHR: true}, token: "ghr_abc123", blocked: true},
		{name: "gho not blocked", block: BlockConfig{}, token: "gho_abc123", blocked: false},
		{name: "ghp not blocked", block: BlockConfig{}, token: "ghp_abc123", blocked: false},
		{name: "ghx never blocked", block: BlockConfig{GHP: true, GHO: true}, token: "ghx_abc123", blocked: false},
		{name: "gha never blocked", block: BlockConfig{GHP: true, GHO: true}, token: "gha_abc123", blocked: false},
		{name: "unknown prefix", block: BlockConfig{GHP: true}, token: "xyz_abc123", blocked: false},
		{name: "empty token", block: BlockConfig{GHP: true}, token: "", blocked: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Block: tt.block}
			got := cfg.IsTokenBlocked(tt.token)
			if got != tt.blocked {
				t.Errorf("IsTokenBlocked(%q) = %v, want %v", tt.token, got, tt.blocked)
			}
		})
	}
}

func TestLoadBlockAnonymousGitFromEnv(t *testing.T) {
	t.Setenv("GHP_BLOCK_ANONYMOUS_GIT", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Block.AnonymousGit {
		t.Error("expected Block.AnonymousGit to be true")
	}
}

func TestLoadBlockAnonymousGitFromYAML(t *testing.T) {
	f, err := os.CreateTemp("", "ghp-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("block:\n  anonymous_git: true\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Block.AnonymousGit {
		t.Error("expected Block.AnonymousGit to be true when set in YAML")
	}
}
