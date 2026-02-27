package config

import (
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
