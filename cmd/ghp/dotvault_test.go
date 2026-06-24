package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeReader is an in-memory dotvaultReader for tests.
type fakeReader struct {
	authErr   error
	authCalls int
	readErr   error
	// secrets is keyed by "service/field".
	secrets map[string]string
}

func (f *fakeReader) Authenticate(ctx context.Context) error {
	f.authCalls++
	return f.authErr
}

func (f *fakeReader) ReadUserSecret(ctx context.Context, service, field string) (string, bool, error) {
	if f.readErr != nil {
		return "", false, f.readErr
	}
	v, ok := f.secrets[service+"/"+field]
	return v, ok, nil
}

// withFakeReader swaps the package factory for the test and reports whether it
// was invoked and with which config path.
func withFakeReader(t *testing.T, r dotvaultReader, err error) *struct {
	called     bool
	configPath string
} {
	t.Helper()
	state := &struct {
		called     bool
		configPath string
	}{}
	orig := newDotvaultReader
	t.Cleanup(func() { newDotvaultReader = orig })
	newDotvaultReader = func(configPath string) (dotvaultReader, error) {
		state.called = true
		state.configPath = configPath
		return r, err
	}
	return state
}

func TestApplyDotvault_NoStanza(t *testing.T) {
	state := withFakeReader(t, &fakeReader{}, nil)
	cfg := &cliConfig{UserToken: "file-tok"}
	if err := cfg.applyDotvault(context.Background()); err != nil {
		t.Fatalf("applyDotvault: %v", err)
	}
	if state.called {
		t.Error("dotvault reader should not be constructed when no stanza is set")
	}
	if cfg.UserToken != "file-tok" {
		t.Errorf("UserToken = %q, want it left untouched", cfg.UserToken)
	}
}

func TestApplyDotvault_ResolvesUserToken(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{"ghp/token": "vault-tok"}}
	state := withFakeReader(t, reader, nil)
	cfg := &cliConfig{
		Dotvault: &dotvaultConfig{
			Service: "ghp",
			Config:  "/etc/dotvault/config.yaml",
			Fields:  map[string]string{"user_token": "token"},
		},
	}
	if err := cfg.applyDotvault(context.Background()); err != nil {
		t.Fatalf("applyDotvault: %v", err)
	}
	if cfg.UserToken != "vault-tok" {
		t.Errorf("UserToken = %q, want vault-tok", cfg.UserToken)
	}
	if reader.authCalls != 1 {
		t.Errorf("authCalls = %d, want 1", reader.authCalls)
	}
	if state.configPath != "/etc/dotvault/config.yaml" {
		t.Errorf("config path = %q, want it forwarded", state.configPath)
	}
}

func TestApplyDotvault_OverridesExistingValue(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{"ghp/token": "vault-tok"}}
	withFakeReader(t, reader, nil)
	cfg := &cliConfig{
		UserToken: "file-or-env-tok", // should be overridden — dotvault is highest precedence
		Dotvault: &dotvaultConfig{
			Service: "ghp",
			Fields:  map[string]string{"user_token": "token"},
		},
	}
	if err := cfg.applyDotvault(context.Background()); err != nil {
		t.Fatalf("applyDotvault: %v", err)
	}
	if cfg.UserToken != "vault-tok" {
		t.Errorf("UserToken = %q, want dotvault value to win", cfg.UserToken)
	}
}

func TestApplyDotvault_MultipleFields(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{
		"ghp/token":  "vault-tok",
		"ghp/server": "https://ghp.example.com",
	}}
	withFakeReader(t, reader, nil)
	cfg := &cliConfig{
		Dotvault: &dotvaultConfig{
			Service: "ghp",
			Fields: map[string]string{
				"user_token": "token",
				"server_url": "server",
			},
		},
	}
	if err := cfg.applyDotvault(context.Background()); err != nil {
		t.Fatalf("applyDotvault: %v", err)
	}
	if cfg.UserToken != "vault-tok" {
		t.Errorf("UserToken = %q, want vault-tok", cfg.UserToken)
	}
	if cfg.ServerURL != "https://ghp.example.com" {
		t.Errorf("ServerURL = %q, want resolved value", cfg.ServerURL)
	}
}

func TestApplyDotvault_UnknownFieldFailsFast(t *testing.T) {
	state := withFakeReader(t, &fakeReader{}, nil)
	cfg := &cliConfig{
		Dotvault: &dotvaultConfig{
			Service: "ghp",
			Fields:  map[string]string{"bogus": "x"},
		},
	}
	err := cfg.applyDotvault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown field mapping") {
		t.Fatalf("expected unknown field mapping error, got %v", err)
	}
	if state.called {
		t.Error("reader should not be constructed when a field mapping is invalid")
	}
}

func TestApplyDotvault_ServiceWithoutFields(t *testing.T) {
	withFakeReader(t, &fakeReader{}, nil)
	cfg := &cliConfig{Dotvault: &dotvaultConfig{Service: "ghp"}}
	err := cfg.applyDotvault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "fields") {
		t.Fatalf("expected fields-empty error, got %v", err)
	}
}

func TestApplyDotvault_FieldsWithoutService(t *testing.T) {
	withFakeReader(t, &fakeReader{}, nil)
	cfg := &cliConfig{Dotvault: &dotvaultConfig{Fields: map[string]string{"user_token": "token"}}}
	err := cfg.applyDotvault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("expected service-empty error, got %v", err)
	}
}

func TestApplyDotvault_AuthError(t *testing.T) {
	reader := &fakeReader{authErr: errors.New("vault unreachable")}
	withFakeReader(t, reader, nil)
	cfg := &cliConfig{Dotvault: &dotvaultConfig{Service: "ghp", Fields: map[string]string{"user_token": "token"}}}
	err := cfg.applyDotvault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected authentication error, got %v", err)
	}
}

func TestApplyDotvault_FieldNotFound(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{}} // ghp/token absent
	withFakeReader(t, reader, nil)
	cfg := &cliConfig{Dotvault: &dotvaultConfig{Service: "ghp", Fields: map[string]string{"user_token": "token"}}}
	err := cfg.applyDotvault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

func TestApplyDotvault_ReadError(t *testing.T) {
	reader := &fakeReader{readErr: errors.New("denied")}
	withFakeReader(t, reader, nil)
	cfg := &cliConfig{Dotvault: &dotvaultConfig{Service: "ghp", Fields: map[string]string{"user_token": "token"}}}
	err := cfg.applyDotvault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "reading ghp/token") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestApplyDotvault_FactoryError(t *testing.T) {
	withFakeReader(t, nil, errors.New("bad dotvault config"))
	cfg := &cliConfig{Dotvault: &dotvaultConfig{Service: "ghp", Fields: map[string]string{"user_token": "token"}}}
	err := cfg.applyDotvault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bad dotvault config") {
		t.Fatalf("expected factory error, got %v", err)
	}
}
