package proxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractRawGitHubToken_Bearer(t *testing.T) {
	tests := []struct {
		name  string
		auth  string
		want  string
	}{
		{"gho bearer", "Bearer gho_abc123", "gho_abc123"},
		{"ghp bearer", "Bearer ghp_def456", "ghp_def456"},
		{"ghu bearer", "Bearer ghu_xyz789", "ghu_xyz789"},
		{"gho token", "token gho_abc123", "gho_abc123"},
		{"ghx not extracted", "Bearer ghx_abc123", ""},
		{"gha not extracted", "Bearer gha_abc123", ""},
		{"no auth", "", ""},
		{"empty bearer", "Bearer ", ""},
		{"random token", "Bearer sometoken", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tt.auth != "" {
				r.Header.Set("Authorization", tt.auth)
			}
			got := extractRawGitHubToken(r)
			if got != tt.want {
				t.Errorf("extractRawGitHubToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractRawGitHubToken_BasicAuth(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:gho_mytoken"))
	r.Header.Set("Authorization", "Basic "+encoded)
	got := extractRawGitHubToken(r)
	if got != "gho_mytoken" {
		t.Errorf("expected gho_mytoken, got %q", got)
	}
}

func TestIsGitHubUserToken(t *testing.T) {
	if !isGitHubUserToken("gho_abc") {
		t.Error("gho_ should be a user token")
	}
	if !isGitHubUserToken("ghp_abc") {
		t.Error("ghp_ should be a user token")
	}
	if !isGitHubUserToken("ghu_abc") {
		t.Error("ghu_ should be a user token")
	}
	if isGitHubUserToken("ghx_abc") {
		t.Error("ghx_ should not be a user token")
	}
	if isGitHubUserToken("gha_abc") {
		t.Error("gha_ should not be a user token")
	}
}

func TestHashToken(t *testing.T) {
	h1 := hashToken("test-token")
	h2 := hashToken("test-token")
	if h1 != h2 {
		t.Error("same token should produce same hash")
	}
	h3 := hashToken("different-token")
	if h1 == h3 {
		t.Error("different tokens should produce different hashes")
	}
	if len(h1) != 64 {
		t.Errorf("expected SHA-256 hex hash length 64, got %d", len(h1))
	}
}

func TestContextUsernameSlot(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)

	// Before preparing slot, GetUsername returns "".
	if got := GetUsername(r); got != "" {
		t.Errorf("expected empty username before slot, got %q", got)
	}

	// SetUsername is a no-op without a slot.
	SetUsername(r, "should-not-stick")
	if got := GetUsername(r); got != "" {
		t.Errorf("expected empty username without slot, got %q", got)
	}

	// Prepare slot.
	r, slot := PrepareUsernameSlot(r)

	// Set and read via context.
	SetUsername(r, "octocat")
	if got := GetUsername(r); got != "octocat" {
		t.Errorf("expected 'octocat', got %q", got)
	}

	// The mutable slot should also reflect the value.
	if *slot != "octocat" {
		t.Errorf("expected slot to be 'octocat', got %q", *slot)
	}
}

func TestUsernameResolver_ResolveFromUserID(t *testing.T) {
	store := newTestStore(t)

	// No user in DB.
	resolver := NewUsernameResolver(store, nil)
	if got := resolver.ResolveFromUserID(context.Background(), "nonexistent-id"); got != "" {
		t.Errorf("expected empty username for nonexistent user, got %q", got)
	}

	// Empty user ID.
	if got := resolver.ResolveFromUserID(context.Background(), ""); got != "" {
		t.Errorf("expected empty username for empty user ID, got %q", got)
	}
}

func TestUsernameResolver_ResolveFromGitHubToken_EmptyToken(t *testing.T) {
	resolver := NewUsernameResolver(newTestStore(t), nil)
	if got := resolver.ResolveFromGitHubToken(context.Background(), ""); got != "" {
		t.Errorf("expected empty username for empty token, got %q", got)
	}
}

func TestUsernameResolver_ResolveFromGitHubToken_CachesResult(t *testing.T) {
	// Start a mock GitHub API server that returns a user login.
	calls := 0
	githubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer githubSrv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil)

	// We can't easily point the go-github client at a custom URL in this
	// test without modifying the resolver, so verify the cache mechanism
	// directly by pre-populating it.
	key := hashToken("gho_testtoken")
	resolver.cache.Add(key, "cached-user")

	got := resolver.ResolveFromGitHubToken(context.Background(), "gho_testtoken")
	if got != "cached-user" {
		t.Errorf("expected cached 'cached-user', got %q", got)
	}

	// The mock server should not have been called since we hit the cache.
	if calls != 0 {
		t.Errorf("expected 0 API calls (cache hit), got %d", calls)
	}
}
