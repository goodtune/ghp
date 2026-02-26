package proxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	ghub "github.com/google/go-github/v68/github"
)

func TestExtractRawGitHubToken_Bearer(t *testing.T) {
	tests := []struct {
		name string
		auth string
		want string
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

func TestUsernameResolver_ResolveFromGitHubToken_NonUserToken(t *testing.T) {
	// gha_ and other non-user token prefixes should be rejected without any
	// API call. The isGitHubUserToken guard must fire before any network I/O.
	resolver := NewUsernameResolver(newTestStore(t), nil)
	if got := resolver.ResolveFromGitHubToken(context.Background(), "gha_installationtoken"); got != "" {
		t.Errorf("expected empty string for non-user token, got %q", got)
	}
	if got := resolver.ResolveFromGitHubToken(context.Background(), "ghx_unknown"); got != "" {
		t.Errorf("expected empty string for unknown prefix, got %q", got)
	}
}

func TestUsernameResolver_ResolveFromGitHubToken_CachesResult(t *testing.T) {
	// Start a mock GitHub API server that returns a fixed user login.
	var callCount atomic.Int32
	githubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer githubSrv.Close()

	srvURL, _ := url.Parse(githubSrv.URL + "/")
	resolver := NewUsernameResolver(newTestStore(t), nil, WithGitHubClientFactory(func(token string) *ghub.Client {
		c := ghub.NewClient(nil).WithAuthToken(token)
		c.BaseURL = srvURL
		return c
	}))

	// First call: cache miss → triggers async lookup, returns "".
	if got := resolver.ResolveFromGitHubToken(context.Background(), "gho_testtoken"); got != "" {
		t.Errorf("expected empty string on first cache miss, got %q", got)
	}

	// Poll until the async goroutine populates the cache (or timeout).
	var cached string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if u := resolver.ResolveFromGitHubToken(context.Background(), "gho_testtoken"); u != "" {
			cached = u
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cached != "octocat" {
		t.Errorf("expected 'octocat' from cache after async lookup, got %q", cached)
	}

	// Verify the GitHub API was called exactly once (on the cache miss).
	if n := callCount.Load(); n != 1 {
		t.Errorf("expected exactly 1 GitHub API call, got %d", n)
	}

	// Another call should be a cache hit with no additional API requests.
	if got := resolver.ResolveFromGitHubToken(context.Background(), "gho_testtoken"); got != "octocat" {
		t.Errorf("expected 'octocat' from cache on second call, got %q", got)
	}
	if n := callCount.Load(); n != 1 {
		t.Errorf("expected still 1 GitHub API call after cache hit, got %d", n)
	}
}

func TestUsernameResolver_ResolveFromGitHubToken_NoDuplicateGoroutines(t *testing.T) {
	// Verify that concurrent cache misses for the same token spawn only one
	// goroutine (i.e. the in-flight deduplication works).
	blocked := make(chan struct{})
	var callCount atomic.Int32
	githubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		<-blocked // hold the response until we release it
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer githubSrv.Close()

	srvURL, _ := url.Parse(githubSrv.URL + "/")
	resolver := NewUsernameResolver(newTestStore(t), nil, WithGitHubClientFactory(func(token string) *ghub.Client {
		c := ghub.NewClient(nil).WithAuthToken(token)
		c.BaseURL = srvURL
		return c
	}))

	// Fire several concurrent cache misses for the same token.
	for range 5 {
		resolver.ResolveFromGitHubToken(context.Background(), "gho_deduptoken")
	}

	// Release the blocked server handler.
	close(blocked)

	// Poll for the cache to be populated.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resolver.ResolveFromGitHubToken(context.Background(), "gho_deduptoken") != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Only one goroutine should have reached the GitHub API.
	if n := callCount.Load(); n != 1 {
		t.Errorf("expected exactly 1 GitHub API call with in-flight deduplication, got %d", n)
	}
}
