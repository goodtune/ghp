package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		{"ghs bearer", "Bearer ghs_bot123", "ghs_bot123"},
		{"gho token", "token gho_abc123", "gho_abc123"},
		{"ghs token", "token ghs_bot123", "ghs_bot123"},
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
	tests := []struct {
		name string
		user string
		pass string
		want string
	}{
		{"gho basic", "x-access-token", "gho_mytoken", "gho_mytoken"},
		{"ghs basic", "x-access-token", "ghs_bottoken", "ghs_bottoken"},
		{"ghp basic", "x-access-token", "ghp_pattoken", "ghp_pattoken"},
		{"wrong user", "username", "gho_mytoken", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			encoded := base64.StdEncoding.EncodeToString([]byte(tt.user + ":" + tt.pass))
			r.Header.Set("Authorization", "Basic "+encoded)
			got := extractRawGitHubToken(r)
			if got != tt.want {
				t.Errorf("extractRawGitHubToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsResolvableGitHubToken(t *testing.T) {
	tests := []struct {
		token string
		want  bool
		desc  string
	}{
		{"gho_abc", true, "OAuth user token"},
		{"ghp_abc", true, "personal access token"},
		{"ghu_abc", true, "user-to-server token"},
		{"ghs_abc", true, "GitHub App installation token (bot)"},
		{"ghx_abc", false, "ghx_ proxy token"},
		{"gha_abc", false, "gha_ agent token"},
		{"randomtoken", false, "no recognized prefix"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := isResolvableGitHubToken(tt.token)
			if got != tt.want {
				t.Errorf("isResolvableGitHubToken(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
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

func TestUsernameResolver_ResolveFromGitHubToken_NonResolvableToken(t *testing.T) {
	// gha_ and other non-resolvable token prefixes should be rejected without
	// any API call. The isResolvableGitHubToken guard must fire before any network I/O.
	resolver := NewUsernameResolver(newTestStore(t), nil)
	if got := resolver.ResolveFromGitHubToken(context.Background(), "gha_installationtoken"); got != "" {
		t.Errorf("expected empty string for non-resolvable token, got %q", got)
	}
	if got := resolver.ResolveFromGitHubToken(context.Background(), "ghx_unknown"); got != "" {
		t.Errorf("expected empty string for unknown prefix, got %q", got)
	}
}

// newMockGraphQLServer creates a mock GitHub GraphQL server that responds to
// the viewer query with the given login. It validates that the request uses
// POST, sends the correct GraphQL query, and carries a Bearer token.
func newMockGraphQLServer(t *testing.T, login string, callCount *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callCount != nil {
			callCount.Add(1)
		}

		// Validate the request is a proper GraphQL query.
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("expected Bearer auth header, got %q", auth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", contentType)
		}

		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]string
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Errorf("expected valid JSON body, got error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		query := reqBody["query"]
		if query != "query UserCurrent{viewer{login}}" {
			t.Errorf("expected viewer query, got %q", query)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{
					"login": login,
				},
			},
		})
	}))
}

func TestUsernameResolver_GraphQL_ResolvesUserToken(t *testing.T) {
	// A user token (gho_) should be resolved via the GraphQL viewer query.
	var callCount atomic.Int32
	srv := newMockGraphQLServer(t, "octocat", &callCount)
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))

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

	// Verify the GraphQL API was called exactly once (on the cache miss).
	if n := callCount.Load(); n != 1 {
		t.Errorf("expected exactly 1 GraphQL API call, got %d", n)
	}

	// Another call should be a cache hit with no additional API requests.
	if got := resolver.ResolveFromGitHubToken(context.Background(), "gho_testtoken"); got != "octocat" {
		t.Errorf("expected 'octocat' from cache on second call, got %q", got)
	}
	if n := callCount.Load(); n != 1 {
		t.Errorf("expected still 1 GraphQL API call after cache hit, got %d", n)
	}
}

func TestUsernameResolver_GraphQL_ResolvesBotToken(t *testing.T) {
	// A GitHub App installation token (ghs_) should be resolved via the
	// GraphQL viewer query, returning the bot account login.
	var callCount atomic.Int32
	srv := newMockGraphQLServer(t, "my-app[bot]", &callCount)
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))

	// First call: cache miss → triggers async lookup.
	if got := resolver.ResolveFromGitHubToken(context.Background(), "ghs_installtoken"); got != "" {
		t.Errorf("expected empty string on first cache miss, got %q", got)
	}

	// Poll until the async goroutine populates the cache.
	var cached string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if u := resolver.ResolveFromGitHubToken(context.Background(), "ghs_installtoken"); u != "" {
			cached = u
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cached != "my-app[bot]" {
		t.Errorf("expected 'my-app[bot]' from cache after async lookup, got %q", cached)
	}

	if n := callCount.Load(); n != 1 {
		t.Errorf("expected exactly 1 GraphQL API call for bot token, got %d", n)
	}
}

func TestUsernameResolver_GraphQL_CachesPerToken(t *testing.T) {
	// Different tokens should get independent cache entries and trigger
	// separate GraphQL lookups.
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		auth := r.Header.Get("Authorization")
		login := "unknown"
		if strings.Contains(auth, "gho_user") {
			login = "human-user"
		} else if strings.Contains(auth, "ghs_bot") {
			login = "bot-user[bot]"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{
					"login": login,
				},
			},
		})
	}))
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))

	// Trigger lookups for both tokens.
	resolver.ResolveFromGitHubToken(context.Background(), "gho_user")
	resolver.ResolveFromGitHubToken(context.Background(), "ghs_bot")

	// Poll until both are cached.
	deadline := time.Now().Add(5 * time.Second)
	var userCached, botCached string
	for time.Now().Before(deadline) {
		if userCached == "" {
			userCached = resolver.ResolveFromGitHubToken(context.Background(), "gho_user")
		}
		if botCached == "" {
			botCached = resolver.ResolveFromGitHubToken(context.Background(), "ghs_bot")
		}
		if userCached != "" && botCached != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if userCached != "human-user" {
		t.Errorf("expected 'human-user' for gho_ token, got %q", userCached)
	}
	if botCached != "bot-user[bot]" {
		t.Errorf("expected 'bot-user[bot]' for ghs_ token, got %q", botCached)
	}

	if n := callCount.Load(); n != 2 {
		t.Errorf("expected 2 GraphQL API calls (one per token), got %d", n)
	}
}

func TestUsernameResolver_GraphQL_NoDuplicateGoroutines(t *testing.T) {
	// Verify that concurrent cache misses for the same token spawn only one
	// goroutine (i.e. the in-flight deduplication works).
	blocked := make(chan struct{})
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		<-blocked // hold the response until we release it
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{
					"login": "octocat",
				},
			},
		})
	}))
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))

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

	// Only one goroutine should have reached the GraphQL API.
	if n := callCount.Load(); n != 1 {
		t.Errorf("expected exactly 1 GraphQL API call with in-flight deduplication, got %d", n)
	}
}

func TestUsernameResolver_GraphQL_HandlesErrorGracefully(t *testing.T) {
	// A failing GraphQL endpoint should not cache anything, and subsequent
	// calls should retry.
	var callCount atomic.Int32
	// Buffered channel signals each time a handler invocation completes.
	done := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
		done <- struct{}{}
	}))
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))

	// First call: cache miss → triggers async lookup that will fail.
	resolver.ResolveFromGitHubToken(context.Background(), "gho_badtoken")

	// Wait for the async goroutine's HTTP handler to finish.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first async lookup to complete")
	}

	// Wait until the resolver goroutine has cleared the inflight entry. Without
	// this there is a race: the handler signals done before defer inflight.Delete
	// runs, so the next call may hit the in-flight guard and skip the retry.
	inflightKey := hashToken("gho_badtoken")
	inflightDeadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := resolver.inflight.Load(inflightKey); !ok {
			break
		}
		if time.Now().After(inflightDeadline) {
			t.Fatal("timeout waiting for inflight entry to clear after first lookup")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Should still return empty (error response is not cached).
	if got := resolver.ResolveFromGitHubToken(context.Background(), "gho_badtoken"); got != "" {
		t.Errorf("expected empty string after failed lookup, got %q", got)
	}

	// Wait for the retry goroutine's HTTP handler to finish.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for retry async lookup to complete")
	}

	// Should have made at least 2 API calls (initial + retry).
	if n := callCount.Load(); n < 2 {
		t.Errorf("expected at least 2 GraphQL API calls after error + retry, got %d", n)
	}
}

func TestUsernameResolver_GraphQL_HandlesGraphQLErrors(t *testing.T) {
	// GitHub GraphQL returns HTTP 200 with a top-level "errors" array for
	// auth/rate-limit/abuse failures. The resolver must treat this as a failed
	// lookup and not cache the empty login.
	var callCount atomic.Int32
	done := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// HTTP 200 with a GraphQL-level error (e.g. insufficient scopes).
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errors":[{"message":"Your token has not been granted the required scopes."}]}`))
		done <- struct{}{}
	}))
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))

	// First call: cache miss → triggers async lookup that returns a GraphQL error.
	resolver.ResolveFromGitHubToken(context.Background(), "gho_scopetoken")

	// Wait for the async goroutine's HTTP handler to finish.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first async lookup to complete")
	}

	// Wait until the resolver goroutine has cleared the inflight entry. Without
	// this there is a race: the handler signals done before defer inflight.Delete
	// runs, so the next call may hit the in-flight guard and skip the retry.
	inflightKey := hashToken("gho_scopetoken")
	inflightDeadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := resolver.inflight.Load(inflightKey); !ok {
			break
		}
		if time.Now().After(inflightDeadline) {
			t.Fatal("timeout waiting for inflight entry to clear after first lookup")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Nothing should be cached — the error response must not populate the cache.
	if got := resolver.ResolveFromGitHubToken(context.Background(), "gho_scopetoken"); got != "" {
		t.Errorf("expected empty string after GraphQL error response, got %q", got)
	}

	// Wait for the retry goroutine's HTTP handler to finish.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for retry async lookup to complete")
	}

	// The retry confirms the error was not cached and another lookup was attempted.
	if n := callCount.Load(); n < 2 {
		t.Errorf("expected at least 2 GraphQL API calls after error + retry, got %d", n)
	}
}

func TestUsernameResolver_GraphQL_SendsCorrectQuery(t *testing.T) {
	// Verify the exact GraphQL query sent matches the expected viewer query.
	var receivedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]string
		json.Unmarshal(body, &reqBody)
		receivedQuery = reqBody["query"]

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{
					"login": "testuser",
				},
			},
		})
	}))
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))
	resolver.ResolveFromGitHubToken(context.Background(), "gho_querytest")

	// Wait for the async goroutine to complete.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resolver.ResolveFromGitHubToken(context.Background(), "gho_querytest") != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if receivedQuery != "query UserCurrent{viewer{login}}" {
		t.Errorf("expected query 'query UserCurrent{viewer{login}}', got %q", receivedQuery)
	}
}

func TestUsernameResolver_GraphQL_ForwardsBearerToken(t *testing.T) {
	// Verify the resolver forwards the raw token as a Bearer credential.
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{
					"login": "testuser",
				},
			},
		})
	}))
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))
	resolver.ResolveFromGitHubToken(context.Background(), "gho_authtest123")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resolver.ResolveFromGitHubToken(context.Background(), "gho_authtest123") != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if receivedAuth != "Bearer gho_authtest123" {
		t.Errorf("expected 'Bearer gho_authtest123', got %q", receivedAuth)
	}
}

func TestUsernameResolver_GraphQL_BasicAuth_BotToken(t *testing.T) {
	// Verify that a ghs_ token delivered via Basic auth (x-access-token:<token>)
	// is extracted and resolved through the GraphQL viewer query.
	srv := newMockGraphQLServer(t, "deploy-bot[bot]", nil)
	defer srv.Close()

	resolver := NewUsernameResolver(newTestStore(t), nil, WithGraphQLURL(srv.URL))

	// Simulate extracting the raw token from a Basic auth header.
	r := httptest.NewRequest("GET", "/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_bottoken"))
	r.Header.Set("Authorization", "Basic "+encoded)

	rawToken := extractRawGitHubToken(r)
	if rawToken != "ghs_bottoken" {
		t.Fatalf("expected ghs_bottoken from Basic auth extraction, got %q", rawToken)
	}

	// Trigger the resolver with the extracted token.
	resolver.ResolveFromGitHubToken(context.Background(), rawToken)

	// Poll until cached.
	var cached string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if u := resolver.ResolveFromGitHubToken(context.Background(), rawToken); u != "" {
			cached = u
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cached != "deploy-bot[bot]" {
		t.Errorf("expected 'deploy-bot[bot]' for ghs_ token via Basic auth, got %q", cached)
	}
}
