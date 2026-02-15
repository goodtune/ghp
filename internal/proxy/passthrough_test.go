package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

type mockTokenResolver struct {
	token string
	err   error
}

func (m *mockTokenResolver) ResolveToGitHubToken(ctx context.Context, ghpToken string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

func TestPassthroughHandler_NoAuth(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("expected no auth header for passthrough, got %q", auth)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>github</html>"))
	}))
	defer upstream.Close()

	handler := NewPassthroughHandler(upstream.URL, nil, "", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPassthroughHandler_GhpToken(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer real-github-token" {
			t.Errorf("expected rewritten auth, got %q", auth)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	resolver := &mockTokenResolver{token: "real-github-token"}

	handler := NewPassthroughHandler(upstream.URL, resolver, "", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://github.com/org/repo.git/info/refs", nil)
	req.Header.Set("Authorization", "Bearer "+token.Prefix+"abc123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPassthroughHandler_EnterpriseHeader(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ent := r.Header.Get("sec-GitHub-allowed-enterprise")
		if ent != "my-enterprise" {
			t.Errorf("expected enterprise header 'my-enterprise', got %q", ent)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewPassthroughHandler(upstream.URL, nil, "my-enterprise", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://github.com/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestCopilotPassthroughHandler(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.githubcopilot.com" {
			t.Errorf("expected host api.githubcopilot.com, got %q", r.Host)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewCopilotPassthroughHandler(upstream.URL, "", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://api.githubcopilot.com/some/path", nil)
	req.Host = "api.githubcopilot.com"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestCopilotPassthroughHandler_EnterpriseHeader(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ent := r.Header.Get("sec-GitHub-allowed-enterprise")
		if ent != "my-enterprise" {
			t.Errorf("expected enterprise header 'my-enterprise', got %q", ent)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewCopilotPassthroughHandler(upstream.URL, "my-enterprise", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://api.githubcopilot.com/", nil)
	req.Host = "api.githubcopilot.com"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// newScopedPassthrough creates a ScopedPassthroughHandler backed by a real
// token.Service and SQLite store, issues a ghp_ token scoped to the given
// repository and scopes, and returns the handler plus the plaintext token.
// The upstream test server simply returns 200 for all requests.
func newScopedPassthrough(t *testing.T, repo string, scopes map[string]string) (http.Handler, string) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()

	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	user := &database.User{GitHubID: 1, GitHubUsername: "testuser", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	encAccess, err := enc.Encrypt("real-github-pat")
	if err != nil {
		t.Fatal(err)
	}
	gt := &database.GitHubToken{
		UserID:                user.ID,
		AccessToken:           encAccess,
		RefreshToken:          "enc_refresh",
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
	}
	if err := store.UpsertGitHubToken(ctx, gt); err != nil {
		t.Fatal(err)
	}

	tokenSvc := token.NewService(store, 7*24*time.Hour)
	result, err := tokenSvc.Create(ctx, token.CreateRequest{
		UserID:        user.ID,
		GitHubTokenID: gt.ID,
		Repository:    repo,
		Scopes:        scopes,
		Duration:      24 * time.Hour,
		SessionID:     "test-session",
	})
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	resolver := NewProxyTokenResolver(tokenSvc, store, enc)
	inner := NewPassthroughHandler(upstream.URL, nil, "", nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, tokenSvc, resolver, slog.Default())

	return handler, result.Token
}

func TestScopedPassthrough_GitPush_InsufficientPermission(t *testing.T) {
	// ghp_ token scoped to goodtune/ghp with contents:read must be rejected
	// for git-receive-pack (push requires contents:write).
	handler, ghpToken := newScopedPassthrough(t, "goodtune/ghp", map[string]string{
		"contents": "read",
	})

	req := httptest.NewRequest("POST", "http://github.com/goodtune/ghp.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only token attempting push, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "contents:write") {
		t.Errorf("expected error to mention required contents:write permission, got: %s", body)
	}
}

func TestScopedPassthrough_GitPush_WrongRepository(t *testing.T) {
	// ghp_ token scoped to goodtune/ghp must be rejected when used
	// against a different repository.
	handler, ghpToken := newScopedPassthrough(t, "goodtune/ghp", map[string]string{
		"contents": "write",
	})

	req := httptest.NewRequest("POST", "http://github.com/goodtune/pac-proxy.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong repository, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "goodtune/ghp") {
		t.Errorf("expected error to mention scoped repository, got: %s", body)
	}
	if !strings.Contains(body, "goodtune/pac-proxy") {
		t.Errorf("expected error to mention requested repository, got: %s", body)
	}
}

func TestScopedPassthrough_GitFetch_Allowed(t *testing.T) {
	// ghp_ token scoped to goodtune/ghp with contents:read should be
	// allowed for git-upload-pack (clone/fetch).
	handler, ghpToken := newScopedPassthrough(t, "goodtune/ghp", map[string]string{
		"contents": "read",
	})

	req := httptest.NewRequest("GET", "http://github.com/goodtune/ghp.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for read token fetching, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestScopedPassthrough_NonGitPath_PassesThrough(t *testing.T) {
	// A request to a non-git path should pass through without scope enforcement.
	handler, ghpToken := newScopedPassthrough(t, "goodtune/ghp", map[string]string{
		"contents": "read",
	})

	req := httptest.NewRequest("GET", "http://github.com/goodtune/other-repo", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should pass through (inner handler returns 200).
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-git path, got %d", rr.Code)
	}
}

// tlsTransport returns an http.RoundTripper that trusts the test server's cert.
func tlsTransport(ts *httptest.Server) http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}
