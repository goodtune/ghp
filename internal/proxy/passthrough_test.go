package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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

func TestPassthroughHandler_GhpToken_SchemePreserved(t *testing.T) {
	// The proxy must preserve the original Authorization scheme when
	// rewriting a ghp_ token to the real GitHub credential.
	ghpTok := token.PrefixProxy + "abc123"
	tests := []struct {
		name       string
		authHeader string
		wantScheme string
	}{
		{
			name:       "Bearer",
			authHeader: "Bearer " + ghpTok,
			wantScheme: "Bearer real-github-token",
		},
		{
			name:       "token",
			authHeader: "token " + ghpTok,
			wantScheme: "token real-github-token",
		},
		{
			name:       "Basic",
			authHeader: basicAuth("x-access-token", ghpTok),
			wantScheme: basicAuth("x-access-token", "real-github-token"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != tt.wantScheme {
					t.Errorf("expected %q, got %q", tt.wantScheme, auth)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			resolver := &mockTokenResolver{token: "real-github-token"}
			handler := NewPassthroughHandler(upstream.URL, resolver, "", nil, tlsTransport(upstream))

			req := httptest.NewRequest("GET", "http://github.com/org/repo.git/info/refs", nil)
			req.Header.Set("Authorization", tt.authHeader)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
		})
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

	resolver := NewProxyTokenResolver(tokenSvc, store, enc, nil)
	inner := NewPassthroughHandler(upstream.URL, nil, "", nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, tokenSvc, resolver, nil, slog.Default())

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
	// Token scoped to goodtune/ghp must be rejected when used
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

// basicAuth encodes credentials as a Basic auth header value per RFC 7617.
// GitHub documents this format as "x-access-token:<token>" for Git HTTP access.
func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// TestPassthroughHandler_BasicAuth_GhpToken is now covered by
// TestPassthroughHandler_GhpToken_SchemePreserved (Basic subtest).

func TestScopedPassthrough_BasicAuth_GitFetch_Allowed(t *testing.T) {
	// A ghp_ token delivered via Basic auth (x-access-token:<token>) should
	// be recognised and subject to the same scope enforcement as Bearer tokens.
	handler, ghpToken := newScopedPassthrough(t, "goodtune/ghp", map[string]string{
		"contents": "read",
	})

	req := httptest.NewRequest("GET", "http://github.com/goodtune/ghp.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", basicAuth("x-access-token", ghpToken))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for Basic auth read token fetching, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestScopedPassthrough_BasicAuth_GitPush_InsufficientPermission(t *testing.T) {
	// A ghp_ token sent via Basic auth with only contents:read must still
	// be rejected for git-receive-pack (push requires contents:write).
	handler, ghpToken := newScopedPassthrough(t, "goodtune/ghp", map[string]string{
		"contents": "read",
	})

	req := httptest.NewRequest("POST", "http://github.com/goodtune/ghp.git/git-receive-pack", nil)
	req.Header.Set("Authorization", basicAuth("x-access-token", ghpToken))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only Basic auth token attempting push, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "contents:write") {
		t.Errorf("expected error to mention required contents:write permission, got: %s", body)
	}
}

func TestScopedPassthrough_BasicAuth_GitPush_WrongRepository(t *testing.T) {
	// A token sent via Basic auth scoped to goodtune/ghp must be
	// rejected when used against a different repository.
	handler, ghpToken := newScopedPassthrough(t, "goodtune/ghp", map[string]string{
		"contents": "write",
	})

	req := httptest.NewRequest("POST", "http://github.com/goodtune/pac-proxy.git/git-receive-pack", nil)
	req.Header.Set("Authorization", basicAuth("x-access-token", ghpToken))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong repository via Basic auth, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "goodtune/pac-proxy") {
		t.Errorf("expected error to mention requested repository, got: %s", body)
	}
}

func TestScopedPassthrough_OpenScoped_AllowsAnyRepo(t *testing.T) {
	// An open-scoped token should allow git operations to any repository.
	handler, ghpToken := newOpenScopedPassthrough(t)

	req := httptest.NewRequest("POST", "http://github.com/goodtune/any-repo.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for open-scoped token, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestScopedPassthrough_OpenScoped_AllowsGitPush(t *testing.T) {
	// An open-scoped token should allow git push (contents:write) without restriction.
	handler, ghpToken := newOpenScopedPassthrough(t)

	req := httptest.NewRequest("POST", "http://github.com/goodtune/ghp.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for open-scoped token git push, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// newOpenScopedPassthrough creates a ScopedPassthroughHandler backed by an
// open-scoped ghp_ token (no repository or permission restrictions).
func newOpenScopedPassthrough(t *testing.T) (http.Handler, string) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()

	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	user := &database.User{GitHubID: 99, GitHubUsername: "openuser", Role: "user"}
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
		// No Repository, no Scopes — open-scoped.
		Duration:  24 * time.Hour,
		SessionID: "open-test-session",
	})
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	resolver := NewProxyTokenResolver(tokenSvc, store, enc, nil)
	inner := NewPassthroughHandler(upstream.URL, nil, "", nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, tokenSvc, resolver, nil, slog.Default())

	return handler, result.Token
}

// tlsTransport returns an http.RoundTripper that trusts the test server's cert.
func tlsTransport(ts *httptest.Server) http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}
