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

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/token"
	"github.com/prometheus/client_golang/prometheus"
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

	handler := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))

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
			handler := NewPassthroughHandler(upstream.URL, resolver, nil, nil, nil, tlsTransport(upstream))

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

	policy := NewEnterprisePolicy(config.GitHubConfig{EnterpriseSlug: "my-enterprise"}, nil, nil)
	handler := NewPassthroughHandler(upstream.URL, nil, policy, nil, nil, tlsTransport(upstream))

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

	tokenSvc := token.NewService(store, 7*24*time.Hour, false)
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
	inner := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))
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

	tokenSvc := token.NewService(store, 7*24*time.Hour, false)
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
	inner := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, tokenSvc, resolver, nil, slog.Default())

	return handler, result.Token
}

// newRepoOnlyPassthrough creates a ScopedPassthroughHandler backed by a
// repo-restricted ghp_ token with no permission scopes.
func newRepoOnlyPassthrough(t *testing.T, repo string) (http.Handler, string) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()

	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	user := &database.User{GitHubID: 42, GitHubUsername: "repouser", Role: "user"}
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

	tokenSvc := token.NewService(store, 7*24*time.Hour, false)
	result, err := tokenSvc.Create(ctx, token.CreateRequest{
		UserID:        user.ID,
		GitHubTokenID: gt.ID,
		Repository:    repo,
		// No Scopes — repo-filtered but any git operation allowed.
		Duration:  24 * time.Hour,
		SessionID: "repo-only-session",
	})
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	resolver := NewProxyTokenResolver(tokenSvc, store, enc, nil)
	inner := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, tokenSvc, resolver, nil, slog.Default())

	return handler, result.Token
}

// newScopeOnlyPassthrough creates a ScopedPassthroughHandler backed by a
// permission-scoped ghp_ token with no repository restriction.
func newScopeOnlyPassthrough(t *testing.T, scopes map[string]string) (http.Handler, string) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()

	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	user := &database.User{GitHubID: 43, GitHubUsername: "scopeuser", Role: "user"}
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

	tokenSvc := token.NewService(store, 7*24*time.Hour, false)
	result, err := tokenSvc.Create(ctx, token.CreateRequest{
		UserID:        user.ID,
		GitHubTokenID: gt.ID,
		// No Repository — permission-scoped only, applies to any repo.
		Scopes:    scopes,
		Duration:  24 * time.Hour,
		SessionID: "scope-only-session",
	})
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	resolver := NewProxyTokenResolver(tokenSvc, store, enc, nil)
	inner := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, tokenSvc, resolver, nil, slog.Default())

	return handler, result.Token
}

func TestScopedPassthrough_RepoOnly_AllowsPushOnCorrectRepo(t *testing.T) {
	// A repo-only token (repos set, no scopes) must allow git push on the
	// allowed repository — no permission enforcement applies.
	handler, ghpToken := newRepoOnlyPassthrough(t, "goodtune/ghp")

	req := httptest.NewRequest("POST", "http://github.com/goodtune/ghp.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for repo-only token git push on correct repo, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestScopedPassthrough_RepoOnly_DeniesWrongRepo(t *testing.T) {
	// A repo-only token (repos set, no scopes) must deny git operations
	// against repositories not in its allowlist.
	handler, ghpToken := newRepoOnlyPassthrough(t, "goodtune/ghp")

	req := httptest.NewRequest("POST", "http://github.com/goodtune/other-repo.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for repo-only token on wrong repo, got %d", rr.Code)
	}
}

func TestScopedPassthrough_ScopeOnly_AllowsPushOnAnyRepo(t *testing.T) {
	// A scope-only token (no repos, scopes set) must allow git push on any
	// repository when the permission is satisfied — no repo restriction applies.
	handler, ghpToken := newScopeOnlyPassthrough(t, map[string]string{
		"contents": "write",
	})

	req := httptest.NewRequest("POST", "http://github.com/any-org/any-repo.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for scope-only token git push on any repo, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestScopedPassthrough_ScopeOnly_DeniesInsufficientPermission(t *testing.T) {
	// A scope-only token (no repos, scopes set) must deny git push when the
	// token only grants contents:read.
	handler, ghpToken := newScopeOnlyPassthrough(t, map[string]string{
		"contents": "read",
	})

	req := httptest.NewRequest("POST", "http://github.com/any-org/any-repo.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for scope-only token with insufficient permission, got %d", rr.Code)
	}
}

func TestScopedPassthrough_BorderPolicy_BlocksRawToken(t *testing.T) {
	// A raw ghs_ token should be rejected by ScopedPassthroughHandler when
	// the block.ghs border policy is active.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not reach upstream when token is blocked")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{Block: config.BlockConfig{GHS: true}}
	inner := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, nil, nil, nil, slog.Default(), cfg)

	req := httptest.NewRequest("GET", "http://github.com/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer ghs_servertoken")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked ghs_ token on git path, got %d", rr.Code)
	}
}

func TestScopedPassthrough_BorderPolicy_AllowsUnblockedRawToken(t *testing.T) {
	// A raw gho_ token should pass through when ghs_ is blocked but gho_ is not.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{Block: config.BlockConfig{GHS: true}}
	inner := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, nil, nil, nil, slog.Default(), cfg)

	req := httptest.NewRequest("GET", "http://github.com/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer gho_oauthtoken")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-blocked gho_ token, got %d", rr.Code)
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

// newAnonymousGitPassthrough creates an upstream TLS test server and a
// ScopedPassthroughHandler configured with the supplied config.
func newAnonymousGitPassthrough(t *testing.T, cfg *config.Config) (http.Handler, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	inner := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, nil, nil, nil, slog.Default(), cfg)
	return handler, upstream
}

func TestScopedPassthrough_AnonymousGit_Blocked(t *testing.T) {
	// An anonymous request with a Git-Protocol header must be short-circuited
	// with 401 and a WWW-Authenticate header when block.anonymous_git is true.
	cfg := &config.Config{Block: config.BlockConfig{AnonymousGit: true}}
	handler, _ := newAnonymousGitPassthrough(t, cfg)

	req := httptest.NewRequest("GET", "http://github.com/goodtune/ghp.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Git-Protocol", "version=2")
	// No Authorization header — anonymous request.
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for anonymous git when blocking is enabled, got %d", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if wwwAuth != `Basic realm="GitHub"` {
		t.Errorf("expected WWW-Authenticate: Basic realm=\"GitHub\", got %q", wwwAuth)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Anonymous git access is not permitted") {
		t.Errorf("expected error message in body, got: %s", body)
	}
}

func TestScopedPassthrough_AnonymousGit_Disabled(t *testing.T) {
	// When block.anonymous_git is false (default), anonymous git requests
	// must pass through to the upstream.
	cfg := &config.Config{Block: config.BlockConfig{AnonymousGit: false}}
	handler, _ := newAnonymousGitPassthrough(t, cfg)

	req := httptest.NewRequest("GET", "http://github.com/goodtune/ghp.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Git-Protocol", "version=2")
	// No Authorization header — anonymous request.
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for anonymous git when blocking is disabled, got %d", rr.Code)
	}
}

func TestScopedPassthrough_AnonymousGit_NoGitProtocolHeader_NotBlocked(t *testing.T) {
	// An anonymous request without a Git-Protocol header is not a git
	// smart HTTP request and must NOT be short-circuited even when blocking is on.
	cfg := &config.Config{Block: config.BlockConfig{AnonymousGit: true}}
	handler, _ := newAnonymousGitPassthrough(t, cfg)

	req := httptest.NewRequest("GET", "http://github.com/goodtune/ghp", nil)
	// No Authorization header, no Git-Protocol header.
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected non-git anonymous request to pass through, got %d", rr.Code)
	}
}

func TestScopedPassthrough_AnonymousGit_AuthenticatedGit_NotBlocked(t *testing.T) {
	// A request with a Git-Protocol header AND an Authorization header must
	// not be blocked — only truly anonymous requests are short-circuited.
	cfg := &config.Config{Block: config.BlockConfig{AnonymousGit: true}}
	handler, _ := newAnonymousGitPassthrough(t, cfg)

	req := httptest.NewRequest("GET", "http://github.com/goodtune/ghp.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:ghp_sometoken")))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Token is not a client token but is authenticated — should pass through (or get a
	// token-blocked response if GHP is blocked), not an anonymous-git 401.
	if rr.Code == http.StatusUnauthorized {
		body := rr.Body.String()
		if strings.Contains(body, "Anonymous git access is not permitted") {
			t.Fatalf("authenticated request should not be rejected as anonymous git, got %d: %s", rr.Code, body)
		}
	}
}

func TestScopedPassthrough_NativeToken_RecordsMetrics(t *testing.T) {
	// A native GitHub token (gho_) forwarded through ScopedPassthroughHandler
	// must emit ProxyRequestTotal with backend=github.com, token_type=gho,
	// type=git, user=unknown.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	inner := NewPassthroughHandler(upstream.URL, nil, nil, nil, nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, nil, nil, nil, slog.Default())

	labels := prometheus.Labels{
		"backend":    "github.com",
		"method":     "GET",
		"status":     "200",
		"token_type": "gho",
		"type":       "git",
		"user":       "unknown",
		"app":        "",
	}

	before := getCounterValue(t, metrics.ProxyRequestTotal, labels)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("Authorization", "Bearer gho_nativetoken")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	after := getCounterValue(t, metrics.ProxyRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected ProxyRequestTotal to increment by 1, got %f", after-before)
	}
}
