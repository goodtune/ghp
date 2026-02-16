package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// captureTransport records the last request sent through it and responds with 200.
type captureTransport struct {
	lastReq *http.Request
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.lastReq = req
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	return rec.Result(), nil
}

func TestForwardRequest_EnterpriseHeader(t *testing.T) {
	ct := &captureTransport{}
	h := &Handler{
		cfg: &config.Config{
			GitHub: config.GitHubConfig{
				EnterpriseSlug: "my-enterprise",
			},
		},
		logger: slog.Default(),
		client: &http.Client{Transport: ct, Timeout: 5 * time.Second},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost/repos/org/repo", nil)

	status := h.forwardRequest(rr, req, "/repos/org/repo", "test-github-token")

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if ct.lastReq == nil {
		t.Fatal("no request captured")
	}
	got := ct.lastReq.Header.Get("sec-GitHub-allowed-enterprise")
	if got != "my-enterprise" {
		t.Errorf("expected enterprise header 'my-enterprise', got %q", got)
	}
}

func TestServeHTTP_NonGhpTokenPassthrough(t *testing.T) {
	// A non-ghp_ token (e.g. gho_xxx) should be forwarded to GitHub as-is,
	// not rejected with 401.
	ct := &captureTransport{}
	h := &Handler{
		cfg: &config.Config{
			GitHub: config.GitHubConfig{
				EnterpriseSlug: "acme",
			},
		},
		logger: slog.Default(),
		client: &http.Client{Transport: ct, Timeout: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://api.github.com/repos/org/repo/pulls", nil)
	req.Header.Set("Authorization", "Bearer gho_realtoken123")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("non-ghp token should not be rejected, got 401")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct.lastReq == nil {
		t.Fatal("no request forwarded to upstream")
	}
	// Original token should be preserved.
	gotAuth := ct.lastReq.Header.Get("Authorization")
	if gotAuth != "Bearer gho_realtoken123" {
		t.Errorf("expected original token preserved, got %q", gotAuth)
	}
	// Enterprise header should still be injected.
	gotEnt := ct.lastReq.Header.Get("sec-GitHub-allowed-enterprise")
	if gotEnt != "acme" {
		t.Errorf("expected enterprise header 'acme', got %q", gotEnt)
	}
}

func TestServeHTTP_NoAuthHeader(t *testing.T) {
	// A request with no Authorization header should also be forwarded
	// (GitHub will return its own 401 if needed).
	ct := &captureTransport{}
	h := &Handler{
		cfg:    &config.Config{},
		logger: slog.Default(),
		client: &http.Client{Transport: ct, Timeout: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://api.github.com/user", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("missing auth should be forwarded, not rejected locally")
	}
	if ct.lastReq == nil {
		t.Fatal("no request forwarded to upstream")
	}
}

func TestForwardRequest_NoEnterpriseHeader(t *testing.T) {
	ct := &captureTransport{}
	h := &Handler{
		cfg: &config.Config{
			GitHub: config.GitHubConfig{},
		},
		logger: slog.Default(),
		client: &http.Client{Transport: ct, Timeout: 5 * time.Second},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost/repos/org/repo", nil)

	h.forwardRequest(rr, req, "/repos/org/repo", "test-github-token")

	if ct.lastReq == nil {
		t.Fatal("no request captured")
	}
	got := ct.lastReq.Header.Get("sec-GitHub-allowed-enterprise")
	if got != "" {
		t.Errorf("expected no enterprise header, got %q", got)
	}
}

// newScopedHandler creates a Handler with a real token.Service backed by SQLite,
// issues a ghp_ token scoped to the given repository and scopes, and returns
// the handler plus the plaintext token.
func newScopedHandler(t *testing.T, repo string, scopes map[string]string) (*Handler, string) {
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

	ct := &captureTransport{}
	h := &Handler{
		cfg:          &config.Config{},
		tokenService: tokenSvc,
		store:        store,
		encryptor:    enc,
		logger:       slog.Default(),
		client:       &http.Client{Transport: ct, Timeout: 5 * time.Second},
	}
	return h, result.Token
}

func TestServeHTTP_GhpToken_WrongRepository(t *testing.T) {
	// A ghp_ token scoped to goodtune/ghp must be rejected when used
	// against a different repository (goodtune/pac-proxy).
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents": "read",
		"issues":   "read",
		"pulls":    "read",
	})

	req := httptest.NewRequest("POST", "http://api.github.com/repos/goodtune/pac-proxy/pulls/1/comments", strings.NewReader(`{"body":"hello"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong repository, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "scoped to goodtune/ghp") {
		t.Errorf("expected error to mention scoped repository, got: %s", body)
	}
	if !strings.Contains(body, "goodtune/pac-proxy") {
		t.Errorf("expected error to mention requested repository, got: %s", body)
	}
}

func TestServeHTTP_GhpToken_ReadOnlyDeniesWrite(t *testing.T) {
	// A ghp_ token scoped to goodtune/ghp with read-only pulls permission
	// must be rejected when attempting to write (POST a PR comment).
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents": "read",
		"issues":   "read",
		"pulls":    "read",
	})

	req := httptest.NewRequest("POST", "http://api.github.com/repos/goodtune/ghp/pulls/1/comments", strings.NewReader(`{"body":"hello"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only token attempting write, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "pulls:write") {
		t.Errorf("expected error to mention required pulls:write permission, got: %s", body)
	}
}

func TestServeHTTP_BasicAuth_GhpToken(t *testing.T) {
	// Git credential helpers and some API clients send credentials via HTTP
	// Basic auth: base64("x-access-token:<token>"). The API proxy must
	// recognise a ghp_ token in this format and enforce scopes just as it
	// would for a Bearer token.
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents": "read",
		"pulls":    "read",
	})

	req := httptest.NewRequest("GET", "http://api.github.com/repos/goodtune/ghp/pulls", nil)
	req.Header.Set("Authorization", basicAuth("x-access-token", ghpToken))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for Basic auth ghp_ token with sufficient scopes, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_BasicAuth_GhpToken_ScopeEnforcement(t *testing.T) {
	// A ghp_ token sent via Basic auth must still have scopes enforced.
	// A read-only pulls token should be rejected for write operations.
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents": "read",
		"pulls":    "read",
	})

	req := httptest.NewRequest("POST", "http://api.github.com/repos/goodtune/ghp/pulls/1/comments", strings.NewReader(`{"body":"hello"}`))
	req.Header.Set("Authorization", basicAuth("x-access-token", ghpToken))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only Basic auth token attempting write, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "pulls:write") {
		t.Errorf("expected error to mention required pulls:write permission, got: %s", body)
	}
}
