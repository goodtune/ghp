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
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/token"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

// captureTransport records the last request sent through it and responds with 200.
type captureTransport struct {
	lastReq         *http.Request
	responseHeaders http.Header // optional headers to include in the response
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.lastReq = req
	rec := httptest.NewRecorder()
	for k, vals := range t.responseHeaders {
		for _, v := range vals {
			rec.Header().Add(k, v)
		}
	}
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
	// A token scoped to goodtune/ghp must be rejected when used
	// against a different repository (goodtune/pac-proxy).
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents": "read",
		"issues":   "read",
		"pull_requests": "read",
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
	if !strings.Contains(body, "goodtune/pac-proxy") {
		t.Errorf("expected error to mention requested repository, got: %s", body)
	}
}

func TestServeHTTP_GhpToken_ReadOnlyDeniesWrite(t *testing.T) {
	// A ghp_ token scoped to goodtune/ghp with read-only pull_requests permission
	// must be rejected when attempting to write (POST a PR comment).
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents":      "read",
		"issues":        "read",
		"pull_requests": "read",
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
	if !strings.Contains(body, "pull_requests:write") {
		t.Errorf("expected error to mention required pull_requests:write permission, got: %s", body)
	}
}

func TestServeHTTP_BasicAuth_GhpToken(t *testing.T) {
	// Git credential helpers and some API clients send credentials via HTTP
	// Basic auth: base64("x-access-token:<token>"). The API proxy must
	// recognise a ghp_ token in this format and enforce scopes just as it
	// would for a Bearer token.
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents":      "read",
		"pull_requests": "read",
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
	// A read-only pull_requests token should be rejected for write operations.
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents":      "read",
		"pull_requests": "read",
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
	if !strings.Contains(body, "pull_requests:write") {
		t.Errorf("expected error to mention required pull_requests:write permission, got: %s", body)
	}
}

func TestServeHTTP_NonGhpToken_GraphQLPathNormalization(t *testing.T) {
	// GHE-style GraphQL requests (/api/graphql) with non-ghp_ tokens should be
	// normalized to /graphql before forwarding to api.github.com, preventing
	// requests to the non-existent https://api.github.com/api/graphql endpoint.
	ct := &captureTransport{}
	h := &Handler{
		cfg:    &config.Config{},
		logger: slog.Default(),
		client: &http.Client{Transport: ct, Timeout: 5 * time.Second},
	}

	req := httptest.NewRequest("POST", "http://api.github.com/api/graphql", strings.NewReader(`{"query":"{ viewer { login } }"}`))
	req.Header.Set("Authorization", "Bearer gho_realtoken123")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct.lastReq == nil {
		t.Fatal("no request forwarded to upstream")
	}
	// Verify the request was sent to /graphql, not /api/graphql.
	if ct.lastReq.URL.Path != "/graphql" {
		t.Errorf("expected path /graphql, got %s", ct.lastReq.URL.Path)
	}
}

// rateLimitTransport responds with a 200 and the given rate limit headers.
type rateLimitTransport struct {
	remaining string
	limit     string
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-RateLimit-Remaining", t.remaining)
	rec.Header().Set("X-RateLimit-Limit", t.limit)
	rec.WriteHeader(http.StatusOK)
	return rec.Result(), nil
}

func TestForwardRequest_RateLimitMetrics(t *testing.T) {
	rt := &rateLimitTransport{remaining: "42", limit: "5000"}
	h := &Handler{
		cfg:    &config.Config{},
		logger: slog.Default(),
		client: &http.Client{Transport: rt, Timeout: 5 * time.Second},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost/repos/org/repo", nil)
	// Prepare a username slot and set the user so rate-limit metrics are labelled.
	req, _ = PrepareUsernameSlot(req)
	SetUsername(req, "ratelimit-testuser")

	h.forwardRequest(rr, req, "/repos/org/repo", "test-token")

	// Verify GitHubRateLimitRemaining was set from the response header.
	var m io_prometheus_client.Metric
	remaining, err := metrics.GitHubRateLimitRemaining.GetMetricWithLabelValues("ratelimit-testuser")
	if err != nil {
		t.Fatalf("GitHubRateLimitRemaining.GetMetricWithLabelValues: %v", err)
	}
	if err := remaining.Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := m.GetGauge().GetValue(); got != 42 {
		t.Errorf("expected GitHubRateLimitRemaining=42, got %v", got)
	}

	// Verify GitHubRateLimitLimit was set from the response header.
	limitMetric, err := metrics.GitHubRateLimitLimit.GetMetricWithLabelValues("ratelimit-testuser")
	if err != nil {
		t.Fatalf("GitHubRateLimitLimit.GetMetricWithLabelValues: %v", err)
	}
	if err := limitMetric.Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := m.GetGauge().GetValue(); got != 5000 {
		t.Errorf("expected GitHubRateLimitLimit=5000, got %v", got)
	}
}

// newOpenScopedHandler creates a Handler with an open-scoped ghp_ token (no
// repository or permission restrictions).
func newOpenScopedHandler(t *testing.T) (*Handler, string) {
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

func TestServeHTTP_OpenScopedToken_AllowsAnyRepo(t *testing.T) {
	// An open-scoped token (no repos, no scopes) should forward any
	// repository request to GitHub without blocking.
	h, ghpToken := newOpenScopedHandler(t)

	req := httptest.NewRequest("POST", "http://api.github.com/repos/org/any-repo/pulls/1/comments", strings.NewReader(`{"body":"hello"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for open-scoped token, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_OpenScopedToken_AllowsWriteOperations(t *testing.T) {
	// An open-scoped token should allow write operations without scope checks.
	h, ghpToken := newOpenScopedHandler(t)

	req := httptest.NewRequest("POST", "http://api.github.com/repos/goodtune/ghp/issues", strings.NewReader(`{"title":"test"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for open-scoped token write, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// newRepoOnlyHandler creates a Handler with a repo-restricted ghp_ token but
// no permission scopes. The token filters by repository but allows any endpoint.
func newRepoOnlyHandler(t *testing.T, repo string) (*Handler, string) {
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

	tokenSvc := token.NewService(store, 7*24*time.Hour)
	result, err := tokenSvc.Create(ctx, token.CreateRequest{
		UserID:        user.ID,
		GitHubTokenID: gt.ID,
		Repository:    repo,
		// No Scopes — repo-filtered but any endpoint allowed.
		Duration:  24 * time.Hour,
		SessionID: "repo-only-session",
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

// newScopeOnlyHandler creates a Handler with a permission-scoped ghp_ token
// but no repository restriction. The token filters by permission but applies
// to any repository.
func newScopeOnlyHandler(t *testing.T, scopes map[string]string) (*Handler, string) {
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

	tokenSvc := token.NewService(store, 7*24*time.Hour)
	result, err := tokenSvc.Create(ctx, token.CreateRequest{
		UserID:        user.ID,
		GitHubTokenID: gt.ID,
		// No Repository — scoped by permission only, applies to any repo.
		Scopes:    scopes,
		Duration:  24 * time.Hour,
		SessionID: "scope-only-session",
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

func TestServeHTTP_RepoOnly_AllowsCorrectRepoWriteOp(t *testing.T) {
	// A repo-only token (repos set, no scopes) must allow write operations
	// on the allowed repository — no permission enforcement applies.
	h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")

	req := httptest.NewRequest("POST", "http://api.github.com/repos/goodtune/ghp/pulls/1/comments", strings.NewReader(`{"body":"hello"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for repo-only token on correct repo write, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_RepoOnly_DeniesWrongRepo(t *testing.T) {
	// A repo-only token (repos set, no scopes) must deny requests to
	// repositories not in its allowlist.
	h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")

	req := httptest.NewRequest("GET", "http://api.github.com/repos/goodtune/other-repo/pulls", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for repo-only token on wrong repo, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "goodtune/other-repo") {
		t.Errorf("expected error to mention the denied repository, got: %s", body)
	}
}

func TestServeHTTP_ScopeOnly_AllowsAnyRepo(t *testing.T) {
	// A scope-only token (no repos, scopes set) must allow requests to any
	// repository as long as the endpoint permission is satisfied.
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"pull_requests": "read",
	})

	// Request to an arbitrary repo — repo restriction is absent.
	req := httptest.NewRequest("GET", "http://api.github.com/repos/some-org/some-repo/pulls", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for scope-only token on any repo, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_ScopeOnly_DeniesInsufficientPermission(t *testing.T) {
	// A scope-only token (no repos, scopes set) must deny requests that
	// require a permission not granted — regardless of repository.
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"pull_requests": "read",
	})

	// Attempt a write operation that requires pull_requests:write.
	req := httptest.NewRequest("POST", "http://api.github.com/repos/some-org/some-repo/pulls/1/comments", strings.NewReader(`{"body":"hello"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for scope-only token with insufficient permission, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "pull_requests:write") {
		t.Errorf("expected error to mention required pull_requests:write permission, got: %s", body)
	}
}

func TestServeHTTP_OpenScopedToken_GraphQLAllowed(t *testing.T) {
	// An open-scoped token (no repos, no scopes) must be allowed to use GraphQL.
	h, ghpToken := newOpenScopedHandler(t)

	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(`{"query":"{ viewer { login } }"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for open-scoped token on GraphQL, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_RepoOnly_GraphQLDenied(t *testing.T) {
	// A repo-restricted token must be denied on GraphQL because repo restrictions
	// cannot be enforced on arbitrary GraphQL queries without query parsing.
	h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")

	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(`{"query":"{ viewer { login } }"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for repo-restricted token on GraphQL, got %d; body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "repository-restricted") {
		t.Errorf("expected error to mention repository restriction, got: %s", body)
	}
}

func TestServeHTTP_ScopeOnly_GraphQLAllowed(t *testing.T) {
	// A scope-only token (scopes set, no repo restrictions) must be allowed to
	// use GraphQL. Per-operation permission enforcement on GraphQL is not
	// implemented; the underlying GitHub token enforces actual access.
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"contents": "read",
	})

	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(`{"query":"{ viewer { login } }"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for scope-only token on GraphQL, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_RepoAndScopeToken_GraphQLDenied(t *testing.T) {
	// A fully-scoped token (repos AND scopes set) must also be denied on GraphQL
	// because repo restrictions cannot be enforced without query parsing.
	h, ghpToken := newScopedHandler(t, "goodtune/ghp", map[string]string{
		"contents": "read",
	})

	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(`{"query":"{ viewer { login } }"}`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for fully-scoped token on GraphQL, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// newScopedHandlerWithTransport is like newScopedHandler but also returns the
// captureTransport so tests can configure response headers.
func newScopedHandlerWithTransport(t *testing.T, repo string, scopes map[string]string) (*Handler, string, *captureTransport) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()

	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	user := &database.User{GitHubID: 77, GitHubUsername: "scopeduser", Role: "user"}
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
	return h, result.Token, ct
}

func TestServeHTTP_ScopedToken_RootEndpoint_SynthesizesOAuthScopes(t *testing.T) {
	// When a scoped ghp_ token is used to call GET /, the proxy should return
	// X-OAuth-Scopes synthesized from the token's permissions rather than the
	// underlying credential's OAuth scopes.
	h, ghpToken, upstream := newScopedHandlerWithTransport(t, "goodtune/ghp", map[string]string{
		"contents":      "read",
		"pull_requests": "write",
	})
	// Simulate GitHub returning the real token's broader OAuth scopes.
	upstream.responseHeaders = http.Header{
		"X-Oauth-Scopes": []string{"repo, user"},
	}

	req := httptest.NewRequest("GET", "http://api.github.com/", nil)
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	got := rr.Header().Get("X-OAuth-Scopes")
	if got == "" {
		t.Fatal("expected X-OAuth-Scopes header to be set")
	}
	// The synthesized scopes must reflect the token's restrictions, not the
	// underlying credential's broader scopes.
	if strings.Contains(got, "repo") || strings.Contains(got, "user") {
		t.Errorf("synthesized X-OAuth-Scopes should not contain underlying OAuth scopes, got %q", got)
	}
	if !strings.Contains(got, "contents:read") {
		t.Errorf("synthesized X-OAuth-Scopes should contain contents:read, got %q", got)
	}
	if !strings.Contains(got, "pull_requests:write") {
		t.Errorf("synthesized X-OAuth-Scopes should contain pull_requests:write, got %q", got)
	}
}

func TestServeHTTP_OpenScopedToken_RootEndpoint_PassesThroughOAuthScopes(t *testing.T) {
	// When an open-scoped ghp_ token calls GET /, the proxy should forward
	// the real X-OAuth-Scopes header from GitHub unchanged.
	store := newTestStore(t)
	ctx := context.Background()

	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	user := &database.User{GitHubID: 88, GitHubUsername: "openuser2", Role: "user"}
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
		// No repo, no scopes — open-scoped.
		Duration:  24 * time.Hour,
		SessionID: "open-session",
	})
	if err != nil {
		t.Fatal(err)
	}

	ct := &captureTransport{
		responseHeaders: http.Header{
			"X-Oauth-Scopes": []string{"repo, user:email"},
		},
	}
	h := &Handler{
		cfg:          &config.Config{},
		tokenService: tokenSvc,
		store:        store,
		encryptor:    enc,
		logger:       slog.Default(),
		client:       &http.Client{Transport: ct, Timeout: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://api.github.com/", nil)
	req.Header.Set("Authorization", "Bearer "+result.Token)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	got := rr.Header().Get("X-OAuth-Scopes")
	if got != "repo, user:email" {
		t.Errorf("open-scoped token should pass through real X-OAuth-Scopes, got %q", got)
	}
}

func TestSyntheticOAuthScopes(t *testing.T) {
	tests := []struct {
		name   string
		scopes database.Scopes
		want   string
	}{
		{
			name:   "nil scopes",
			scopes: nil,
			want:   "",
		},
		{
			name:   "empty scopes",
			scopes: database.Scopes{},
			want:   "",
		},
		{
			name:   "single scope",
			scopes: database.Scopes{"contents": "read"},
			want:   "contents:read",
		},
		{
			name:   "multiple scopes sorted",
			scopes: database.Scopes{"pull_requests": "write", "contents": "read", "issues": "write"},
			want:   "contents:read, issues:write, pull_requests:write",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := syntheticOAuthScopes(tc.scopes)
			if got != tc.want {
				t.Errorf("syntheticOAuthScopes(%v) = %q, want %q", tc.scopes, got, tc.want)
			}
		})
	}
}
