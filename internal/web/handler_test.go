package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// testHarness bundles the dependencies shared across smoke tests.
type testHarness struct {
	store   database.Store
	authH   *auth.Handler
	handler *Handler
	router  chi.Router
	enc     *crypto.Encryptor
}

// newTestHarness sets up an in-memory SQLite store with migrations applied,
// creates the auth handler and web handler, and wires up a chi router.
func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	ctx := context.Background()

	// Open in-memory SQLite.
	store, err := database.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Run migrations.
	migrator := database.NewMigrator(store, "sqlite")
	if err := migrator.Migrate(ctx); err != nil {
		t.Fatalf("running migrations: %v", err)
	}

	// Encryptor.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Defaults()
	cfg.DevMode = true

	authH := auth.NewHandler(cfg, store, enc, logger)
	ts := token.NewService(store, 7*24*time.Hour)
	handler := NewHandler(authH, store, enc, ts, false, logger)

	r := chi.NewRouter()
	handler.RegisterRoutes(r)

	return &testHarness{
		store:   store,
		authH:   authH,
		handler: handler,
		router:  r,
		enc:     enc,
	}
}

// seedUser creates a user in the database and returns its ID.
func (h *testHarness) seedUser(t *testing.T, username, role string, ghID int64) string {
	t.Helper()
	ctx := context.Background()
	user := &database.User{
		GitHubID:       ghID,
		GitHubUsername: username,
		GitHubEmail:    username + "@test.local",
		Role:           role,
	}
	if err := h.store.UpsertUser(ctx, user); err != nil {
		t.Fatalf("seeding user: %v", err)
	}
	return user.ID
}

// seedToken creates a proxy token for the given user and returns its ID.
func (h *testHarness) seedToken(t *testing.T, userID, repo string, scopes map[string]string) string {
	t.Helper()
	ctx := context.Background()

	scopesJSON, _ := json.Marshal(scopes)
	reposJSON, _ := json.Marshal([]string{repo})

	tok := &database.ProxyToken{
		TokenHash:    "testhash-" + userID + "-" + repo,
		TokenPrefix:  "ghx_test",
		TokenType:    "proxy",
		UserID:       &userID,
		Repositories: json.RawMessage(reposJSON),
		Scopes:       json.RawMessage(scopesJSON),
		SessionID:    "test-session",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	if err := h.store.CreateProxyToken(ctx, tok); err != nil {
		t.Fatalf("seeding token: %v", err)
	}
	return tok.ID
}

// createSession creates a session via the auth handler and returns a cookie.
func (h *testHarness) createSession(t *testing.T, userID, username, role string) *http.Cookie {
	t.Helper()
	sessionToken := h.authH.CreateTestSession(userID, username, role)
	return &http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sessionToken,
	}
}

// doRequest performs a request against the test router and returns the response.
// It does NOT follow redirects so we can assert on 3xx status codes.
func (h *testHarness) doRequest(t *testing.T, method, path string, cookies ...*http.Cookie) *http.Response {
	t.Helper()

	srv := httptest.NewServer(h.router)
	t.Cleanup(srv.Close)

	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// bodyString reads and returns the response body as a string.
func bodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- Smoke Tests ---

func TestSmoke_UnauthenticatedRedirect(t *testing.T) {
	h := newTestHarness(t)
	resp := h.doRequest(t, "GET", "/dashboard/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/login/" {
		t.Fatalf("expected redirect to /login/, got %q", loc)
	}
}

func TestSmoke_LoginPageRenders(t *testing.T) {
	h := newTestHarness(t)
	resp := h.doRequest(t, "GET", "/login/")
	body := bodyString(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "GitHub Proxy") {
		t.Fatal("login page should contain 'GitHub Proxy'")
	}
	if !strings.Contains(body, "Sign in with GitHub") {
		t.Fatal("login page should contain 'Sign in with GitHub'")
	}
}

func TestSmoke_DashboardRendersWithTokens(t *testing.T) {
	h := newTestHarness(t)

	userID := h.seedUser(t, "alice", "user", 1001)
	h.seedToken(t, userID, "org/repo", map[string]string{"contents": "read"})

	cookie := h.createSession(t, userID, "alice", "user")
	resp := h.doRequest(t, "GET", "/dashboard/", cookie)
	body := bodyString(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "ghx_test") {
		t.Fatal("dashboard should contain the token prefix 'ghx_test'")
	}
	if !strings.Contains(body, "org/repo") {
		t.Fatal("dashboard should contain the repository name")
	}
	if !strings.Contains(body, "contents:read") {
		t.Fatal("dashboard should contain the scope 'contents:read'")
	}
	// The token card template is used.
	if !strings.Contains(body, "token-card") {
		t.Fatal("dashboard should render token cards")
	}
}

func TestSmoke_DashboardEmptyState(t *testing.T) {
	h := newTestHarness(t)

	userID := h.seedUser(t, "bob", "user", 1002)
	cookie := h.createSession(t, userID, "bob", "user")
	resp := h.doRequest(t, "GET", "/dashboard/", cookie)
	body := bodyString(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "No tokens yet") {
		t.Fatal("dashboard with no tokens should show empty state text")
	}
	if !strings.Contains(body, "empty-state") {
		t.Fatal("dashboard should render the empty-state div")
	}
}

func TestSmoke_AdminUsersTable(t *testing.T) {
	h := newTestHarness(t)

	adminID := h.seedUser(t, "adminuser", "admin", 2001)
	h.seedUser(t, "regularuser", "user", 2002)

	cookie := h.createSession(t, adminID, "adminuser", "admin")
	resp := h.doRequest(t, "GET", "/admin/", cookie)
	body := bodyString(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "adminuser") {
		t.Fatal("admin users table should contain 'adminuser'")
	}
	if !strings.Contains(body, "regularuser") {
		t.Fatal("admin users table should contain 'regularuser'")
	}
	if !strings.Contains(body, "<table") {
		t.Fatal("admin page should contain a table element")
	}
	if !strings.Contains(body, "USERNAME") {
		t.Fatal("admin page should have USERNAME column header")
	}
}

func TestSmoke_AdminTokensTable(t *testing.T) {
	h := newTestHarness(t)

	adminID := h.seedUser(t, "tokenadmin", "admin", 3001)
	userID := h.seedUser(t, "tokenuser", "user", 3002)
	h.seedToken(t, userID, "myorg/myrepo", map[string]string{"contents": "write"})

	cookie := h.createSession(t, adminID, "tokenadmin", "admin")
	resp := h.doRequest(t, "GET", "/admin/tokens/", cookie)
	body := bodyString(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "All Tokens") {
		t.Fatal("admin tokens page should contain 'All Tokens'")
	}
	if !strings.Contains(body, "ghx_test") {
		t.Fatal("admin tokens table should contain the token prefix")
	}
	if !strings.Contains(body, "tokenuser") {
		t.Fatal("admin tokens table should display the username")
	}
	if !strings.Contains(body, "myorg/myrepo") {
		t.Fatal("admin tokens table should display the repository")
	}
}

func TestSmoke_AdminForbiddenForNonAdmin(t *testing.T) {
	h := newTestHarness(t)

	userID := h.seedUser(t, "nonadmin", "user", 4001)
	cookie := h.createSession(t, userID, "nonadmin", "user")
	resp := h.doRequest(t, "GET", "/admin/", cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", resp.StatusCode)
	}
}
