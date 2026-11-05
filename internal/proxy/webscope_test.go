package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/token"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func TestGitHubWebScope(t *testing.T) {
	tests := []struct {
		name, method, path, query string
		wantRepo, wantPerm        string
		wantLevel                 string
	}{
		{"upload-pack refs", "GET", "/o/r.git/info/refs", "service=git-upload-pack", "o/r", "contents", "read"},
		{"receive-pack", "POST", "/o/r.git/git-receive-pack", "", "o/r", "contents", "write"},
		{"refs without service", "GET", "/o/r.git/info/refs", "", "o/r", "", ""},
		{"other .git suffix", "GET", "/o/r.git/HEAD", "", "o/r", "", ""},
		{"archive tar", "GET", "/o/r/archive/HEAD.tar.gz", "", "o/r", "contents", "read"},
		{"archive head", "HEAD", "/o/r/archive/refs/tags/v1.zip", "", "o/r", "contents", "read"},
		{"archive post", "POST", "/o/r/archive/HEAD.tar.gz", "", "o/r", "", ""},
		{"release download", "GET", "/o/r/releases/download/v1/a.tgz", "", "o/r", "contents", "read"},
		{"repo page", "GET", "/o/r", "", "o/r", "", ""},
		{"root", "GET", "/", "", "", "", ""},
		{"login", "GET", "/login", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, perm, level := GitHubWebScope(tt.method, tt.path, tt.query)
			if repo != tt.wantRepo || perm != tt.wantPerm || level != tt.wantLevel {
				t.Fatalf("GitHubWebScope = (%q, %q, %q), want (%q, %q, %q)", repo, perm, level, tt.wantRepo, tt.wantPerm, tt.wantLevel)
			}
		})
	}
}

func TestCodeloadScope(t *testing.T) {
	tests := []struct {
		name, method, path string
		wantRepo, wantPerm string
	}{
		{"tar.gz", "GET", "/o/r/tar.gz/main", "o/r", "contents"},
		{"legacy.zip", "HEAD", "/o/r/legacy.zip/refs/heads/main", "o/r", "contents"},
		{"post archive", "POST", "/o/r/zip/main", "o/r", ""},
		{"non-archive", "GET", "/o/r/whatever", "o/r", ""},
		{"root", "GET", "/", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, perm, _ := CodeloadScope(tt.method, tt.path, "")
			if repo != tt.wantRepo || perm != tt.wantPerm {
				t.Fatalf("CodeloadScope = (%q, %q), want (%q, %q)", repo, perm, tt.wantRepo, tt.wantPerm)
			}
		})
	}
}

// webScopeFixture holds a token store, a resolver, and an upstream that
// records the Authorization header of every forwarded request.
type webScopeFixture struct {
	tokenSvc *token.Service
	resolver TokenResolver
	upstream *httptest.Server
	mu       sync.Mutex
	authSeen []string
	store    database.Store
	userID   string
	ghTokID  string
}

func (f *webScopeFixture) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.authSeen...)
}

func newWebScopeFixture(t *testing.T) *webScopeFixture {
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
	f := &webScopeFixture{store: store, userID: user.ID, ghTokID: gt.ID}
	f.tokenSvc = token.NewService(store, 7*24*time.Hour, false)
	f.resolver = NewProxyTokenResolver(f.tokenSvc, store, enc, nil)
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(f.upstream.Close)
	return f
}

func (f *webScopeFixture) token(t *testing.T, repo string, scopes map[string]string) string {
	t.Helper()
	res, err := f.tokenSvc.Create(context.Background(), token.CreateRequest{
		UserID:        f.userID,
		GitHubTokenID: f.ghTokID,
		Repository:    repo,
		Scopes:        scopes,
		Duration:      24 * time.Hour,
		SessionID:     "test-session",
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Token
}

func (f *webScopeFixture) githubHandler() http.Handler {
	inner := NewPassthroughHandler(f.upstream.URL, nil, nil, tlsTransport(f.upstream))
	return NewScopedPassthroughHandler(inner, f.tokenSvc, f.resolver, nil, nil, slog.Default())
}

func (f *webScopeFixture) codeloadHandler() http.Handler {
	// Point the codeload passthrough at the test upstream.
	inner := NewPassthroughHandler(f.upstream.URL, nil, nil, tlsTransport(f.upstream))
	return NewScopedCodeloadHandler(inner, f.tokenSvc, f.resolver, nil, slog.Default())
}

func TestScopedPassthrough_GitHubVhost_Issue292(t *testing.T) {
	tests := []struct {
		name       string
		repo       string
		scopes     map[string]string
		method     string
		path       string
		wantStatus int
		wantBody   string
	}{
		// GAP-A3 live repro: repo-A token, B's archive on the github.com vhost.
		{"GAP-A3 archive other repo", "acme/a", nil, "GET", "/acme/b/archive/HEAD.tar.gz", 403, "not scoped to acme/b"},
		{"archive own repo", "acme/a", nil, "GET", "/acme/a/archive/HEAD.tar.gz", 200, ""},
		{"archive own repo with contents:read", "acme/a", map[string]string{"contents": "read"}, "GET", "/acme/a/archive/HEAD.tar.gz", 200, ""},
		{"archive without contents", "acme/a", map[string]string{"issues": "read"}, "GET", "/acme/a/archive/HEAD.tar.gz", 403, "contents:read"},
		{"release download other repo", "acme/a", nil, "GET", "/acme/b/releases/download/v1/x.tgz", 403, "not scoped to acme/b"},
		{"release download own repo", "acme/a", nil, "GET", "/acme/a/releases/download/v1/x.tgz", 200, ""},
		{"refs without service", "acme/a", nil, "GET", "/acme/a.git/info/refs", 403, "not mapped"},
		{"other .git suffix", "acme/a", nil, "GET", "/acme/a.git/HEAD", 403, "not mapped"},
		{"repo page", "acme/a", nil, "GET", "/acme/a", 403, "not mapped"},
		{"permission-only token unmapped", "", map[string]string{"contents": "read"}, "GET", "/acme/a/pulls", 403, "not mapped"},
		{"permission-only token archive", "", map[string]string{"contents": "read"}, "GET", "/acme/z/archive/main.zip", 200, ""},
		{"case-insensitive repo match", "o/r", nil, "GET", "/O/R/archive/x", 200, ""},
		{"dot-segment traversal", "acme/a", nil, "GET", "/acme/a/archive/../../../acme/b/archive/HEAD.tar.gz", 403, "not mapped"},
		{"encoded slash traversal", "acme/a", nil, "GET", "/acme/a/archive/..%2F..%2Facme/b", 403, "not mapped"},
		{"encoded dot", "acme/a", nil, "GET", "/acme/a/archive/%2e%2e/x", 403, "not mapped"},
		{"empty segment", "acme/a", nil, "GET", "/acme/a//archive/x", 403, "not mapped"},
		{"open-scoped token unmapped path", "", nil, "GET", "/acme/a/pulls", 200, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newWebScopeFixture(t)
			tok := f.token(t, tt.repo, tt.scopes)
			req := httptest.NewRequest(tt.method, "http://github.com"+tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rr := httptest.NewRecorder()
			f.githubHandler().ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantBody != "" && !strings.Contains(rr.Body.String(), tt.wantBody) {
				t.Fatalf("body %q does not contain %q", rr.Body.String(), tt.wantBody)
			}
			seen := f.seen()
			if tt.wantStatus == 403 && len(seen) != 0 {
				t.Fatalf("denied request reached upstream: %v", seen)
			}
			if tt.wantStatus == 200 && (len(seen) != 1 || seen[0] != "Bearer real-github-pat") {
				t.Fatalf("upstream auth = %v, want real credential", seen)
			}
		})
	}
}

func TestScopedCodeload_Issue292(t *testing.T) {
	tests := []struct {
		name       string
		repo       string
		scopes     map[string]string
		path       string
		auth       string // "" means use the client token
		wantStatus int
		wantAuth   string
	}{
		{"own repo archive", "acme/a", nil, "/acme/a/tar.gz/main", "", 200, "Bearer real-github-pat"},
		{"other repo archive", "acme/a", nil, "/acme/b/tar.gz/main", "", 403, ""},
		{"no contents permission", "acme/a", map[string]string{"issues": "read"}, "/acme/a/zip/main", "", 403, ""},
		{"unmapped path", "acme/a", nil, "/acme/a/whatever", "", 403, ""},
		{"traversal with leading empty segment", "acme/a", nil, "//acme/a/zip/../../../acme/b/zip/main", "", 403, ""},
		{"open-scoped token resolved", "", nil, "/acme/b/zip/main", "", 200, "Bearer real-github-pat"},
		{"anonymous unchanged", "acme/a", nil, "/acme/b/zip/main", "none", 200, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newWebScopeFixture(t)
			tok := f.token(t, tt.repo, tt.scopes)
			req := httptest.NewRequest("GET", "http://codeload.github.com"+tt.path, nil)
			if tt.auth == "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rr := httptest.NewRecorder()
			f.codeloadHandler().ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			seen := f.seen()
			for _, a := range seen {
				if strings.Contains(a, token.PrefixProxy) {
					t.Fatalf("client token forwarded upstream: %q", a)
				}
			}
			if tt.wantStatus == 403 && len(seen) != 0 {
				t.Fatalf("denied request reached upstream: %v", seen)
			}
			if tt.wantStatus == 200 && (len(seen) != 1 || seen[0] != tt.wantAuth) {
				t.Fatalf("upstream auth = %v, want %q", seen, tt.wantAuth)
			}
		})
	}
}

func TestScopedPassthrough_DenialMetric(t *testing.T) {
	f := newWebScopeFixture(t)
	tok := f.token(t, "acme/a", nil)
	cases := []struct {
		handler http.Handler
		host    string
		path    string
		vhost   string
		reason  string
	}{
		{f.githubHandler(), "github.com", "/acme/a", "github.com", "unmapped"},
		{f.githubHandler(), "github.com", "/acme/b/archive/HEAD.tar.gz", "github.com", "repo"},
		{f.codeloadHandler(), "codeload.github.com", "/acme/b/zip/main", "codeload.github.com", "repo"},
	}
	for _, c := range cases {
		before := deniedCount(t, c.vhost, c.reason)
		req := httptest.NewRequest("GET", "http://"+c.host+c.path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		c.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s%s: status = %d, want 403", c.host, c.path, rr.Code)
		}
		after := deniedCount(t, c.vhost, c.reason)
		if after-before != 1 {
			t.Fatalf("%s%s: denial counter delta = %v, want 1", c.host, c.path, after-before)
		}
	}
}

func deniedCount(t *testing.T, vhost, reason string) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	c := metrics.PassthroughScopeDeniedTotal.WithLabelValues(vhost, reason)
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetCounter().GetValue()
}
