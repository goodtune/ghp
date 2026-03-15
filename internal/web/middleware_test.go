package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/proxy"
)

// wantSecurityHeaders lists the security headers that SecurityHeadersMiddleware
// must set on every response that passes through it.
var wantSecurityHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
	"X-Content-Type-Options":  "nosniff",
	"X-Frame-Options":         "DENY",
	"Referrer-Policy":         "strict-origin-when-cross-origin",
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		handlerHeaders map[string]string // headers set by the inner handler
		wantStatus     int
	}{
		{
			name:       "sets all security headers",
			wantStatus: http.StatusOK,
		},
		{
			name:           "passes through handler headers alongside security headers",
			handlerHeaders: map[string]string{"Content-Type": "text/html"},
			wantStatus:     http.StatusOK,
		},
		{
			name:       "sets security headers on error responses",
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.handlerHeaders {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.wantStatus)
			})

			rr := httptest.NewRecorder()
			SecurityHeadersMiddleware(inner).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

			if rr.Code != tc.wantStatus {
				t.Errorf("status: got %d, want %d", rr.Code, tc.wantStatus)
			}
			for header, want := range wantSecurityHeaders {
				if got := rr.Header().Get(header); got != want {
					t.Errorf("%s: got %q, want %q", header, got, want)
				}
			}
			for k, want := range tc.handlerHeaders {
				if got := rr.Header().Get(k); got != want {
					t.Errorf("handler header %s: got %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestServerHeaderMiddleware(t *testing.T) {
	tests := []struct {
		name            string
		version         string
		wantVersion     string // expected X-GitHub-Proxy-Version value ("" means absent)
		upstreamHeaders map[string]string // headers set by inner handler (simulates upstream response)
	}{
		{
			name:        "dev version",
			version:     "dev",
			wantVersion: "dev",
		},
		{
			name:        "release version",
			version:     "1.2.3",
			wantVersion: "1.2.3",
		},
		{
			name:        "empty version",
			version:     "",
			wantVersion: "",
		},
		{
			// The reverse proxy copies GitHub's "server: github.com" via
			// Header().Add(). The middleware must win: only one Server value.
			name:            "overwrites upstream server header",
			version:         "1.0.0",
			wantVersion:     "1.0.0",
			upstreamHeaders: map[string]string{"Server": "github.com"},
		},
		{
			// When version is set, any upstream X-GitHub-Proxy-Version must
			// be overwritten with exactly one value matching version.
			name:            "overwrites upstream version header",
			version:         "2.0.0",
			wantVersion:     "2.0.0",
			upstreamHeaders: map[string]string{"X-GitHub-Proxy-Version": "upstream-leaked"},
		},
		{
			// When version is empty, any upstream X-GitHub-Proxy-Version
			// must be deleted entirely.
			name:            "deletes upstream version header when version empty",
			version:         "",
			wantVersion:     "",
			upstreamHeaders: map[string]string{"X-GitHub-Proxy-Version": "upstream-leaked"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.upstreamHeaders {
					// Simulate httputil.ReverseProxy which uses Add when copying
					// upstream response headers, potentially producing duplicates.
					w.Header().Add(k, v)
				}
				w.WriteHeader(http.StatusOK)
			})

			rr := httptest.NewRecorder()
			ServerHeaderMiddleware(tc.version)(inner).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

			if got := rr.Header().Get("Server"); got != "GitHub Proxy" {
				t.Errorf("Server header: got %q, want %q", got, "GitHub Proxy")
			}
			// Ensure there is exactly one Server header value (no duplicates).
			if vals := rr.Header().Values("Server"); len(vals) != 1 {
				t.Errorf("Server header count: got %d values %v, want exactly 1", len(vals), vals)
			}
			if tc.wantVersion != "" {
				if got := rr.Header().Get("X-GitHub-Proxy-Version"); got != tc.wantVersion {
					t.Errorf("X-GitHub-Proxy-Version header: got %q, want %q", got, tc.wantVersion)
				}
				if vals := rr.Header().Values("X-GitHub-Proxy-Version"); len(vals) != 1 {
					t.Errorf("X-GitHub-Proxy-Version header count: got %d values %v, want exactly 1", len(vals), vals)
				}
			} else {
				if vals := rr.Header().Values("X-GitHub-Proxy-Version"); len(vals) != 0 {
					t.Errorf("X-GitHub-Proxy-Version header: got %v, want header to be absent", vals)
				}
			}
		})
	}
}

func TestServerHeaderMiddlewareEmptyResponse(t *testing.T) {
	// A handler that returns without calling Write or WriteHeader should
	// still have the Server header set (implicit 200).
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// intentionally empty — no Write, no WriteHeader
	})
	rr := httptest.NewRecorder()
	ServerHeaderMiddleware("1.0.0")(inner).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if got := rr.Header().Get("Server"); got != "GitHub Proxy" {
		t.Errorf("Server header: got %q, want %q", got, "GitHub Proxy")
	}
	if got := rr.Header().Get("X-GitHub-Proxy-Version"); got != "1.0.0" {
		t.Errorf("X-GitHub-Proxy-Version header: got %q, want %q", got, "1.0.0")
	}
}

func TestServerHeaderMiddlewareFlusher(t *testing.T) {
	// Verify that Flush() is delegated through the wrapper and sets the header.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})
	rr := httptest.NewRecorder()
	ServerHeaderMiddleware("1.0.0")(inner).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if got := rr.Header().Get("Server"); got != "GitHub Proxy" {
		t.Errorf("Server header: got %q, want %q", got, "GitHub Proxy")
	}
	if got := rr.Header().Get("X-GitHub-Proxy-Version"); got != "1.0.0" {
		t.Errorf("X-GitHub-Proxy-Version header: got %q, want %q", got, "1.0.0")
	}
}

// noopStore implements database.Store with all methods returning zero values.
type noopStore struct{}

func (noopStore) CreateApp(_ context.Context, _ *database.App) error                            { return nil }
func (noopStore) GetAppByID(_ context.Context, _ string) (*database.App, error)                 { return nil, nil }
func (noopStore) GetDefaultApp(_ context.Context) (*database.App, error)                        { return nil, nil }
func (noopStore) ListApps(_ context.Context) ([]*database.App, error)                           { return nil, nil }
func (noopStore) UpdateApp(_ context.Context, _ *database.App) error                            { return nil }
func (noopStore) DeleteApp(_ context.Context, _ string) error                                   { return nil }
func (noopStore) SetDefaultApp(_ context.Context, _ string) error                               { return nil }
func (noopStore) UpsertUser(_ context.Context, _ *database.User) error                          { return nil }
func (noopStore) GetUserByGitHubID(_ context.Context, _ int64) (*database.User, error)         { return nil, nil }
func (noopStore) GetUserByID(_ context.Context, _ string) (*database.User, error)               { return nil, nil }
func (noopStore) ListUsers(_ context.Context) ([]*database.User, error)                         { return nil, nil }
func (noopStore) SyncAdminRoles(_ context.Context, _ []string) error                            { return nil }
func (noopStore) UpsertGitHubToken(_ context.Context, _ *database.GitHubToken) error           { return nil }
func (noopStore) GetGitHubToken(_ context.Context, _ string) (*database.GitHubToken, error)    { return nil, nil }
func (noopStore) GetGitHubTokenByID(_ context.Context, _ string) (*database.GitHubToken, error) { return nil, nil }
func (noopStore) CreateProxyToken(_ context.Context, _ *database.ProxyToken) error              { return nil }
func (noopStore) GetProxyTokenByHash(_ context.Context, _ string) (*database.ProxyToken, error) { return nil, nil }
func (noopStore) GetProxyTokenByID(_ context.Context, _ string) (*database.ProxyToken, error)   { return nil, nil }
func (noopStore) ListProxyTokens(_ context.Context, _ string) ([]*database.ProxyToken, error)   { return nil, nil }
func (noopStore) ListAllProxyTokens(_ context.Context) ([]*database.ProxyToken, error)          { return nil, nil }
func (noopStore) ListActiveProxyTokens(_ context.Context) ([]*database.ProxyToken, error)       { return nil, nil }
func (noopStore) RevokeProxyToken(_ context.Context, _ string) error                            { return nil }
func (noopStore) UpdateProxyTokenUsage(_ context.Context, _ string) error                       { return nil }
func (noopStore) UpdateProxyTokenAppID(_ context.Context, _ string, _ string) error             { return nil }
func (noopStore) Close() error { return nil }

// stubStore is a minimal database.Store that overrides UpsertUser and
// UpsertGitHubToken for the auth test-login flow. All other methods
// are provided by the embedded noopStore and return zero values.
type stubStore struct{ noopStore }

func (s *stubStore) UpsertUser(_ context.Context, u *database.User) error {
	if u.ID == "" {
		u.ID = "test-user-id"
	}
	return nil
}
func (s *stubStore) UpsertGitHubToken(_ context.Context, _ *database.GitHubToken) error {
	return nil
}
func (s *stubStore) Close() error { return nil }

func TestSessionUsernameMiddleware_WithSession(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DevMode: true}
	ah := auth.NewHandler(cfg, &stubStore{}, enc, slog.Default())

	// Use test-login to create a session.
	mux := http.NewServeMux()
	ah.RegisterRoutes(mux)
	loginReq := httptest.NewRequest("POST", "/auth/test-login",
		bytes.NewReader([]byte(`{"username":"alice","role":"admin"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	mux.ServeHTTP(loginRR, loginReq)

	if loginRR.Code != http.StatusOK {
		t.Fatalf("test-login: got %d, want 200; body: %s", loginRR.Code, loginRR.Body.String())
	}

	// Extract session cookie.
	cookies := loginRR.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie returned by test-login")
	}

	// Verify the middleware injects both username and user ID.
	var gotUsername, gotUserID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUsername = proxy.GetUsername(r)
		gotUserID = proxy.GetUserID(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := SessionUsernameMiddleware(ah)(inner)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(sessionCookie)
	// Prepare the access log slots (normally done by accessLogHandler).
	req, slots := proxy.PrepareAccessLogSlots(req)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if gotUsername != "alice" {
		t.Errorf("GetUsername inside handler: got %q, want %q", gotUsername, "alice")
	}
	if *slots.Username != "alice" {
		t.Errorf("username slot: got %q, want %q", *slots.Username, "alice")
	}
	if gotUserID == "" {
		t.Error("GetUserID inside handler: got empty string, want non-empty user ID")
	}
	if *slots.UserID == "" {
		t.Error("user ID slot: got empty string, want non-empty user ID")
	}
}

func TestSessionUsernameMiddleware_NoSession(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DevMode: true}
	ah := auth.NewHandler(cfg, &stubStore{}, enc, slog.Default())

	var gotUsername, gotUserID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUsername = proxy.GetUsername(r)
		gotUserID = proxy.GetUserID(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := SessionUsernameMiddleware(ah)(inner)

	req := httptest.NewRequest("GET", "/login", nil)
	req, slots := proxy.PrepareAccessLogSlots(req)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if gotUsername != "" {
		t.Errorf("GetUsername: got %q, want empty string", gotUsername)
	}
	if *slots.Username != "" {
		t.Errorf("username slot: got %q, want empty string", *slots.Username)
	}
	if gotUserID != "" {
		t.Errorf("GetUserID: got %q, want empty string", gotUserID)
	}
	if *slots.UserID != "" {
		t.Errorf("user ID slot: got %q, want empty string", *slots.UserID)
	}
}

// TestSecurityHeadersAllRoutes verifies that when SecurityHeadersMiddleware
// wraps the top-level mux, all routes (web UI, API, auth, docs) receive
// security headers alongside their own handler-specific headers.
func TestSecurityHeadersAllRoutes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "web-index")
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "web-login")
	})
	mux.HandleFunc("GET /api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "api-data")
	})
	mux.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "auth-callback")
	})

	wrapped := SecurityHeadersMiddleware(mux)

	tests := []struct {
		name        string
		path        string
		wantHandler string
	}{
		{
			name:        "web index",
			path:        "/",
			wantHandler: "web-index",
		},
		{
			name:        "web login",
			path:        "/login",
			wantHandler: "web-login",
		},
		{
			name:        "API route",
			path:        "/api/data",
			wantHandler: "api-data",
		},
		{
			name:        "auth route",
			path:        "/auth/callback",
			wantHandler: "auth-callback",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, httptest.NewRequest("GET", tc.path, nil))

			if got := rr.Header().Get("X-Handler"); got != tc.wantHandler {
				t.Errorf("X-Handler: got %q, want %q", got, tc.wantHandler)
			}
			for header, want := range wantSecurityHeaders {
				if got := rr.Header().Get(header); got != want {
					t.Errorf("%s: got %q, want %q", header, got, want)
				}
			}
		})
	}
}
