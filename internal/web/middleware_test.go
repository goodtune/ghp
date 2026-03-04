package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
		name       string
		version    string
		wantHeader string
	}{
		{
			name:       "dev version",
			version:    "dev",
			wantHeader: "GitHub Proxy dev",
		},
		{
			name:       "release version",
			version:    "1.2.3",
			wantHeader: "GitHub Proxy 1.2.3",
		},
		{
			name:       "empty version",
			version:    "",
			wantHeader: "GitHub Proxy ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			rr := httptest.NewRecorder()
			ServerHeaderMiddleware(tc.version)(inner).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

			if got := rr.Header().Get("Server"); got != tc.wantHeader {
				t.Errorf("Server header: got %q, want %q", got, tc.wantHeader)
			}
		})
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
