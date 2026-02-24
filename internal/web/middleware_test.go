package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// wantSecurityHeaders lists the security headers that securityHeadersMiddleware
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
			securityHeadersMiddleware(inner).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

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

// TestSecurityHeadersMuxPrecedence verifies that:
//   - All routes on the inner (web UI) mux receive security headers.
//   - More-specific patterns registered on an outer mux take precedence and
//     bypass the security-headers middleware entirely (they do not receive the
//     headers), demonstrating that the middleware does not bleed into unrelated
//     handlers.
func TestSecurityHeadersMuxPrecedence(t *testing.T) {
	// Build the same structure that RegisterRoutes uses: an inner mux wrapped
	// with securityHeadersMiddleware, mounted as a "/" fallback on an outer mux
	// that also has more-specific patterns.
	inner := http.NewServeMux()
	inner.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "web-index")
		w.WriteHeader(http.StatusOK)
	})
	inner.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "web-login")
		w.WriteHeader(http.StatusOK)
	})

	outer := http.NewServeMux()
	outer.HandleFunc("GET /api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "api-data")
		w.WriteHeader(http.StatusOK)
	})
	outer.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "auth-callback")
		w.WriteHeader(http.StatusOK)
	})
	outer.Handle("/", securityHeadersMiddleware(inner))

	tests := []struct {
		name            string
		path            string
		wantHandler     string
		wantSecHeaders  bool // whether security headers should be present
	}{
		{
			name:           "web index receives security headers",
			path:           "/",
			wantHandler:    "web-index",
			wantSecHeaders: true,
		},
		{
			name:           "web login receives security headers",
			path:           "/login",
			wantHandler:    "web-login",
			wantSecHeaders: true,
		},
		{
			name:           "outer /api/ pattern takes precedence, no security headers",
			path:           "/api/data",
			wantHandler:    "api-data",
			wantSecHeaders: false,
		},
		{
			name:           "outer /auth/ pattern takes precedence, no security headers",
			path:           "/auth/callback",
			wantHandler:    "auth-callback",
			wantSecHeaders: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			outer.ServeHTTP(rr, httptest.NewRequest("GET", tc.path, nil))

			if got := rr.Header().Get("X-Handler"); got != tc.wantHandler {
				t.Errorf("X-Handler: got %q, want %q", got, tc.wantHandler)
			}
			for header, want := range wantSecurityHeaders {
				got := rr.Header().Get(header)
				if tc.wantSecHeaders && got != want {
					t.Errorf("%s: got %q, want %q", header, got, want)
				}
				if !tc.wantSecHeaders && got != "" {
					t.Errorf("%s: expected empty (outer-mux route), got %q", header, got)
				}
			}
		})
	}
}
