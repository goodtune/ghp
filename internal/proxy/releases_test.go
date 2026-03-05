package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/config"
)

func TestReleasesHandler(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		mode       string
		redirectTo string
		allow      []string
		path       string
		wantStatus int
		wantLoc    string // expected Location header (for redirects)
	}{
		{
			name:       "disabled - no mode set",
			mode:       "",
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusOK,
		},
		{
			name:       "block mode - release path blocked",
			mode:       "block",
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "block mode - non-release path passes through",
			mode:       "block",
			path:       "/goodtune/ghp/archive/refs/heads/main.tar.gz",
			wantStatus: http.StatusOK,
		},
		{
			name:       "block mode - root path passes through",
			mode:       "block",
			path:       "/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "block mode - org in allow list passes through",
			mode:       "block",
			allow:      []string{"goodtune"},
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusOK,
		},
		{
			name:       "block mode - org/repo in allow list passes through",
			mode:       "block",
			allow:      []string{"goodtune/ghp"},
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusOK,
		},
		{
			name:       "block mode - different org/repo not in allow list",
			mode:       "block",
			allow:      []string{"goodtune/other"},
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "redirect mode - release path redirected",
			mode:       "redirect",
			redirectTo: "https://releases.example.com/",
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusFound,
			wantLoc:    "https://releases.example.com/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
		},
		{
			name:       "redirect mode - no trailing slash on redirect base",
			mode:       "redirect",
			redirectTo: "https://releases.example.com",
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusFound,
			wantLoc:    "https://releases.example.com/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
		},
		{
			name:       "redirect mode - org in allow list passes through",
			mode:       "redirect",
			redirectTo: "https://releases.example.com/",
			allow:      []string{"goodtune"},
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusOK,
		},
		{
			name:       "redirect mode - non-release path passes through",
			mode:       "redirect",
			redirectTo: "https://releases.example.com/",
			path:       "/goodtune/ghp/archive/main.zip",
			wantStatus: http.StatusOK,
		},
		{
			name:       "redirect mode - empty redirect_to returns 500",
			mode:       "redirect",
			redirectTo: "",
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "unknown mode - passes through with warning",
			mode:       "unknown",
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Releases: config.ReleasesConfig{
					Mode:       tt.mode,
					RedirectTo: tt.redirectTo,
					Allow:      tt.allow,
				},
			}
			handler := NewReleasesHandler(passthrough, cfg, nil)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantLoc != "" {
				got := w.Header().Get("Location")
				if got != tt.wantLoc {
					t.Errorf("Location = %q, want %q", got, tt.wantLoc)
				}
			}
		})
	}
}

func TestReleasesHandlerQueryString(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := &config.Config{
		Releases: config.ReleasesConfig{
			Mode:       "redirect",
			RedirectTo: "https://releases.example.com/",
		},
	}
	handler := NewReleasesHandler(passthrough, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/releases/download/0.7.0/ghp.tar.gz?foo=bar", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusFound)
	}
	want := "https://releases.example.com/goodtune/ghp/releases/download/0.7.0/ghp.tar.gz?foo=bar"
	if got := w.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}
