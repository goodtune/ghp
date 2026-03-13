package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
		rawPath    string // if set, overrides req.URL.Path after request creation (use for paths that url.Parse would mangle, e.g. "//...")
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
			name:       "redirect mode - relative redirect_to returns 500",
			mode:       "redirect",
			redirectTo: "/mirror",
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "redirect mode - empty redirect_to returns 500",
			mode:       "redirect",
			redirectTo: "",
			path:       "/goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusInternalServerError,
		},
		{
			// httptest.NewRequest parses "//..." as authority-relative (host=goodtune),
			// so we use rawPath to set req.URL.Path directly to a true double-slash path.
			name:       "block mode - double slash does not bypass policy",
			mode:       "block",
			path:       "/",
			rawPath:    "//goodtune/ghp/releases/download/0.7.0/ghp_linux.tar.gz",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unknown mode - passes through",
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
			if tt.rawPath != "" {
				req.URL.Path = tt.rawPath
			}
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

// roundTripFunc adapts a function into an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestReleasesHandlerHeadCheck(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		headStatus     int
		headErr        bool
		wantStatus     int
		wantLoc        string
		wantBodySubstr string
	}{
		{
			name:       "HEAD returns 200 - redirect proceeds",
			headStatus: http.StatusOK,
			wantStatus: http.StatusFound,
			wantLoc:    "https://mirror.example.com/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz",
		},
		{
			name:           "HEAD returns 404 - returns friendly 404 page",
			headStatus:     http.StatusNotFound,
			wantStatus:     http.StatusNotFound,
			wantBodySubstr: "Release Not Found",
		},
		{
			name:       "HEAD returns 403 - redirect proceeds",
			headStatus: http.StatusForbidden,
			wantStatus: http.StatusFound,
			wantLoc:    "https://mirror.example.com/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz",
		},
		{
			name:       "HEAD request fails - redirect proceeds",
			headErr:    true,
			wantStatus: http.StatusFound,
			wantLoc:    "https://mirror.example.com/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodHead {
						t.Errorf("expected HEAD request, got %s", req.Method)
					}
					if tt.headErr {
						return nil, errors.New("connection refused")
					}
					return &http.Response{
						StatusCode: tt.headStatus,
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				}),
			}

			cfg := &config.Config{
				Releases: config.ReleasesConfig{
					Mode:              "redirect",
					RedirectTo:        "https://mirror.example.com",
					RedirectHeadCheck: true,
				},
			}
			handler := NewReleasesHandlerWithClient(passthrough, cfg, nil, client)

			req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz", nil)
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
			if tt.wantBodySubstr != "" {
				body := w.Body.String()
				if !strings.Contains(body, tt.wantBodySubstr) {
					t.Errorf("body does not contain %q:\n%s", tt.wantBodySubstr, body)
				}
			}
		})
	}
}

func TestReleasesHandlerHeadCheckDisabled(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Client that would return 404, but head check is disabled so it should
	// never be called.
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatal("HEAD request should not be made when redirect_head_check is false")
			return nil, nil
		}),
	}

	cfg := &config.Config{
		Releases: config.ReleasesConfig{
			Mode:              "redirect",
			RedirectTo:        "https://mirror.example.com",
			RedirectHeadCheck: false,
		},
	}
	handler := NewReleasesHandlerWithClient(passthrough, cfg, nil, client)

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusFound)
	}
}

func TestReleasesHandlerHeadCheck404Content(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}),
	}

	cfg := &config.Config{
		Releases: config.ReleasesConfig{
			Mode:              "redirect",
			RedirectTo:        "https://mirror.example.com",
			RedirectHeadCheck: true,
		},
	}
	handler := NewReleasesHandlerWithClient(passthrough, cfg, nil, client)

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body := w.Body.String()
	// Check the default template populates the expected fields.
	for _, want := range []string{
		"goodtune/ghp",
		"ghp_linux.tar.gz",
		"v1.0.0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q:\n%s", want, body)
		}
	}
}

func TestReleasesHandlerHeadCheckCustomTemplate(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}),
	}

	// Write a custom template to a temp file.
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "custom-404.html")
	if err := os.WriteFile(tmplPath, []byte(`<h1>Custom: {{.Owner}}/{{.Repo}} {{.Tag}} {{.Asset}}</h1>`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Releases: config.ReleasesConfig{
			Mode:                     "redirect",
			RedirectTo:               "https://mirror.example.com",
			RedirectHeadCheck:        true,
			RedirectNotFoundTemplate: tmplPath,
		},
	}
	handler := NewReleasesHandlerWithClient(passthrough, cfg, nil, client)

	req := httptest.NewRequest(http.MethodGet, "/cli/cli/releases/download/v2.50.0/gh_linux_amd64.tar.gz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	want := "<h1>Custom: cli/cli v2.50.0 gh_linux_amd64.tar.gz</h1>"
	if got := w.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestReleasesHandlerHeadCheckBadCustomTemplate(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}),
	}

	cfg := &config.Config{
		Releases: config.ReleasesConfig{
			Mode:                     "redirect",
			RedirectTo:               "https://mirror.example.com",
			RedirectHeadCheck:        true,
			RedirectNotFoundTemplate: "/nonexistent/template.html",
		},
	}
	handler := NewReleasesHandlerWithClient(passthrough, cfg, nil, client)

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should fall back to default template when custom template fails to load.
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if !strings.Contains(w.Body.String(), "Release Not Found") {
		t.Error("expected default template fallback when custom template path is invalid")
	}
}

// TestNewReleasesHandlerNetrcAuth verifies the end-to-end wiring of
// NewReleasesHandler when redirect_head_check_netrc is set: the handler must
// send Basic auth credentials from the netrc file on outgoing HEAD probes.
func TestNewReleasesHandlerNetrcAuth(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var capturedUser, capturedPass string
	var gotAuth bool
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser, capturedPass, gotAuth = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()

	// Build a netrc file for the mirror's hostname.
	mirrorURL, err := url.Parse(mirror.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	netrcPath := filepath.Join(dir, "netrc")
	content := fmt.Sprintf("machine %s login mirroruser password mirrorsecret\n", mirrorURL.Hostname())
	if err := os.WriteFile(netrcPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Override the base transport so the netrc client trusts the test TLS cert.
	orig := netrcTransportBase
	netrcTransportBase = mirror.Client().Transport
	defer func() { netrcTransportBase = orig }()

	cfg := &config.Config{
		Releases: config.ReleasesConfig{
			Mode:                   "redirect",
			RedirectTo:             mirror.URL,
			RedirectHeadCheck:      true,
			RedirectHeadCheckNetrc: netrcPath,
		},
	}
	handler := NewReleasesHandler(passthrough, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Mirror returned 200, so handler should issue a client redirect.
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if !gotAuth {
		t.Error("expected Basic auth on HEAD request to mirror")
	}
	if capturedUser != "mirroruser" || capturedPass != "mirrorsecret" {
		t.Errorf("auth credentials = %q/%q, want mirroruser/mirrorsecret", capturedUser, capturedPass)
	}
}

// TestNewReleasesHandlerNetrcLoadErrorNoRedirect verifies that HEAD probes do
// not follow redirects even when the netrc file cannot be loaded. A mirror
// returning 302 must be treated as "found" regardless of auth configuration,
// and must never trigger the friendly 404 page.
func TestNewReleasesHandlerNetrcLoadErrorNoRedirect(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// redirectTarget returns 404 — if the HEAD client follows the mirror's
	// redirect, the handler would incorrectly serve a 404 page.
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer redirectTarget.Close()

	// Mirror returns 302 on HEAD requests.
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			http.Redirect(w, r, redirectTarget.URL+r.URL.Path, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()

	cfg := &config.Config{
		Releases: config.ReleasesConfig{
			Mode:                   "redirect",
			RedirectTo:             mirror.URL,
			RedirectHeadCheck:      true,
			RedirectHeadCheckNetrc: "/nonexistent/netrc", // triggers load error
		},
	}
	handler := NewReleasesHandler(passthrough, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// The mirror returned 302 (not 404) for the HEAD probe.
	// A client that stops at the first response treats 302 as "found" and the
	// handler issues a 302 redirect to the original client.
	// A client that follows the redirect would hit redirectTarget (404) and
	// serve the friendly 404 page instead.
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d — HEAD client must not follow redirects even when netrc loading fails", w.Code, http.StatusFound)
	}
}

// TestNewReleasesHandlerNoRedirectWithoutNetrc verifies that HEAD probes do not
// follow redirects when redirect_head_check is enabled but no netrc is set.
func TestNewReleasesHandlerNoRedirectWithoutNetrc(t *testing.T) {
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// redirectTarget returns 404 — following the redirect would trigger a 404 page.
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer redirectTarget.Close()

	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			http.Redirect(w, r, redirectTarget.URL+r.URL.Path, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()

	cfg := &config.Config{
		Releases: config.ReleasesConfig{
			Mode:              "redirect",
			RedirectTo:        mirror.URL,
			RedirectHeadCheck: true,
		},
	}
	handler := NewReleasesHandler(passthrough, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/releases/download/v1.0.0/ghp_linux.tar.gz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d — HEAD probes must not follow redirects", w.Code, http.StatusFound)
	}
}
