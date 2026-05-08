package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
)

// codeloadCounterValue reads the current value of the CodeloadRedirectTotal
// counter for the given label set.
func codeloadCounterValue(t *testing.T, owner, repo, archive, result string) float64 {
	t.Helper()
	return getCounterValue(t, metrics.CodeloadRedirectTotal, prometheus.Labels{
		"owner":   owner,
		"repo":    repo,
		"archive": archive,
		"result":  result,
	})
}

func TestCodeloadHandler_RedirectsArchiveRequests(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantArchive string
		wantOwner   string
		wantRepo    string
		wantLoc     string
	}{
		{
			name:        "tar.gz with sha",
			path:        "/actions/checkout/tar.gz/34e114876b0b11c390a56381ad16ebd13914f8d5",
			wantArchive: "tar.gz",
			wantOwner:   "actions",
			wantRepo:    "checkout",
			wantLoc:     "https://codeload.cache.example.com/actions/checkout/tar.gz/34e114876b0b11c390a56381ad16ebd13914f8d5",
		},
		{
			name:        "zip with branch",
			path:        "/actions/checkout/zip/main",
			wantArchive: "zip",
			wantOwner:   "actions",
			wantRepo:    "checkout",
			wantLoc:     "https://codeload.cache.example.com/actions/checkout/zip/main",
		},
		{
			name:        "legacy.tar.gz with tag",
			path:        "/goodtune/ghp/legacy.tar.gz/v1.0.0",
			wantArchive: "legacy.tar.gz",
			wantOwner:   "goodtune",
			wantRepo:    "ghp",
			wantLoc:     "https://codeload.cache.example.com/goodtune/ghp/legacy.tar.gz/v1.0.0",
		},
		{
			name:        "legacy.zip preserves query string",
			path:        "/goodtune/ghp/legacy.zip/abc123?foo=bar",
			wantArchive: "legacy.zip",
			wantOwner:   "goodtune",
			wantRepo:    "ghp",
			wantLoc:     "https://codeload.cache.example.com/goodtune/ghp/legacy.zip/abc123?foo=bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Codeload: config.CodeloadConfig{
					RedirectTo: "https://codeload.cache.example.com/",
				},
			}
			handler := NewCodeloadHandler(cfg, nil, failingTransport(t))

			before := codeloadCounterValue(t, tt.wantOwner, tt.wantRepo, tt.wantArchive, "redirect")

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Host = "codeload.github.com"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			if got := w.Header().Get("Location"); got != tt.wantLoc {
				t.Errorf("Location = %q, want %q", got, tt.wantLoc)
			}

			after := codeloadCounterValue(t, tt.wantOwner, tt.wantRepo, tt.wantArchive, "redirect")
			if after-before != 1 {
				t.Errorf("redirect counter increment = %f, want 1", after-before)
			}
		})
	}
}

func TestCodeloadHandler_RedirectTrimsTrailingSlash(t *testing.T) {
	cfg := &config.Config{
		Codeload: config.CodeloadConfig{
			RedirectTo: "https://codeload.cache.example.com",
		},
	}
	handler := NewCodeloadHandler(cfg, nil, failingTransport(t))

	req := httptest.NewRequest(http.MethodGet, "/actions/checkout/tar.gz/abc123", nil)
	req.Host = "codeload.github.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	want := "https://codeload.cache.example.com/actions/checkout/tar.gz/abc123"
	if got := w.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestCodeloadHandler_AllowListPassesThrough(t *testing.T) {
	var upstreamHits int
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamHits++
		if req.URL.Host != "codeload.github.com" {
			t.Errorf("upstream Host = %q, want codeload.github.com", req.URL.Host)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("archive bytes")),
			Header:     http.Header{},
		}, nil
	})

	tests := []struct {
		name  string
		allow []string
		owner string
		repo  string
	}{
		{"org-level allow", []string{"actions"}, "actions", "checkout"},
		{"org/repo allow", []string{"actions/checkout"}, "actions", "checkout"},
		{"case insensitive", []string{"ACTIONS/Checkout"}, "actions", "checkout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Codeload: config.CodeloadConfig{
					RedirectTo: "https://codeload.cache.example.com/",
					Allow:      tt.allow,
				},
			}
			handler := NewCodeloadHandler(cfg, nil, transport)

			before := codeloadCounterValue(t, tt.owner, tt.repo, "tar.gz", "passthrough")

			upstreamHits = 0
			req := httptest.NewRequest(http.MethodGet, "/"+tt.owner+"/"+tt.repo+"/tar.gz/abc123", nil)
			req.Host = "codeload.github.com"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 (passthrough)", w.Code)
			}
			if upstreamHits != 1 {
				t.Errorf("upstream hits = %d, want 1", upstreamHits)
			}
			if w.Header().Get("Location") != "" {
				t.Errorf("unexpected Location header: %q", w.Header().Get("Location"))
			}

			after := codeloadCounterValue(t, tt.owner, tt.repo, "tar.gz", "passthrough")
			if after-before != 1 {
				t.Errorf("passthrough counter increment = %f, want 1", after-before)
			}
		})
	}
}

func TestCodeloadHandler_NoRedirectToConfigured_AlwaysPassthrough(t *testing.T) {
	var upstreamHits int
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamHits++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     http.Header{},
		}, nil
	})

	cfg := &config.Config{
		Codeload: config.CodeloadConfig{},
	}
	handler := NewCodeloadHandler(cfg, nil, transport)

	req := httptest.NewRequest(http.MethodGet, "/actions/checkout/tar.gz/abc123", nil)
	req.Host = "codeload.github.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if upstreamHits != 1 {
		t.Errorf("upstream hits = %d, want 1", upstreamHits)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("Location") != "" {
		t.Errorf("unexpected Location header on passthrough: %q", w.Header().Get("Location"))
	}
}

func TestCodeloadHandler_InvalidRedirectTo_FallsBackToPassthrough(t *testing.T) {
	var upstreamHits int
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamHits++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     http.Header{},
		}, nil
	})

	cfg := &config.Config{
		Codeload: config.CodeloadConfig{
			RedirectTo: "/relative/not-absolute",
		},
	}
	handler := NewCodeloadHandler(cfg, nil, transport)

	req := httptest.NewRequest(http.MethodGet, "/actions/checkout/tar.gz/abc123", nil)
	req.Host = "codeload.github.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (fallback to passthrough)", w.Code)
	}
	if upstreamHits != 1 {
		t.Errorf("upstream hits = %d, want 1", upstreamHits)
	}
}

func TestCodeloadHandler_NonArchivePathPassesThrough(t *testing.T) {
	var upstreamHits int
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamHits++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     http.Header{},
		}, nil
	})

	cfg := &config.Config{
		Codeload: config.CodeloadConfig{
			RedirectTo: "https://codeload.cache.example.com/",
		},
	}
	handler := NewCodeloadHandler(cfg, nil, transport)

	// Codeload only serves archive paths in practice, but anything that
	// doesn't match the archive pattern should fall through to upstream
	// rather than being redirected (avoid sending unrelated traffic to a
	// mirror that only knows how to serve archives).
	for _, path := range []string{
		"/",
		"/actions/checkout",
		"/actions/checkout/blob/main/README.md",
		"/actions/checkout/refs", // archive format must come right after repo
	} {
		t.Run(path, func(t *testing.T) {
			upstreamHits = 0
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Host = "codeload.github.com"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if upstreamHits != 1 {
				t.Errorf("upstream hits = %d, want 1", upstreamHits)
			}
			if w.Header().Get("Location") != "" {
				t.Errorf("unexpected Location header: %q", w.Header().Get("Location"))
			}
		})
	}
}

// failingTransport returns a RoundTripper that fails the test if invoked. Used
// in redirect tests where no upstream call should happen.
func failingTransport(t *testing.T) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Errorf("unexpected upstream request to %s %s", req.Method, req.URL)
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
}
