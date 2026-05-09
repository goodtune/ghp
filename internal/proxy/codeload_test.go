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

func TestCodeloadHandler_NoRedirectToConfigured_PassthroughIsCounted(t *testing.T) {
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

	before := codeloadCounterValue(t, "actions", "checkout", "tar.gz", "passthrough")

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

	after := codeloadCounterValue(t, "actions", "checkout", "tar.gz", "passthrough")
	if after-before != 1 {
		t.Errorf("passthrough counter increment = %f, want 1", after-before)
	}
}

func TestCodeloadHandler_InvalidRedirectTo_FallsBackToPassthrough(t *testing.T) {
	// Anything that isn't a fully-qualified http(s) URL should be rejected at
	// validation time and the handler should fall back to transparent
	// passthrough. Each case is independent — the cache that backs
	// resolveRedirectBase is per-handler, so a fresh handler is constructed
	// per row.
	cases := []struct {
		name       string
		redirectTo string
	}{
		{"relative path", "/relative/not-absolute"},
		{"file scheme", "file:///tmp/cache"},
		{"opaque scheme without host", "https:no-host"},
		{"non-http scheme", "ftp://example.com/cache"},
		{"with query string", "https://mirror.example.com/?token=abc"},
		{"with fragment", "https://mirror.example.com/#section"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
					RedirectTo: tc.redirectTo,
				},
			}
			handler := NewCodeloadHandler(cfg, nil, transport)

			before := codeloadCounterValue(t, "actions", "checkout", "tar.gz", "passthrough")

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
			if loc := w.Header().Get("Location"); loc != "" {
				t.Errorf("unexpected Location header on rejected redirect_to %q: %q", tc.redirectTo, loc)
			}

			after := codeloadCounterValue(t, "actions", "checkout", "tar.gz", "passthrough")
			if after-before != 1 {
				t.Errorf("passthrough counter increment = %f, want 1", after-before)
			}
		})
	}
}

// TestCodeloadHandler_LowercasesOwnerAndRepoMetricLabels verifies that the
// owner/repo Prometheus labels are lowercased before incrementing the counter.
// GitHub treats owner and repo case-insensitively, so "Actions/Checkout" and
// "actions/checkout" must collapse to a single time series rather than create
// duplicate entries that inflate cardinality.
func TestCodeloadHandler_LowercasesOwnerAndRepoMetricLabels(t *testing.T) {
	cfg := &config.Config{
		Codeload: config.CodeloadConfig{
			RedirectTo: "https://codeload.cache.example.com/",
		},
	}
	handler := NewCodeloadHandler(cfg, nil, failingTransport(t))

	before := codeloadCounterValue(t, "actions", "checkout", "tar.gz", "redirect")

	// Send the path with mixed-case owner/repo.
	req := httptest.NewRequest(http.MethodGet, "/Actions/Checkout/tar.gz/abc123", nil)
	req.Host = "codeload.github.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	// The Location header preserves the original casing — only the metric
	// label is normalised.
	want := "https://codeload.cache.example.com/Actions/Checkout/tar.gz/abc123"
	if got := w.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	after := codeloadCounterValue(t, "actions", "checkout", "tar.gz", "redirect")
	if after-before != 1 {
		t.Errorf("lowercase-labelled counter increment = %f, want 1", after-before)
	}

	// Confirm the mixed-case label series did not increment (i.e. we did
	// not split into two time series).
	mixedCase := codeloadCounterValue(t, "Actions", "Checkout", "tar.gz", "redirect")
	if mixedCase != 0 {
		t.Errorf("mixed-case counter has value %f; expected 0 (label should be normalised)", mixedCase)
	}
}

// TestCodeloadHandler_HotReloadsRedirectTo verifies that mutating
// cfg.Codeload.RedirectTo after the handler is constructed (as happens on
// SIGUSR1) takes effect on the next request. This is the scenario described
// in docs/features/codeload.md and must work without a server restart.
func TestCodeloadHandler_HotReloadsRedirectTo(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
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

	// Initially no redirect: archive path passes through.
	req := httptest.NewRequest(http.MethodGet, "/actions/checkout/tar.gz/abc123", nil)
	req.Host = "codeload.github.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-reload: status = %d, want 200 (passthrough)", w.Code)
	}

	// Simulate SIGUSR1 hot-reload mutating the config in-place.
	cfg.Codeload.RedirectTo = "https://codeload.cache.example.com/"

	req = httptest.NewRequest(http.MethodGet, "/actions/checkout/tar.gz/abc123", nil)
	req.Host = "codeload.github.com"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("post-reload: status = %d, want 302", w.Code)
	}
	want := "https://codeload.cache.example.com/actions/checkout/tar.gz/abc123"
	if got := w.Header().Get("Location"); got != want {
		t.Errorf("post-reload: Location = %q, want %q", got, want)
	}

	// Reload again to clear redirect_to and confirm we go back to passthrough.
	cfg.Codeload.RedirectTo = ""

	req = httptest.NewRequest(http.MethodGet, "/actions/checkout/tar.gz/abc123", nil)
	req.Host = "codeload.github.com"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("post-clear: status = %d, want 200 (passthrough)", w.Code)
	}
}

// TestCodeloadHandler_AbsoluteFormRequest verifies the redirect target is
// built from the URL's path/query only, even when the request URL has scheme
// and host populated (as happens when ghp acts as an HTTP forward proxy).
func TestCodeloadHandler_AbsoluteFormRequest(t *testing.T) {
	cfg := &config.Config{
		Codeload: config.CodeloadConfig{
			RedirectTo: "https://codeload.cache.example.com/",
		},
	}
	handler := NewCodeloadHandler(cfg, nil, failingTransport(t))

	req := httptest.NewRequest(http.MethodGet, "/actions/checkout/tar.gz/abc123?foo=bar", nil)
	// Mimic the request shape produced by Go's net/http for an absolute-form
	// request line (e.g. forward-proxy clients).
	req.URL.Scheme = "https"
	req.URL.Host = "codeload.github.com"
	req.Host = "codeload.github.com"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	want := "https://codeload.cache.example.com/actions/checkout/tar.gz/abc123?foo=bar"
	if got := w.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q (absolute-form must not leak scheme/host into target)", got, want)
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
