package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
)

// captureTransport records the last request sent through it and responds with 200.
type captureTransport struct {
	lastReq *http.Request
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.lastReq = req
	rec := httptest.NewRecorder()
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
