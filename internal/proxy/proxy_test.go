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
