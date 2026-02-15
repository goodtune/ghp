package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/token"
)

type mockTokenResolver struct {
	token string
	err   error
}

func (m *mockTokenResolver) ResolveToGitHubToken(ctx context.Context, ghpToken string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

func TestPassthroughHandler_NoAuth(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("expected no auth header for passthrough, got %q", auth)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>github</html>"))
	}))
	defer upstream.Close()

	handler := NewPassthroughHandler(upstream.URL, nil, "", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPassthroughHandler_GhpToken(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer real-github-token" {
			t.Errorf("expected rewritten auth, got %q", auth)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	resolver := &mockTokenResolver{token: "real-github-token"}

	handler := NewPassthroughHandler(upstream.URL, resolver, "", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://github.com/org/repo.git/info/refs", nil)
	req.Header.Set("Authorization", "Bearer "+token.Prefix+"abc123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPassthroughHandler_EnterpriseHeader(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ent := r.Header.Get("sec-GitHub-allowed-enterprise")
		if ent != "my-enterprise" {
			t.Errorf("expected enterprise header 'my-enterprise', got %q", ent)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewPassthroughHandler(upstream.URL, nil, "my-enterprise", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://github.com/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestCopilotPassthroughHandler(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.githubcopilot.com" {
			t.Errorf("expected host api.githubcopilot.com, got %q", r.Host)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewCopilotPassthroughHandler(upstream.URL, "", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://api.githubcopilot.com/some/path", nil)
	req.Host = "api.githubcopilot.com"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestCopilotPassthroughHandler_EnterpriseHeader(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ent := r.Header.Get("sec-GitHub-allowed-enterprise")
		if ent != "my-enterprise" {
			t.Errorf("expected enterprise header 'my-enterprise', got %q", ent)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewCopilotPassthroughHandler(upstream.URL, "my-enterprise", nil, tlsTransport(upstream))

	req := httptest.NewRequest("GET", "http://api.githubcopilot.com/", nil)
	req.Host = "api.githubcopilot.com"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// tlsTransport returns an http.RoundTripper that trusts the test server's cert.
func tlsTransport(ts *httptest.Server) http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}
