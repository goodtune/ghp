package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/web"
)

func TestHostDispatch(t *testing.T) {
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api"))
	})
	githubHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("github"))
	})
	copilotHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("copilot"))
	})
	mgmtHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mgmt"))
	})

	dispatch := newHostDispatch(hostDispatchConfig{
		apiHandler:     apiHandler,
		githubHandler:  githubHandler,
		copilotHandler: copilotHandler,
		mgmtHandler:    mgmtHandler,
		managementHost: "ghp.example.com",
	})

	tests := []struct {
		host     string
		expected string
	}{
		{"api.github.com", "api"},
		{"api.github.com:443", "api"},
		{"github.com", "github"},
		{"github.com:443", "github"},
		{"api.githubcopilot.com", "copilot"},
		{"copilot.githubcopilot.com", "copilot"},
		{"githubcopilot.com", "copilot"},
		{"ghp.example.com", "mgmt"},
		{"ghp.example.com:443", "mgmt"},
		{"unknown.example.com", ""}, // 404 when managementHost is set
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			rr := httptest.NewRecorder()
			dispatch.ServeHTTP(rr, req)

			body := rr.Body.String()
			if tt.expected == "" {
				if rr.Code != http.StatusNotFound {
					t.Errorf("expected 404, got %d", rr.Code)
				}
			} else if body != tt.expected {
				t.Errorf("host %s: expected %q, got %q", tt.host, tt.expected, body)
			}
		})
	}

}

// TestServerHeaderAllBackends verifies that the Server and X-GitHub-Proxy-Version
// response headers are set on all backends (api, github, copilot, mgmt) when
// ServerHeaderMiddleware wraps the host dispatch handler.
func TestServerHeaderAllBackends(t *testing.T) {
	const version = "1.2.3"

	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api"))
	})
	githubHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("github"))
	})
	copilotHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("copilot"))
	})
	mgmtHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mgmt"))
	})

	dispatch := newHostDispatch(hostDispatchConfig{
		apiHandler:     apiHandler,
		githubHandler:  githubHandler,
		copilotHandler: copilotHandler,
		mgmtHandler:    mgmtHandler,
		managementHost: "ghp.example.com",
	})
	handler := web.ServerHeaderMiddleware(version)(dispatch)

	tests := []struct {
		name string
		host string
		body string
	}{
		{"api backend", "api.github.com", "api"},
		{"github backend", "github.com", "github"},
		{"copilot backend", "api.githubcopilot.com", "copilot"},
		{"mgmt backend", "ghp.example.com", "mgmt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if got := rr.Body.String(); got != tt.body {
				t.Errorf("body: got %q, want %q", got, tt.body)
			}
			if got := rr.Header().Get("Server"); got != "GitHub Proxy" {
				t.Errorf("Server header: got %q, want %q", got, "GitHub Proxy")
			}
			if got := rr.Header().Get("X-GitHub-Proxy-Version"); got != version {
				t.Errorf("X-GitHub-Proxy-Version header: got %q, want %q", got, version)
			}
		})
	}
}

func TestHostDispatch_EmptyManagementHost(t *testing.T) {
	mgmtHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mgmt"))
	})

	dispatch := newHostDispatch(hostDispatchConfig{
		apiHandler:     http.NotFoundHandler(),
		githubHandler:  http.NotFoundHandler(),
		copilotHandler: http.NotFoundHandler(),
		mgmtHandler:    mgmtHandler,
		managementHost: "", // empty = catch-all fallback
	})

	tests := []struct {
		host     string
		expected string
	}{
		{"localhost", "mgmt"},
		{"localhost:8080", "mgmt"},
		{"anything.example.com", "mgmt"},
		{"192.168.1.1", "mgmt"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			rr := httptest.NewRecorder()
			dispatch.ServeHTTP(rr, req)

			body := rr.Body.String()
			if body != tt.expected {
				t.Errorf("host %s: expected %q, got %q", tt.host, tt.expected, body)
			}
		})
	}
}
