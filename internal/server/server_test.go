package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestIsLoopbackListenAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"::1", true},
		{"localhost:8080", true},
		{"localhost", true},
		{":8080", false},      // all interfaces
		{"0.0.0.0:8080", false},
		{"0.0.0.0", false},
		{"192.168.1.1:8080", false},
	}
	for _, tt := range tests {
		got := isLoopbackListenAddr(tt.addr)
		if got != tt.want {
			t.Errorf("isLoopbackListenAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
