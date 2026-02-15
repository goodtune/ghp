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
		{"unknown.example.com", ""},
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
