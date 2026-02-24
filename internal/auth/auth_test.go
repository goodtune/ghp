package auth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/config"
)

func TestSecureCookies(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		want    bool
	}{
		{
			name: "no TLS, no BaseURL",
			cfg:  &config.Config{},
			want: false,
		},
		{
			name: "https BaseURL",
			cfg: &config.Config{
				Server: config.ServerConfig{BaseURL: "https://example.com"},
			},
			want: true,
		},
		{
			name: "http BaseURL",
			cfg: &config.Config{
				Server: config.ServerConfig{BaseURL: "http://example.com"},
			},
			want: false,
		},
		{
			name: "TLS certificates configured",
			cfg: &config.Config{
				TLS: config.TLSConfig{
					Certificates: []config.CertificateConfig{
						{CertFile: "cert.pem", KeyFile: "key.pem"},
					},
				},
			},
			want: true,
		},
		{
			name: "TLS configured and http BaseURL",
			cfg: &config.Config{
				Server: config.ServerConfig{BaseURL: "http://example.com"},
				TLS: config.TLSConfig{
					Certificates: []config.CertificateConfig{
						{CertFile: "cert.pem", KeyFile: "key.pem"},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(tt.cfg, nil, nil, slog.Default())
			got := h.secureCookies()
			if got != tt.want {
				t.Errorf("secureCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleTestLogin_BodyTooLarge(t *testing.T) {
	cfg := &config.Config{DevMode: true}
	h := NewHandler(cfg, nil, nil, slog.Default())

	// Body must be valid-looking JSON so the decoder reads past the 1 MB limit.
	body := strings.NewReader(`{"username":"` + strings.Repeat("x", maxRequestBodySize) + `"}`)
	req := httptest.NewRequest("POST", "/auth/test-login", body)
	w := httptest.NewRecorder()
	h.handleTestLogin(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestHandleTestLogin_InvalidJSON(t *testing.T) {
	cfg := &config.Config{DevMode: true}
	h := NewHandler(cfg, nil, nil, slog.Default())

	req := httptest.NewRequest("POST", "/auth/test-login", strings.NewReader("not valid json"))
	w := httptest.NewRecorder()
	h.handleTestLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}
