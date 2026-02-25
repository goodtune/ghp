package auth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	req.RemoteAddr = "127.0.0.1:1234"
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
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.handleTestLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandleTestLogin_NonLoopbackRejected(t *testing.T) {
	cfg := &config.Config{DevMode: true}
	h := NewHandler(cfg, nil, nil, slog.Default())

	req := httptest.NewRequest("POST", "/auth/test-login", strings.NewReader(`{"username":"alice"}`))
	req.RemoteAddr = "203.0.113.1:5678" // non-loopback address
	w := httptest.NewRecorder()
	h.handleTestLogin(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected %d for non-loopback RemoteAddr, got %d", http.StatusForbidden, w.Code)
	}
}

func TestIsLoopbackRemoteAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:1234", true},
		{"[::1]:1234", true},
		{"::1", true},
		{"127.0.0.1", true},
		{"192.168.1.1:80", false},
		{"0.0.0.0:80", false},
		{"203.0.113.5:443", false},
	}
	for _, tt := range tests {
		got := isLoopbackRemoteAddr(tt.addr)
		if got != tt.want {
			t.Errorf("isLoopbackRemoteAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

// TestExchangeCode_URLEncoding verifies that special characters in client_id,
// client_secret, code, and redirect_uri are correctly percent-encoded in the
// application/x-www-form-urlencoded request body sent to GitHub.
func TestExchangeCode_URLEncoding(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		code         string
		redirectURI  string
	}{
		{
			name:         "ampersand in client_secret",
			clientID:     "id&injected=1",
			clientSecret: "secret&extra=bad",
			code:         "code123",
		},
		{
			name:         "equals sign in code",
			clientID:     "myid",
			clientSecret: "mysecret",
			code:         "code=broken",
		},
		{
			name:         "plus sign in client_id",
			clientID:     "id+plus",
			clientSecret: "secret",
			code:         "abc",
		},
		{
			name:         "special chars in redirect_uri",
			clientID:     "myid",
			clientSecret: "mysecret",
			code:         "abc",
			redirectURI:  "https://app.example.com/cb?foo=bar&baz=qux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedBody string
			ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				capturedBody = string(raw)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "gho_test",
					"expires_in":   28800,
				})
			}))
			defer ghServer.Close()

			cfg := &config.Config{
				GitHub: config.GitHubConfig{
					ClientID:     tt.clientID,
					ClientSecret: tt.clientSecret,
				},
			}
			h := NewHandler(cfg, nil, nil, slog.Default())
			h.githubBaseURL = ghServer.URL

			_, _, _, err := h.exchangeCode(tt.code, tt.redirectURI)
			if err != nil {
				t.Fatalf("exchangeCode returned error: %v", err)
			}

			parsed, err := url.ParseQuery(capturedBody)
			if err != nil {
				t.Fatalf("failed to parse captured body %q: %v", capturedBody, err)
			}

			if got := parsed.Get("client_id"); got != tt.clientID {
				t.Errorf("client_id: got %q, want %q", got, tt.clientID)
			}
			if got := parsed.Get("client_secret"); got != tt.clientSecret {
				t.Errorf("client_secret: got %q, want %q", got, tt.clientSecret)
			}
			if got := parsed.Get("code"); got != tt.code {
				t.Errorf("code: got %q, want %q", got, tt.code)
			}
			if tt.redirectURI != "" {
				if got := parsed.Get("redirect_uri"); got != tt.redirectURI {
					t.Errorf("redirect_uri: got %q, want %q", got, tt.redirectURI)
				}
			} else {
				if _, ok := parsed["redirect_uri"]; ok {
					t.Error("redirect_uri should not be present when empty")
				}
			}
		})
	}
}
