package auth

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goodtune/ghp/internal/config"
)

func TestValidateRedirectURI(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret: "test-secret",
			AllowedRedirects: []string{
				"https://app.example.com/auth/callback",
				"*.example.org",
			},
		},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{"exact match", "https://app.example.com/auth/callback", true},
		{"wrong path", "https://app.example.com/other", false},
		{"wildcard match", "https://app.example.org/callback", true},
		{"wildcard subdomain", "https://sub.example.org/callback", true},
		{"wildcard deep subdomain", "https://a.b.example.org/callback", true},
		{"wildcard bare domain rejected", "https://example.org/callback", false},
		{"not in allowlist", "https://evil.com/callback", false},
		{"http rejected", "http://app.example.com/auth/callback", false},
		{"empty", "", false},
		{"relative path", "/auth/callback", false},
		{"no scheme", "app.example.com/auth/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.validateRedirectURI(tt.uri)
			if got != tt.want {
				t.Errorf("validateRedirectURI(%q) = %v, want %v", tt.uri, got, tt.want)
			}
		})
	}
}

func TestValidateRedirectURI_DevMode(t *testing.T) {
	cfg := &config.Config{
		DevMode: true,
		Auth: config.AuthConfig{
			JWTSecret: "test-secret",
			AllowedRedirects: []string{
				"http://localhost:3000/auth/callback",
			},
		},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	if !h.validateRedirectURI("http://localhost:3000/auth/callback") {
		t.Error("dev mode should allow HTTP localhost")
	}

	// HTTP to non-localhost should still be rejected in dev mode.
	cfg.Auth.AllowedRedirects = append(cfg.Auth.AllowedRedirects, "http://app.example.com/cb")
	if h.validateRedirectURI("http://app.example.com/cb") {
		t.Error("dev mode should still reject HTTP to non-localhost")
	}
}

func TestMatchesRedirectPattern(t *testing.T) {
	tests := []struct {
		name    string
		rawURI  string
		pattern string
		want    bool
	}{
		{"exact match", "https://app.example.com/cb", "https://app.example.com/cb", true},
		{"exact trailing slash normalized", "https://app.example.com/cb/", "https://app.example.com/cb", true},
		{"exact no match", "https://app.example.com/other", "https://app.example.com/cb", false},
		{"wildcard matches subdomain", "https://app.example.com/cb", "*.example.com", true},
		{"wildcard no match bare domain", "https://example.com/cb", "*.example.com", false},
		{"wildcard deep subdomain", "https://a.b.example.com/cb", "*.example.com", true},
		{"wildcard wrong domain", "https://app.other.com/cb", "*.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, _ := url.Parse(tt.rawURI)
			got := matchesRedirectPattern(tt.rawURI, parsed, tt.pattern)
			if got != tt.want {
				t.Errorf("matchesRedirectPattern(%q, %q) = %v, want %v",
					tt.rawURI, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"localhost:3000", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"::1", true},
		{"example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := isLocalhost(tt.host); got != tt.want {
				t.Errorf("isLocalhost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestBrokerAuthorize(t *testing.T) {
	cfg := &config.Config{
		GitHub: config.GitHubConfig{
			ClientID: "test-client-id",
		},
		Server: config.ServerConfig{
			BaseURL: "https://proxy.example.com",
		},
		Auth: config.AuthConfig{
			JWTSecret:        "test-secret-key-for-hmac-256-xx",
			AllowedRedirects: []string{"https://app.example.com/auth/callback"},
		},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	req := httptest.NewRequest("GET",
		"/auth/authorize?redirect_uri=https://app.example.com/auth/callback&state=csrf123", nil)
	w := httptest.NewRecorder()
	h.handleBrokerAuthorize(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", w.Code)
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("invalid Location header: %v", err)
	}
	if loc.Host != "github.com" {
		t.Errorf("expected redirect to github.com, got %s", loc.Host)
	}
	if loc.Query().Get("client_id") != "test-client-id" {
		t.Errorf("expected client_id=test-client-id, got %s", loc.Query().Get("client_id"))
	}
	if loc.Query().Get("redirect_uri") != "https://proxy.example.com/auth/callback" {
		t.Errorf("unexpected redirect_uri: %s", loc.Query().Get("redirect_uri"))
	}

	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("expected state parameter")
	}

	// Verify broker state was stored.
	bs, ok := h.brokerStates.Get(state)
	if !ok {
		t.Fatal("broker state not stored")
	}
	if bs.RedirectURI != "https://app.example.com/auth/callback" {
		t.Errorf("wrong redirect_uri in state: %s", bs.RedirectURI)
	}
	if bs.DownstreamState != "csrf123" {
		t.Errorf("wrong downstream state: %s", bs.DownstreamState)
	}
}

func TestBrokerAuthorize_MissingRedirectURI(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{JWTSecret: "test-secret"},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	req := httptest.NewRequest("GET", "/auth/authorize", nil)
	w := httptest.NewRecorder()
	h.handleBrokerAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBrokerAuthorize_DisallowedRedirectURI(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:        "test-secret",
			AllowedRedirects: []string{"https://allowed.example.com/cb"},
		},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	req := httptest.NewRequest("GET",
		"/auth/authorize?redirect_uri=https://evil.com/cb", nil)
	w := httptest.NewRecorder()
	h.handleBrokerAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBrokerCallback(t *testing.T) {
	// Mock GitHub OAuth token exchange and user info endpoints.
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "gho_test_token",
				"token_type":   "bearer",
				"expires_in":   28800,
			})
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         12345,
				"login":      "octocat",
				"email":      "octocat@github.com",
				"avatar_url": "https://avatars.githubusercontent.com/u/12345",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ghServer.Close()

	jwtSecret := "test-secret-key-for-hmac-256-xx"
	cfg := &config.Config{
		GitHub: config.GitHubConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
		Server: config.ServerConfig{
			BaseURL: "https://proxy.example.com",
		},
		Auth: config.AuthConfig{
			JWTSecret:        jwtSecret,
			AllowedRedirects: []string{"https://app.example.com/auth/callback"},
		},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())
	h.githubBaseURL = ghServer.URL
	h.githubAPIBaseURL = ghServer.URL

	// Pre-populate broker state as if /auth/authorize had run.
	stateToken := "test-state-token"
	h.brokerStates.Add(stateToken, &brokerState{
		RedirectURI:     "https://app.example.com/auth/callback",
		DownstreamState: "csrf123",
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	})

	req := httptest.NewRequest("GET",
		"/auth/callback?code=test-code&state="+stateToken, nil)
	w := httptest.NewRecorder()
	h.handleBrokerCallback(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d: %s", w.Code, w.Body.String())
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("invalid Location header: %v", err)
	}
	if loc.Scheme != "https" || loc.Host != "app.example.com" {
		t.Errorf("unexpected redirect host: %s://%s", loc.Scheme, loc.Host)
	}
	if loc.Path != "/auth/callback" {
		t.Errorf("unexpected redirect path: %s", loc.Path)
	}

	// Verify state was passed through.
	if loc.Query().Get("state") != "csrf123" {
		t.Errorf("expected state=csrf123, got %s", loc.Query().Get("state"))
	}

	// Verify JWT.
	tokenStr := loc.Query().Get("token")
	if tokenStr == "" {
		t.Fatal("missing token in redirect")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &BrokerClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	claims, ok := token.Claims.(*BrokerClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}
	if claims.Subject != "octocat" {
		t.Errorf("expected sub=octocat, got %s", claims.Subject)
	}
	if claims.AvatarURL != "https://avatars.githubusercontent.com/u/12345" {
		t.Errorf("unexpected avatar_url: %s", claims.AvatarURL)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://app.example.com/auth/callback" {
		t.Errorf("unexpected aud: %v", claims.Audience)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("expected exp claim")
	}
	// Token should expire within ~60 seconds of now.
	expDelta := time.Until(claims.ExpiresAt.Time)
	if expDelta < 55*time.Second || expDelta > 65*time.Second {
		t.Errorf("expected exp ~60s from now, got %v", expDelta)
	}
}

func TestBrokerCallback_NoState(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{JWTSecret: "test-secret"},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	// Without downstream state, the redirect should not include a state param.
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "gho_test_token",
				"expires_in":   28800,
			})
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         1,
				"login":      "testuser",
				"avatar_url": "https://avatars.githubusercontent.com/u/1",
			})
		}
	}))
	defer ghServer.Close()

	h.githubBaseURL = ghServer.URL
	h.githubAPIBaseURL = ghServer.URL

	stateToken := "no-downstream-state"
	h.brokerStates.Add(stateToken, &brokerState{
		RedirectURI:     "https://app.example.com/cb",
		DownstreamState: "", // no downstream state
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	})

	req := httptest.NewRequest("GET",
		"/auth/callback?code=test-code&state="+stateToken, nil)
	w := httptest.NewRecorder()
	h.handleBrokerCallback(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d: %s", w.Code, w.Body.String())
	}

	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "" {
		t.Errorf("expected no state param, got %q", loc.Query().Get("state"))
	}
	if loc.Query().Get("token") == "" {
		t.Error("expected token param")
	}
}

func TestBrokerCallback_ExpiredState(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{JWTSecret: "test-secret"},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	stateToken := "expired-state"
	h.brokerStates.Add(stateToken, &brokerState{
		RedirectURI: "https://app.example.com/cb",
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
	})

	req := httptest.NewRequest("GET",
		"/auth/callback?code=test-code&state="+stateToken, nil)
	w := httptest.NewRecorder()
	h.handleBrokerCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired state, got %d", w.Code)
	}
}

func TestBrokerCallback_InvalidState(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{JWTSecret: "test-secret"},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	req := httptest.NewRequest("GET",
		"/auth/callback?code=test-code&state=nonexistent", nil)
	w := httptest.NewRecorder()
	h.handleBrokerCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid state, got %d", w.Code)
	}
}

func TestBrokerCallback_MissingCode(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{JWTSecret: "test-secret"},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	req := httptest.NewRequest("GET", "/auth/callback?state=test-state", nil)
	w := httptest.NewRecorder()
	h.handleBrokerCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBrokerCallback_MissingState(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{JWTSecret: "test-secret"},
	}
	h := NewHandler(cfg, nil, nil, slog.Default())

	req := httptest.NewRequest("GET", "/auth/callback?code=test-code", nil)
	w := httptest.NewRecorder()
	h.handleBrokerCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBrokerCallbackURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		reqHost string
		tls     bool
		want    string
	}{
		{
			name:    "with base URL",
			baseURL: "https://proxy.example.com",
			want:    "https://proxy.example.com/auth/callback",
		},
		{
			name:    "base URL with trailing slash",
			baseURL: "https://proxy.example.com/",
			want:    "https://proxy.example.com/auth/callback",
		},
		{
			name:    "no base URL, HTTPS",
			reqHost: "proxy.example.com",
			tls:     true,
			want:    "https://proxy.example.com/auth/callback",
		},
		{
			name:    "no base URL, HTTP",
			reqHost: "proxy.example.com:8080",
			want:    "http://proxy.example.com:8080/auth/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{BaseURL: tt.baseURL},
			}
			h := NewHandler(cfg, nil, nil, slog.Default())

			req := httptest.NewRequest("GET", "/", nil)
			if tt.reqHost != "" {
				req.Host = tt.reqHost
			}
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}

			got := h.brokerCallbackURL(req)
			if got != tt.want {
				t.Errorf("brokerCallbackURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
