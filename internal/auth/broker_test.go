package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
)
func TestValidateRedirectURI(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			AllowedRedirects: []string{
				"https://app.example.com/auth/callback",
				"*.example.org",
			},
		},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

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

func TestValidateRedirectURI_PathScopedWildcard(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			AllowedRedirects: []string{
				"*.example.com/auth/callback",
			},
		},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{"path-scoped wildcard match", "https://app.example.com/auth/callback", true},
		{"path-scoped deep subdomain match", "https://a.b.example.com/auth/callback", true},
		{"path-scoped wrong path rejected", "https://app.example.com/other", false},
		{"path-scoped bare domain rejected", "https://example.com/auth/callback", false},
		{"path-scoped wrong domain rejected", "https://app.other.com/auth/callback", false},
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
			AllowedRedirects: []string{
				"http://localhost:3000/auth/callback",
			},
		},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

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
		{"wildcard path match", "https://app.example.com/auth/callback", "*.example.com/auth/callback", true},
		{"wildcard path mismatch", "https://app.example.com/other", "*.example.com/auth/callback", false},
		{"wildcard path prefix match", "https://app.example.com/auth/callback?foo=bar", "*.example.com/auth/callback", true},
		{"wildcard path bare domain rejected", "https://example.com/auth/callback", "*.example.com/auth/callback", false},
		{"wildcard path subdirectory allowed", "https://app.example.com/auth/callback/extra", "*.example.com/auth/callback", true},
		// HasPrefix semantics: a pattern path is a string prefix, not a path segment
		// boundary. "/auth/callbackmalicious" starts with "/auth/callback" and therefore
		// matches. Operators should use trailing-slash patterns (e.g.
		// "*.example.com/auth/callback/") or exact URLs when this matters.
		{"wildcard path prefix overlap matches", "https://app.example.com/auth/callbackmalicious", "*.example.com/auth/callback", true},
		{"wildcard path with port", "https://app.example.com:8443/auth/callback", "*.example.com/auth/callback", true},
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
			AllowedRedirects: []string{"https://app.example.com/auth/callback"},
		},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

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

	// Verify broker state was stored by reading it back. Note that
	// ConsumeOAuthState atomically reads-and-deletes — the test does not
	// need to inspect the row again afterwards, so this is fine; if a true
	// non-destructive peek is ever needed, add a separate Get method.
	bs, err := h.store.ConsumeOAuthState(context.Background(), state, database.OAuthStateKindBroker)
	if err != nil {
		t.Fatalf("broker state not stored: %v", err)
	}
	if bs.BrokerRedirectURI != "https://app.example.com/auth/callback" {
		t.Errorf("wrong redirect_uri in state: %s", bs.BrokerRedirectURI)
	}
	if bs.BrokerDownstreamState != "csrf123" {
		t.Errorf("wrong downstream state: %s", bs.BrokerDownstreamState)
	}
}

func TestBrokerAuthorize_MissingRedirectURI(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

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
			AllowedRedirects: []string{"https://allowed.example.com/cb"},
		},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET",
		"/auth/authorize?redirect_uri=https://evil.com/cb", nil)
	w := httptest.NewRecorder()
	h.handleBrokerAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBrokerCallback(t *testing.T) {
	privKey, privPEM := generateTestRSAKey(t)

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

	cfg := &config.Config{
		GitHub: config.GitHubConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
		Server: config.ServerConfig{
			BaseURL: "https://proxy.example.com",
		},
		Auth: config.AuthConfig{
			JWTPrivateKey:    privPEM,
			AllowedRedirects: []string{"https://app.example.com/auth/callback"},
		},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())
	h.githubBaseURL = ghServer.URL
	h.githubAPIBaseURL = ghServer.URL

	// Pre-populate broker state as if /auth/authorize had run.
	stateToken := "test-state-token"
	if err := h.store.CreateOAuthState(context.Background(), &database.OAuthState{
		State:                 stateToken,
		Kind:                  database.OAuthStateKindBroker,
		BrokerRedirectURI:     "https://app.example.com/auth/callback",
		BrokerDownstreamState: "csrf123",
		ExpiresAt:             time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed broker state: %v", err)
	}

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

	// Verify JWT is signed with RS256.
	tokenStr := loc.Query().Get("token")
	if tokenStr == "" {
		t.Fatal("missing token in redirect")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &BrokerClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return &privKey.PublicKey, nil
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
	if claims.Issuer != "https://proxy.example.com" {
		t.Errorf("expected iss=https://proxy.example.com, got %s", claims.Issuer)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("expected exp claim")
	}
	// Token should expire within ~60 seconds of now.
	expDelta := time.Until(claims.ExpiresAt.Time)
	if expDelta < 55*time.Second || expDelta > 65*time.Second {
		t.Errorf("expected exp ~60s from now, got %v", expDelta)
	}

	// Verify kid header is present.
	if token.Header["kid"] == nil || token.Header["kid"] == "" {
		t.Error("expected kid header in JWT")
	}
}

func TestBrokerCallback_NoState(t *testing.T) {
	_, privPEM := generateTestRSAKey(t)
	cfg := &config.Config{
		Auth: config.AuthConfig{JWTPrivateKey: privPEM},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

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
	if err := h.store.CreateOAuthState(context.Background(), &database.OAuthState{
		State:                 stateToken,
		Kind:                  database.OAuthStateKindBroker,
		BrokerRedirectURI:     "https://app.example.com/cb",
		BrokerDownstreamState: "", // no downstream state
		ExpiresAt:             time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed broker state: %v", err)
	}

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

func TestBrokerCallback_InvalidState(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET",
		"/auth/callback?code=test-code&state=nonexistent", nil)
	w := httptest.NewRecorder()
	h.handleBrokerCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid state, got %d", w.Code)
	}
}

func TestBrokerCallback_MissingCode(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET", "/auth/callback?state=test-state", nil)
	w := httptest.NewRecorder()
	h.handleBrokerCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBrokerCallback_MissingState(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

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
			h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

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

// generateTestRSAKey is a helper that creates a 2048-bit RSA key and returns
// it along with the PEM-encoded private key string.
func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return privKey, string(pemBytes)
}

func TestHandleJWKS(t *testing.T) {
	_, privPEM := generateTestRSAKey(t)

	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTPrivateKey:    privPEM,
			AllowedRedirects: []string{"https://app.example.com/auth/callback"},
		},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.handleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %s", key.Kty)
	}
	if key.Alg != "RS256" {
		t.Errorf("expected alg=RS256, got %s", key.Alg)
	}
	if key.Use != "sig" {
		t.Errorf("expected use=sig, got %s", key.Use)
	}
	if key.Kid == "" {
		t.Error("expected non-empty kid field")
	}
	if key.N == "" || key.E == "" {
		t.Error("expected non-empty n and e fields")
	}
}

func TestHandleJWKS_NoKey(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.handleJWKS(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no RSA key configured, got %d", w.Code)
	}
}
