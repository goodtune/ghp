# Multi-Virtualhost Implementation Plan


**Goal:** Transform ghp from a single-port reverse-proxy-dependent service into a direct-listening TLS termination point that routes four virtualhosts: `api.github.com`, `github.com`, `*.githubcopilot.com`, and a configurable management host.

**Architecture:** Single `http.Server` on :443 with SNI-based cert selection and host-dispatch middleware. A second server on :80 handles HTTP→HTTPS redirects. Transparent reverse proxies (`httputil.ReverseProxy`) handle `github.com` and `*.githubcopilot.com` traffic. Legacy plain HTTP mode is preserved for dev/backward compat.

**Tech Stack:** Go stdlib (`crypto/tls`, `net/http/httputil`, `net/http`), slog for logging, koanf for config.

**Design doc:** `docs/plans/2025-02-14-multi-virtualhost-design.md`

---

### Task 1: Add TLS and server config types

**Files:**
- Modify: `internal/config/config.go:15-49` (Config, ServerConfig, GitHubConfig structs)

**Step 1: Add TLSConfig and CertificateConfig types and new fields**

Add to `internal/config/config.go`:

```go
type TLSConfig struct {
	Certificates []CertificateConfig `koanf:"certificates"`
}

type CertificateConfig struct {
	CertFile string `koanf:"cert_file"`
	KeyFile  string `koanf:"key_file"`
}
```

Add to `Config` struct:

```go
TLS TLSConfig `koanf:"tls"`
```

Add to `ServerConfig`:

```go
HTTPSListen    string `koanf:"https_listen"`
HTTPListen     string `koanf:"http_listen"`
ManagementHost string `koanf:"management_host"`
```

Add to `GitHubConfig`:

```go
EnterpriseSlug string `koanf:"enterprise_slug"`
```

Add `"tls"` to the env var section switch case (line 127).

**Step 2: Run build to verify**

Run: `go build ./...`
Expected: clean build

**Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat: add TLS, server, and enterprise config types"
```

---

### Task 2: TLS certificate loader

**Files:**
- Create: `internal/server/tls.go`
- Create: `internal/server/tls_test.go`

**Step 1: Write failing test**

Create `internal/server/tls_test.go`:

```go
package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
)

func TestLoadTLSConfig(t *testing.T) {
	// Generate a self-signed cert for testing.
	dir := t.TempDir()
	certFile, keyFile := generateTestCert(t, dir, "test.example.com")

	cfg := &config.TLSConfig{
		Certificates: []config.CertificateConfig{
			{CertFile: certFile, KeyFile: keyFile},
		},
	}

	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if tlsCfg.GetCertificate == nil {
		t.Fatal("expected GetCertificate to be set")
	}
}

func TestLoadTLSConfigEmpty(t *testing.T) {
	cfg := &config.TLSConfig{}
	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		t.Fatal("expected nil tls.Config for empty cert list")
	}
}

func TestLoadTLSConfigBadFile(t *testing.T) {
	cfg := &config.TLSConfig{
		Certificates: []config.CertificateConfig{
			{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"},
		},
	}
	_, err := loadTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for bad cert files")
	}
}

func generateTestCert(t *testing.T, dir, hostname string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(dir, hostname+".pem")
	keyPath := filepath.Join(dir, hostname+"-key.pem")

	certOut, _ := os.Create(certPath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.Create(keyPath)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()

	return certPath, keyPath
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestLoadTLSConfig -v`
Expected: FAIL — `loadTLSConfig` not defined

**Step 3: Implement loadTLSConfig**

Create `internal/server/tls.go`:

```go
package server

import (
	"crypto/tls"
	"fmt"

	"github.com/goodtune/ghp/internal/config"
)

// loadTLSConfig loads certificate files and builds a tls.Config with
// SNI-based certificate selection. Returns nil if no certificates are configured.
func loadTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if len(cfg.Certificates) == 0 {
		return nil, nil
	}

	certs := make([]tls.Certificate, 0, len(cfg.Certificates))
	for _, cc := range cfg.Certificates {
		cert, err := tls.LoadX509KeyPair(cc.CertFile, cc.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading cert %s: %w", cc.CertFile, err)
		}
		certs = append(certs, cert)
	}

	tlsCfg := &tls.Config{
		Certificates: certs,
	}

	// Build a certificate map for SNI selection.
	// Go's tls.Config handles this automatically when Certificates is populated
	// and GetCertificate is not set, but we set GetCertificate explicitly so
	// we can log unmatched SNI requests.
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		for i := range certs {
			if hello.ServerName != "" {
				if err := certs[i].Leaf.Verify(x509.VerifyOptions{}); err == nil { // not ideal
				}
			}
		}
		return nil, nil // fall through to default
	}

	// Actually, let Go handle SNI matching via the built-in mechanism.
	// It already supports wildcard certs. Remove the custom GetCertificate
	// and just set Certificates. But we need GetCertificate for the test.
	// Use BuildNameToCertificate equivalent.
	tlsCfg.GetCertificate = nil
	// Parse leaf certs so Go can match by SNI.
	for i := range tlsCfg.Certificates {
		leaf, err := tlsCfg.Certificates[i].Leaf, error(nil)
		if leaf == nil {
			leaf, err = x509.ParseCertificate(tlsCfg.Certificates[i].Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("parsing leaf cert: %w", err)
			}
			tlsCfg.Certificates[i].Leaf = leaf
		}
	}

	return tlsCfg, nil
}
```

Wait — the above is getting messy. Let me simplify. Go's `tls.Config` with `Certificates` populated already does SNI matching when leaf certs are parsed. The cleaner approach:

```go
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/goodtune/ghp/internal/config"
)

// loadTLSConfig loads certificate files and builds a tls.Config with
// SNI-based certificate selection. Returns nil if no certificates are configured.
func loadTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if len(cfg.Certificates) == 0 {
		return nil, nil
	}

	tlsCfg := &tls.Config{}

	for _, cc := range cfg.Certificates {
		cert, err := tls.LoadX509KeyPair(cc.CertFile, cc.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading cert %s: %w", cc.CertFile, err)
		}
		// Parse leaf so Go can match by SNI (including wildcards).
		if cert.Leaf == nil {
			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("parsing leaf cert %s: %w", cc.CertFile, err)
			}
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}

	return tlsCfg, nil
}
```

Update the test — remove the `GetCertificate` check since we rely on Go's built-in SNI matching. Instead check that `Certificates` has the right count:

```go
func TestLoadTLSConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateTestCert(t, dir, "test.example.com")

	cfg := &config.TLSConfig{
		Certificates: []config.CertificateConfig{
			{CertFile: certFile, KeyFile: keyFile},
		},
	}

	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.Certificates[0].Leaf == nil {
		t.Fatal("expected leaf cert to be parsed")
	}
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run TestLoadTLS -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/server/tls.go internal/server/tls_test.go
git commit -m "feat: add TLS certificate loader with SNI support"
```

---

### Task 3: Access logging middleware

**Files:**
- Create: `internal/server/accesslog.go`
- Create: `internal/server/accesslog_test.go`

**Step 1: Write failing test**

Create `internal/server/accesslog_test.go`:

```go
package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	handler := accessLogHandler(inner, logger)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("User-Agent", "git/2.40")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	log := buf.String()
	for _, want := range []string{"http_request", "GET", "/org/repo", "200", "git/2.40", "github.com"} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q: %s", want, log)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestAccessLog -v`
Expected: FAIL — `accessLogHandler` not defined

**Step 3: Implement accessLogHandler**

Create `internal/server/accesslog.go`:

```go
package server

import (
	"log/slog"
	"net/http"
	"time"
)

// responseRecorder wraps http.ResponseWriter to capture status and size.
type responseRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.size += n
	return n, err
}

// accessLogHandler wraps an http.Handler with standard HTTP access logging.
func accessLogHandler(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		logger.Info("http_request",
			"method", r.Method,
			"host", r.Host,
			"path", r.URL.Path,
			"status", rec.status,
			"size", rec.size,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
		)
	})
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run TestAccessLog -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/server/accesslog.go internal/server/accesslog_test.go
git commit -m "feat: add HTTP access log middleware"
```

---

### Task 4: github.com passthrough handler

**Files:**
- Create: `internal/proxy/passthrough.go`
- Create: `internal/proxy/passthrough_test.go`

This handler is an `httputil.ReverseProxy` to `https://github.com` that intercepts
`ghp_` tokens when present, swapping them for real GitHub credentials.

**Step 1: Write failing test**

Create `internal/proxy/passthrough_test.go`:

```go
package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/token"
)

func TestPassthroughHandler_NoAuth(t *testing.T) {
	// Upstream mock that checks no ghp_ token leaks through.
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

	handler := NewPassthroughHandler(upstream.URL, nil, nil, nil)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPassthroughHandler_GhpToken(t *testing.T) {
	// Upstream mock that checks the token was rewritten.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer real-github-token" {
			t.Errorf("expected rewritten auth, got %q", auth)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Mock token resolver that returns a known token.
	resolver := &mockTokenResolver{
		token:       "real-github-token",
		resolveFunc: nil, // set up below
	}

	handler := NewPassthroughHandler(upstream.URL, resolver, nil, nil)

	req := httptest.NewRequest("GET", "http://github.com/org/repo.git/info/refs", nil)
	req.Header.Set("Authorization", "Bearer "+token.Prefix+"abc123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
```

The `mockTokenResolver` and `NewPassthroughHandler` interfaces need to be
designed as part of implementation. The key contract:

- `TokenResolver` interface: given a `ghp_` token string, return the real
  GitHub access token string (or error)
- `NewPassthroughHandler(upstreamURL string, resolver TokenResolver, enterpriseSlug string, logger *slog.Logger) http.Handler`

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestPassthroughHandler -v`
Expected: FAIL — types not defined

**Step 3: Implement NewPassthroughHandler**

Create `internal/proxy/passthrough.go`:

```go
package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/goodtune/ghp/internal/token"
)

// TokenResolver resolves a ghp_ token to a real GitHub access token.
type TokenResolver interface {
	ResolveToGitHubToken(ctx context.Context, ghpToken string) (string, error)
}

// NewPassthroughHandler creates a transparent reverse proxy to the given
// upstream URL. If a ghp_ token is found in the Authorization header, it
// is resolved and replaced with the real GitHub credential.
// If enterpriseSlug is non-empty, the sec-GitHub-allowed-enterprise header
// is injected on every request.
func NewPassthroughHandler(upstream string, resolver TokenResolver, enterpriseSlug string, logger *slog.Logger) http.Handler {
	target, _ := url.Parse(upstream)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host

			// Inject enterprise header if configured.
			if enterpriseSlug != "" {
				req.Header.Set("sec-GitHub-allowed-enterprise", enterpriseSlug)
			}

			// Check for ghp_ token.
			if resolver != nil {
				if ghpToken := extractGhpToken(req); ghpToken != "" {
					realToken, err := resolver.ResolveToGitHubToken(req.Context(), ghpToken)
					if err != nil {
						if logger != nil {
							logger.Warn("passthrough token resolution failed", "error", err)
						}
						// Remove the ghp_ token to avoid leaking it upstream.
						req.Header.Del("Authorization")
						return
					}
					req.Header.Set("Authorization", "Bearer "+realToken)
				}
			}
		},
	}

	// Use the upstream's TLS config for test servers.
	if target.Scheme == "https" {
		proxy.Transport = http.DefaultTransport
	}

	return proxy
}

// extractGhpToken checks for a ghp_ prefixed token in the Authorization header.
// Returns the full token string or empty if not found.
func extractGhpToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	scheme := strings.ToLower(parts[0])
	tok := parts[1]
	if (scheme == "token" || scheme == "bearer") && strings.HasPrefix(tok, token.Prefix) {
		return tok
	}
	return ""
}
```

Also add a `TokenResolverFunc` adapter and the mock for tests. Update the test
file to include the mock and fix up the resolver interface usage.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run TestPassthroughHandler -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/proxy/passthrough.go internal/proxy/passthrough_test.go
git commit -m "feat: add github.com passthrough handler with ghp_ token interception"
```

---

### Task 5: Copilot passthrough handler

**Files:**
- Modify: `internal/proxy/passthrough.go` (add `NewCopilotPassthroughHandler`)
- Modify: `internal/proxy/passthrough_test.go` (add tests)

The Copilot handler is similar to the GitHub passthrough but preserves the
original `Host` (subdomain varies: `api.githubcopilot.com`, etc.) and does
not intercept tokens.

**Step 1: Write failing test**

Add to `internal/proxy/passthrough_test.go`:

```go
func TestCopilotPassthroughHandler(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify original host is preserved.
		if r.Host != "api.githubcopilot.com" {
			t.Errorf("expected host api.githubcopilot.com, got %q", r.Host)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewCopilotPassthroughHandler(upstream.URL, "", nil)

	req := httptest.NewRequest("GET", "http://api.githubcopilot.com/some/path", nil)
	req.Host = "api.githubcopilot.com"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestCopilotPassthrough -v`
Expected: FAIL — `NewCopilotPassthroughHandler` not defined

**Step 3: Implement NewCopilotPassthroughHandler**

Add to `internal/proxy/passthrough.go`:

```go
// NewCopilotPassthroughHandler creates a transparent reverse proxy for
// *.githubcopilot.com traffic. The original Host is preserved so the
// correct subdomain reaches the real Copilot service. No token
// interception is performed.
func NewCopilotPassthroughHandler(upstreamBase string, enterpriseSlug string, logger *slog.Logger) http.Handler {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Preserve the original host (e.g. api.githubcopilot.com).
			originalHost := req.Host
			req.URL.Scheme = "https"
			req.URL.Host = originalHost
			req.Host = originalHost

			if enterpriseSlug != "" {
				req.Header.Set("sec-GitHub-allowed-enterprise", enterpriseSlug)
			}
		},
	}
}
```

Note: In tests, the upstream URL is a test server, so the Director needs
adjustment for testability. The implementation will use the real host. For
testing, we can override Transport. Adjust as needed during implementation.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run TestCopilotPassthrough -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/proxy/passthrough.go internal/proxy/passthrough_test.go
git commit -m "feat: add *.githubcopilot.com passthrough handler"
```

---

### Task 6: TokenResolver implementation

**Files:**
- Create: `internal/proxy/resolver.go`
- Create: `internal/proxy/resolver_test.go`

The passthrough handler needs a `TokenResolver` that bridges the existing
`token.Service` and `database.Store` / `crypto.Encryptor` to resolve a
`ghp_` token string into a plaintext GitHub access token.

**Step 1: Write failing test**

Create `internal/proxy/resolver_test.go` — test that given a valid ghp_ token,
the resolver returns the decrypted GitHub token. Use the existing test helpers
from `database/sqlite_test.go` patterns for setting up a test store.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestTokenResolver -v`
Expected: FAIL

**Step 3: Implement ProxyTokenResolver**

Create `internal/proxy/resolver.go`:

```go
package proxy

import (
	"context"
	"fmt"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// ProxyTokenResolver resolves ghp_ tokens to real GitHub access tokens.
type ProxyTokenResolver struct {
	tokenService *token.Service
	store        database.Store
	encryptor    *crypto.Encryptor
}

// NewProxyTokenResolver creates a new resolver.
func NewProxyTokenResolver(ts *token.Service, store database.Store, enc *crypto.Encryptor) *ProxyTokenResolver {
	return &ProxyTokenResolver{tokenService: ts, store: store, encryptor: enc}
}

// ResolveToGitHubToken resolves a ghp_ token to a plaintext GitHub access token.
func (r *ProxyTokenResolver) ResolveToGitHubToken(ctx context.Context, ghpToken string) (string, error) {
	pt, err := r.tokenService.Resolve(ctx, ghpToken)
	if err != nil {
		return "", fmt.Errorf("resolving token: %w", err)
	}
	if pt == nil {
		return "", fmt.Errorf("invalid token")
	}

	gt, err := r.store.GetGitHubTokenByID(ctx, pt.GitHubTokenID)
	if err != nil {
		return "", fmt.Errorf("loading github token: %w", err)
	}
	if gt == nil {
		return "", fmt.Errorf("github token not found")
	}

	plaintext, err := r.encryptor.Decrypt(gt.AccessToken)
	if err != nil {
		return "", fmt.Errorf("decrypting github token: %w", err)
	}

	return plaintext, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run TestTokenResolver -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/proxy/resolver.go internal/proxy/resolver_test.go
git commit -m "feat: add ProxyTokenResolver for passthrough handlers"
```

---

### Task 7: Host dispatch handler

**Files:**
- Modify: `internal/server/server.go:153-169` (replace `hostRoutingHandler`)

**Step 1: Write failing test**

Create or add to `internal/server/server_test.go`:

```go
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
		{"unknown.example.com", ""},  // 404
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestHostDispatch -v`
Expected: FAIL — `newHostDispatch` not defined

**Step 3: Implement newHostDispatch**

Replace the existing `hostRoutingHandler` in `internal/server/server.go` with:

```go
type hostDispatchConfig struct {
	apiHandler     http.Handler
	githubHandler  http.Handler
	copilotHandler http.Handler
	mgmtHandler    http.Handler
	managementHost string
}

// newHostDispatch creates a handler that routes requests by Host header.
func newHostDispatch(cfg hostDispatchConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		switch {
		case host == "api.github.com":
			cfg.apiHandler.ServeHTTP(w, r)
		case host == "github.com":
			cfg.githubHandler.ServeHTTP(w, r)
		case host == "githubcopilot.com" || strings.HasSuffix(host, ".githubcopilot.com"):
			cfg.copilotHandler.ServeHTTP(w, r)
		case strings.EqualFold(host, cfg.managementHost):
			cfg.mgmtHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run TestHostDispatch -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/server/server.go internal/server/server_test.go
git commit -m "feat: add four-way host dispatch handler"
```

---

### Task 8: HTTP redirect server

**Files:**
- Create: `internal/server/redirect.go`
- Create: `internal/server/redirect_test.go`

**Step 1: Write failing test**

Create `internal/server/redirect_test.go`:

```go
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSRedirectHandler(t *testing.T) {
	handler := httpsRedirectHandler()

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Host = "github.com"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("expected 301, got %d", rr.Code)
	}

	loc := rr.Header().Get("Location")
	expected := "https://github.com/org/repo"
	if loc != expected {
		t.Errorf("expected location %q, got %q", expected, loc)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestHTTPSRedirect -v`
Expected: FAIL — `httpsRedirectHandler` not defined

**Step 3: Implement httpsRedirectHandler**

Create `internal/server/redirect.go`:

```go
package server

import (
	"net/http"
)

// httpsRedirectHandler returns a handler that redirects all HTTP requests
// to their HTTPS equivalent.
func httpsRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run TestHTTPSRedirect -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/server/redirect.go internal/server/redirect_test.go
git commit -m "feat: add HTTP-to-HTTPS redirect handler"
```

---

### Task 9: Wire up server lifecycle

**Files:**
- Modify: `internal/server/server.go` (update `Run()` method)

This is the integration task that wires everything together. The `Run()` method
needs to:

1. Create all handlers (existing + new passthrough handlers)
2. Build the host dispatch
3. Wrap GitHub-facing handlers with access logging
4. Load TLS config if configured
5. Start HTTPS server on `https_listen` (or plain HTTP on `listen` for legacy mode)
6. Start HTTP redirect server on `http_listen`
7. Gracefully shut down both servers

**Step 1: Update Run() to detect TLS vs legacy mode**

In `internal/server/server.go`, update the `Run()` method. After existing
handler creation (line 69-71), add:

```go
// Create passthrough handlers.
resolver := proxy.NewProxyTokenResolver(tokenSvc, store, enc)
githubHandler := proxy.NewPassthroughHandler(
    "https://github.com", resolver, s.cfg.GitHub.EnterpriseSlug, s.logger)
copilotHandler := proxy.NewCopilotPassthroughHandler(
    "", s.cfg.GitHub.EnterpriseSlug, s.logger)

// Build host dispatch with access logging on GitHub-facing handlers.
dispatch := newHostDispatch(hostDispatchConfig{
    apiHandler:     accessLogHandler(proxyHandler, s.logger),
    githubHandler:  accessLogHandler(githubHandler, s.logger),
    copilotHandler: accessLogHandler(copilotHandler, s.logger),
    mgmtHandler:    mux,
    managementHost: s.cfg.Server.ManagementHost,
})
```

Replace the server creation block with:

```go
// TLS mode: https_listen configured with certificates.
if s.cfg.Server.HTTPSListen != "" {
    tlsCfg, err := loadTLSConfig(&s.cfg.TLS)
    if err != nil {
        return fmt.Errorf("loading TLS config: %w", err)
    }
    if tlsCfg == nil {
        return fmt.Errorf("https_listen configured but no TLS certificates provided")
    }

    // HTTPS server.
    httpsLn, err := net.Listen("tcp", s.cfg.Server.HTTPSListen)
    if err != nil {
        return fmt.Errorf("listening on %s: %w", s.cfg.Server.HTTPSListen, err)
    }
    tlsLn := tls.NewListener(httpsLn, tlsCfg)

    httpsServer := &http.Server{Handler: dispatch}

    // HTTP redirect server.
    var httpServer *http.Server
    if s.cfg.Server.HTTPListen != "" {
        httpLn, err := net.Listen("tcp", s.cfg.Server.HTTPListen)
        if err != nil {
            return fmt.Errorf("listening on %s: %w", s.cfg.Server.HTTPListen, err)
        }
        httpServer = &http.Server{Handler: httpsRedirectHandler()}
        go httpServer.Serve(httpLn)
    }

    // Graceful shutdown for both servers.
    shutdownCtx, cancel := signal.NotifyContext(ctx, shutdownSignals()...)
    defer cancel()
    go func() {
        <-shutdownCtx.Done()
        s.logger.Info("server_shutdown", "msg", "shutting down")
        httpsServer.Shutdown(context.Background())
        if httpServer != nil {
            httpServer.Shutdown(context.Background())
        }
    }()

    s.logger.Info("server_ready",
        "https_listen", s.cfg.Server.HTTPSListen,
        "http_listen", s.cfg.Server.HTTPListen,
        "msg", "ready to accept connections")
    notifySystemd("READY=1")

    if err := httpsServer.Serve(tlsLn); err != http.ErrServerClosed {
        return fmt.Errorf("server error: %w", err)
    }
    notifySystemd("STOPPING=1")
    return nil
}

// Legacy mode: plain HTTP on single port (no TLS).
ln, err := s.createListener()
if err != nil {
    return fmt.Errorf("creating listener: %w", err)
}
httpServer := &http.Server{Handler: dispatch}

// ... existing shutdown, signal, serve code ...
```

**Step 2: Add required imports**

Add `"crypto/tls"` to imports in `server.go`.

**Step 3: Run build to verify**

Run: `go build ./...`
Expected: clean build

**Step 4: Run all tests**

Run: `go test ./...`
Expected: all pass

**Step 5: Commit**

```bash
git add internal/server/server.go
git commit -m "feat: wire up TLS server with host dispatch and legacy fallback"
```

---

### Task 10: Enterprise header injection on existing API proxy

**Files:**
- Modify: `internal/proxy/proxy.go:272-292` (`forwardRequest` method)

The passthrough handlers already inject the enterprise header via their
Director functions. The existing API proxy handler (`forwardRequest`) also
needs to inject it.

**Step 1: Write failing test**

Add a test that verifies the enterprise header is set on forwarded requests
when `cfg.GitHub.EnterpriseSlug` is configured.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestEnterpriseHeader -v`
Expected: FAIL

**Step 3: Add enterprise header to forwardRequest**

In `internal/proxy/proxy.go`, in the `forwardRequest` method, after setting
the Authorization header (line 292), add:

```go
// Inject enterprise access restriction header if configured.
if h.cfg.GitHub.EnterpriseSlug != "" {
    proxyReq.Header.Set("sec-GitHub-allowed-enterprise", h.cfg.GitHub.EnterpriseSlug)
}
```

Also add it in `handleGraphQL` before the `forwardRequest` call — actually,
`forwardRequest` is shared by both paths, so adding it there covers both.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run TestEnterpriseHeader -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/proxy_test.go
git commit -m "feat: inject enterprise access restriction header on API proxy"
```

---

### Task 11: End-to-end verification

**Step 1: Build**

Run: `go build ./...`
Expected: clean build

**Step 2: Run all tests**

Run: `go test ./... -count=1`
Expected: all pass

**Step 3: Run go vet**

Run: `go vet ./...`
Expected: clean

**Step 4: Manual smoke test (dev mode)**

Start the server in dev mode (plain HTTP):

```bash
go run ./cmd/ghp serve --config testdata/dev.yaml
```

Test host routing:

```bash
# Management UI
curl -s -H "Host: ghp.example.com" http://localhost:8080/ | head -5

# API proxy (will fail auth, but should reach proxy handler)
curl -s -H "Host: api.github.com" http://localhost:8080/user

# github.com passthrough (should proxy to real github.com)
curl -s -H "Host: github.com" http://localhost:8080/ | head -5

# Copilot passthrough
curl -s -H "Host: api.githubcopilot.com" http://localhost:8080/ | head -5

# Unknown host → 404
curl -s -o /dev/null -w "%{http_code}" -H "Host: unknown.example.com" http://localhost:8080/
# Expected: 404
```

**Step 5: Commit any fixups**

```bash
git add -p  # review changes
git commit -m "fix: address smoke test findings"
```
