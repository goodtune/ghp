package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/token"
)

// rewriteTransport returns a RoundTripper that redirects every request to the
// given test server, so the reverse proxy under test never makes a real
// network call.
func rewriteTransport(t *testing.T, target string) http.RoundTripper {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req = req.Clone(req.Context())
		req.URL.Scheme = u.Scheme
		req.URL.Host = u.Host
		return http.DefaultTransport.RoundTrip(req)
	})
}

func TestParseRawPath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantOwner string
		wantRepo  string
		wantOK    bool
	}{
		{"classic ref form", "/goodtune/ghp/main/README.md", "goodtune", "ghp", true},
		{"explicit refs form", "/goodtune/ghp/refs/heads/main/README.md", "goodtune", "ghp", true},
		{"ref containing slashes", "/goodtune/ghp/feature/x/y/file.txt", "goodtune", "ghp", true},
		{"nested file path", "/goodtune/ghp/main/a/b/c/d.yaml", "goodtune", "ghp", true},
		{"casing normalised", "/GoodTune/GHP/main/README.md", "goodtune", "ghp", true},
		{"leading double slash", "//goodtune/ghp/main/README.md", "goodtune", "ghp", true},
		{"owner and repo only", "/goodtune/ghp", "", "", false},
		{"owner only", "/goodtune", "", "", false},
		{"root", "/", "", "", false},
		{"empty", "", "", "", false},
		{"trailing slash no file", "/goodtune/ghp/", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, ok := parseRawPath(tt.path)
			if ok != tt.wantOK || owner != tt.wantOwner || repo != tt.wantRepo {
				t.Errorf("parseRawPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.path, owner, repo, ok, tt.wantOwner, tt.wantRepo, tt.wantOK)
			}
		})
	}
}

func TestRawHandler_UnattributedPaths(t *testing.T) {
	tests := []struct {
		name                string
		method              string
		target              string
		allowQueryToken     bool
		wantStatus          int
		wantForwarded       bool
		wantQueryOnUpstream string
	}{
		{
			name:   "anonymous request is forwarded",
			method: http.MethodGet, target: "/goodtune/ghp/main/README.md",
			allowQueryToken: true, wantStatus: http.StatusOK, wantForwarded: true,
		},
		{
			name:   "query token forwarded unmodified when allowed",
			method: http.MethodGet, target: "/goodtune/ghp/main/README.md?token=ABC123",
			allowQueryToken: true, wantStatus: http.StatusOK, wantForwarded: true,
			wantQueryOnUpstream: "token=ABC123",
		},
		{
			name:   "query token rejected when policy disallows",
			method: http.MethodGet, target: "/goodtune/ghp/main/README.md?token=ABC123",
			allowQueryToken: false, wantStatus: http.StatusForbidden, wantForwarded: false,
		},
		{
			name:   "HEAD is allowed",
			method: http.MethodHead, target: "/goodtune/ghp/main/README.md",
			allowQueryToken: true, wantStatus: http.StatusOK, wantForwarded: true,
		},
		{
			name:   "POST is rejected",
			method: http.MethodPost, target: "/goodtune/ghp/main/README.md",
			allowQueryToken: true, wantStatus: http.StatusForbidden, wantForwarded: false,
		},
		{
			name:   "non-matching path is forwarded uncounted",
			method: http.MethodGet, target: "/goodtune/ghp",
			allowQueryToken: true, wantStatus: http.StatusOK, wantForwarded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var forwarded bool
			var upstreamQuery string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				upstreamQuery = r.URL.RawQuery
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			cfg := &config.Config{}
			cfg.Raw.AllowQueryToken = tt.allowQueryToken

			h := NewRawHandler(cfg, nil, nil, nil, nil, rewriteTransport(t, upstream.URL))

			req := httptest.NewRequest(tt.method, tt.target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if forwarded != tt.wantForwarded {
				t.Errorf("forwarded = %v, want %v", forwarded, tt.wantForwarded)
			}
			if tt.wantQueryOnUpstream != "" && upstreamQuery != tt.wantQueryOnUpstream {
				t.Errorf("upstream query = %q, want %q", upstreamQuery, tt.wantQueryOnUpstream)
			}
		})
	}
}

// fakeScopeEnforcer resolves any client token to a ProxyToken carrying the
// given repository allowlist and permission scopes. A nil repos slice or nil
// scopes map encodes as JSON null, i.e. "no restriction on that dimension" —
// the same shape the store returns for an unrestricted token.
type fakeScopeEnforcer struct {
	pt *database.ProxyToken
}

func newFakeScopeEnforcer(t *testing.T, repos []string, scopes map[string]string) *fakeScopeEnforcer {
	t.Helper()
	reposJSON, err := json.Marshal(repos)
	if err != nil {
		t.Fatalf("marshal repos: %v", err)
	}
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		t.Fatalf("marshal scopes: %v", err)
	}
	return &fakeScopeEnforcer{pt: &database.ProxyToken{
		TokenType:    string(token.TokenTypeProxy),
		Repositories: reposJSON,
		Scopes:       scopesJSON,
	}}
}

func (f *fakeScopeEnforcer) Resolve(ctx context.Context, clientToken string) (*database.ProxyToken, error) {
	return f.pt, nil
}

func TestRawHandler_ScopeEnforcement(t *testing.T) {
	tests := []struct {
		name           string
		tokenRepos     []string
		tokenScopes    map[string]string // permission -> level; nil means unrestricted
		target         string
		wantStatus     int
		wantForwarded  bool
		wantAuthHeader string
	}{
		{
			name:        "repo in allowlist is forwarded with real credential",
			tokenRepos:  []string{"goodtune/ghp"},
			tokenScopes: map[string]string{"contents": "read"},
			target:      "/goodtune/ghp/main/README.md",
			wantStatus:  http.StatusOK, wantForwarded: true,
			wantAuthHeader: "token real-github-token",
		},
		{
			name:        "repo outside allowlist is denied",
			tokenRepos:  []string{"goodtune/other"},
			tokenScopes: map[string]string{"contents": "read"},
			target:      "/goodtune/ghp/main/README.md",
			wantStatus:  http.StatusForbidden, wantForwarded: false,
		},
		{
			name:        "missing contents permission is denied",
			tokenRepos:  []string{"goodtune/ghp"},
			tokenScopes: map[string]string{"issues": "read"},
			target:      "/goodtune/ghp/main/README.md",
			wantStatus:  http.StatusForbidden, wantForwarded: false,
		},
		{
			name:       "open scoped token is forwarded",
			tokenRepos: nil, tokenScopes: nil,
			target:     "/goodtune/ghp/main/README.md",
			wantStatus: http.StatusOK, wantForwarded: true,
			wantAuthHeader: "token real-github-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var forwarded bool
			var gotAuth string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			cfg := &config.Config{}
			cfg.Raw.AllowQueryToken = true

			enforcer := newFakeScopeEnforcer(t, tt.tokenRepos, tt.tokenScopes)
			resolver := &mockTokenResolver{token: "real-github-token"}

			h := NewRawHandler(cfg, enforcer, resolver, nil, nil, rewriteTransport(t, upstream.URL))

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Header.Set("Authorization", "token "+token.PrefixProxy+"testtoken")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if forwarded != tt.wantForwarded {
				t.Errorf("forwarded = %v, want %v", forwarded, tt.wantForwarded)
			}
			if tt.wantAuthHeader != "" && gotAuth != tt.wantAuthHeader {
				t.Errorf("upstream Authorization = %q, want %q", gotAuth, tt.wantAuthHeader)
			}
		})
	}
}

func TestRawHandler_StripsQueryTokenOnAuthenticatedPath(t *testing.T) {
	var upstreamQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{}
	cfg.Raw.AllowQueryToken = true
	enforcer := newFakeScopeEnforcer(t, nil, nil)
	resolver := &mockTokenResolver{token: "real-github-token"}
	h := NewRawHandler(cfg, enforcer, resolver, nil, nil, rewriteTransport(t, upstream.URL))

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/main/README.md?token=GITHUBISSUED&ref=x", nil)
	req.Header.Set("Authorization", "token "+token.PrefixProxy+"testtoken")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(upstreamQuery, "GITHUBISSUED") {
		t.Errorf("upstream query = %q, GitHub-issued token must be stripped", upstreamQuery)
	}
	if !strings.Contains(upstreamQuery, "ref=x") {
		t.Errorf("upstream query = %q, unrelated params must be preserved", upstreamQuery)
	}
}

// rawCounterValue reads the current value of the RawRequestTotal counter for
// the given label set.
func rawCounterValue(t *testing.T, owner, repo, result string) float64 {
	t.Helper()
	return getCounterValue(t, metrics.RawRequestTotal, prometheus.Labels{
		"owner":  owner,
		"repo":   repo,
		"result": result,
	})
}

func TestRawHandler_CountsResults(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{}
	cfg.Raw.AllowQueryToken = false
	h := NewRawHandler(cfg, nil, nil, nil, nil, rewriteTransport(t, upstream.URL))

	before := rawCounterValue(t, "metricsowner", "metricsrepo", "denied_policy")
	req := httptest.NewRequest(http.MethodGet, "/MetricsOwner/MetricsRepo/main/f.txt?token=X", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	after := rawCounterValue(t, "metricsowner", "metricsrepo", "denied_policy")

	if after != before+1 {
		t.Errorf("denied_policy counter = %v, want %v", after, before+1)
	}
}
