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
	dto "github.com/prometheus/client_model/go"

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
	tests := []struct {
		name        string
		target      string
		wantAbsent  string
		wantPresent string
	}{
		{
			name:        "plain token parameter",
			target:      "/goodtune/ghp/main/README.md?token=GITHUBISSUED&ref=x",
			wantAbsent:  "GITHUBISSUED",
			wantPresent: "ref=x",
		},
		{
			// url.Values.Get cannot see a token smuggled behind a semicolon:
			// ParseQuery discards any &-segment containing ";", so the parsed
			// map is empty. Stripping must not be conditional on Get("token"),
			// and the segments that are not the token must survive.
			name:        "token smuggled behind a semicolon",
			target:      "/goodtune/ghp/main/README.md?x=1;token=SECRET",
			wantAbsent:  "SECRET",
			wantPresent: "x=1",
		},
		{
			// url.Values.Del is exact-case, so an uppercased parameter name
			// survived the strip. GitHub's query parsing is case-insensitive
			// on this parameter; ours must be too.
			name:        "uppercase token parameter",
			target:      "/goodtune/ghp/main/README.md?TOKEN=SECRET&ref=x",
			wantAbsent:  "SECRET",
			wantPresent: "ref=x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Header.Set("Authorization", "token "+token.PrefixProxy+"testtoken")
			h.ServeHTTP(httptest.NewRecorder(), req)

			if strings.Contains(upstreamQuery, tt.wantAbsent) {
				t.Errorf("upstream query = %q, GitHub-issued token %q must be stripped", upstreamQuery, tt.wantAbsent)
			}
			if tt.wantPresent != "" && !strings.Contains(upstreamQuery, tt.wantPresent) {
				t.Errorf("upstream query = %q, unrelated params must be preserved (%q)", upstreamQuery, tt.wantPresent)
			}
		})
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

// rawStageCount reads the observation count of the decision-pipeline histogram
// for the given stage and token type.
func rawStageCount(t *testing.T, stage, tokenType string) uint64 {
	t.Helper()
	m := &dto.Metric{}
	h, err := metrics.ProxyDecisionDuration.GetMetricWith(prometheus.Labels{
		"stage":      stage,
		"token_type": tokenType,
	})
	if err != nil {
		t.Fatalf("get histogram for stage %q/%q: %v", stage, tokenType, err)
	}
	if err := h.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("write histogram for stage %q/%q: %v", stage, tokenType, err)
	}
	return m.GetHistogram().GetSampleCount()
}

// TestRawHandler_ObservesDecisionStages verifies the handler is instrumented on
// the unattributed paths as well as the enforced one. The unattributed exits
// record total and upstream_roundtrip under token_type="unknown"; token
// extraction is timed on every content-path request and carries the real token
// type when a GHP token is present.
func TestRawHandler_ObservesDecisionStages(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	newHandler := func() http.Handler {
		cfg := &config.Config{}
		cfg.Raw.AllowQueryToken = true
		return NewRawHandler(cfg, newFakeScopeEnforcer(t, nil, nil),
			&mockTokenResolver{token: "real-github-token"}, nil, nil,
			rewriteTransport(t, upstream.URL))
	}

	t.Run("anonymous records total and upstream_roundtrip as unknown", func(t *testing.T) {
		beforeTotal := rawStageCount(t, metrics.StageTotal, "unknown")
		beforeUpstream := rawStageCount(t, metrics.StageUpstreamRoundtrip, "unknown")

		req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/main/README.md", nil)
		newHandler().ServeHTTP(httptest.NewRecorder(), req)

		if got := rawStageCount(t, metrics.StageTotal, "unknown"); got != beforeTotal+1 {
			t.Errorf("total observations = %d, want %d", got, beforeTotal+1)
		}
		if got := rawStageCount(t, metrics.StageUpstreamRoundtrip, "unknown"); got != beforeUpstream+1 {
			t.Errorf("upstream_roundtrip observations = %d, want %d", got, beforeUpstream+1)
		}
	})

	t.Run("denied_method records total", func(t *testing.T) {
		before := rawStageCount(t, metrics.StageTotal, "unknown")

		req := httptest.NewRequest(http.MethodPost, "/goodtune/ghp/main/README.md", nil)
		newHandler().ServeHTTP(httptest.NewRecorder(), req)

		if got := rawStageCount(t, metrics.StageTotal, "unknown"); got != before+1 {
			t.Errorf("total observations = %d, want %d", got, before+1)
		}
	})

	t.Run("query_token records total and upstream_roundtrip as unknown", func(t *testing.T) {
		beforeTotal := rawStageCount(t, metrics.StageTotal, "unknown")
		beforeUpstream := rawStageCount(t, metrics.StageUpstreamRoundtrip, "unknown")

		req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/main/README.md?token=ABC", nil)
		newHandler().ServeHTTP(httptest.NewRecorder(), req)

		if got := rawStageCount(t, metrics.StageTotal, "unknown"); got != beforeTotal+1 {
			t.Errorf("total observations = %d, want %d", got, beforeTotal+1)
		}
		if got := rawStageCount(t, metrics.StageUpstreamRoundtrip, "unknown"); got != beforeUpstream+1 {
			t.Errorf("upstream_roundtrip observations = %d, want %d", got, beforeUpstream+1)
		}
	})

	t.Run("denied_policy records total but not upstream_roundtrip", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Raw.AllowQueryToken = false
		denying := NewRawHandler(cfg, nil, nil, nil, nil, rewriteTransport(t, upstream.URL))

		beforeTotal := rawStageCount(t, metrics.StageTotal, "unknown")
		beforeUpstream := rawStageCount(t, metrics.StageUpstreamRoundtrip, "unknown")

		req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/main/README.md?token=ABC", nil)
		denying.ServeHTTP(httptest.NewRecorder(), req)

		if got := rawStageCount(t, metrics.StageTotal, "unknown"); got != beforeTotal+1 {
			t.Errorf("total observations = %d, want %d", got, beforeTotal+1)
		}
		if got := rawStageCount(t, metrics.StageUpstreamRoundtrip, "unknown"); got != beforeUpstream {
			t.Errorf("upstream_roundtrip observations = %d, want %d — a denied request never reaches upstream", got, beforeUpstream)
		}
	})

	t.Run("token extraction is timed with the real token type", func(t *testing.T) {
		before := rawStageCount(t, metrics.StageTokenExtraction, string(token.TokenTypeProxy))

		req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/main/README.md", nil)
		req.Header.Set("Authorization", "token "+token.PrefixProxy+"testtoken")
		newHandler().ServeHTTP(httptest.NewRecorder(), req)

		if got := rawStageCount(t, metrics.StageTokenExtraction, string(token.TokenTypeProxy)); got != before+1 {
			t.Errorf("token_extraction observations = %d, want %d", got, before+1)
		}
	})
}

// TestRawHandler_SemicolonSmuggledQueryToken covers the classification guard.
// ParseQuery discards any &-segment containing ";", so "?x=1;token=X" parses
// to an empty map. Classifying on url.Values.Get would push such a request
// past the policy branch into the anonymous branch, forwarding the
// GitHub-issued token upstream and counting it as anonymous — an evadable
// policy control, not the documented "forwarded but not attributed" trade.
func TestRawHandler_SemicolonSmuggledQueryToken(t *testing.T) {
	tests := []struct {
		name            string
		owner           string
		repo            string
		allowQueryToken bool
		wantStatus      int
		wantForwarded   bool
		wantResult      string
	}{
		{
			name:  "denied when policy disallows query tokens",
			owner: "smugglea", repo: "repoa",
			allowQueryToken: false,
			wantStatus:      http.StatusForbidden, wantForwarded: false,
			wantResult: "denied_policy",
		},
		{
			name:  "classified as query_token when policy allows",
			owner: "smuggleb", repo: "repob",
			allowQueryToken: true,
			wantStatus:      http.StatusOK, wantForwarded: true,
			wantResult: "query_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var forwarded bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			cfg := &config.Config{}
			cfg.Raw.AllowQueryToken = tt.allowQueryToken
			h := NewRawHandler(cfg, nil, nil, nil, nil, rewriteTransport(t, upstream.URL))

			before := rawCounterValue(t, tt.owner, tt.repo, tt.wantResult)
			anonBefore := rawCounterValue(t, tt.owner, tt.repo, "anonymous")

			target := "/" + tt.owner + "/" + tt.repo + "/main/f.txt?x=1;token=GITHUBTOKEN"
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if forwarded != tt.wantForwarded {
				t.Errorf("forwarded = %v, want %v", forwarded, tt.wantForwarded)
			}
			if after := rawCounterValue(t, tt.owner, tt.repo, tt.wantResult); after != before+1 {
				t.Errorf("%s counter = %v, want %v", tt.wantResult, after, before+1)
			}
			if after := rawCounterValue(t, tt.owner, tt.repo, "anonymous"); after != anonBefore {
				t.Errorf("anonymous counter = %v, want %v — smuggled token must not be counted as anonymous", after, anonBefore)
			}
		})
	}
}

// TestRawQueryToken exercises the token-detection and stripping helpers
// directly. These back both the raw.allow_query_token policy check and the
// strip on the authenticated path, so their edge cases are worth pinning down
// independently of the handler.
func TestRawQueryToken(t *testing.T) {
	tests := []struct {
		name      string
		rawQuery  string
		wantHas   bool
		wantStrip string
	}{
		{"empty", "", false, ""},
		{"no token", "a=1&b=2", false, "a=1&b=2"},
		{"plain token", "token=X", true, ""},
		{"token among others", "a=1&token=X&b=2", true, "a=1&b=2"},
		{"semicolon separated", "x=1;token=X", true, "x=1"},
		{"semicolon only separator", "token=X;y=2", true, "y=2"},
		{"uppercase key", "TOKEN=X&a=1", true, "a=1"},
		{"mixed case key", "ToKeN=X", true, ""},
		{"percent-encoded key", "%74oken=X&a=1", true, "a=1"},
		{"token as a value is not a key", "a=token&b=2", false, "a=token&b=2"},
		{"key prefixed but not equal", "tokenish=X", false, "tokenish=X"},
		{"bare token key with no value", "token", true, ""},
		{"repeated token params", "token=X&a=1;token=Y", true, "a=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rawQueryHasToken(tt.rawQuery); got != tt.wantHas {
				t.Errorf("rawQueryHasToken(%q) = %v, want %v", tt.rawQuery, got, tt.wantHas)
			}
			if got := stripRawQueryToken(tt.rawQuery); got != tt.wantStrip {
				t.Errorf("stripRawQueryToken(%q) = %q, want %q", tt.rawQuery, got, tt.wantStrip)
			}
		})
	}
}
