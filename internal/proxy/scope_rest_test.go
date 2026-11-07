package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
)

// Live-run repro GAP-A1 (#290): DELETE git/refs with contents:read must be
// denied by GHP, not forwarded.
func TestServeHTTP_GapA1_DeleteRefDeniedForContentsRead(t *testing.T) {
	h, tok, ct := newScopedHandlerWithTransport(t, "owner/w", map[string]string{"contents": "read"})
	req := httptest.NewRequest("DELETE", "http://api.github.com/repos/owner/w/git/refs/heads/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "contents:write") {
		t.Errorf("expected contents:write in body, got %s", rr.Body.String())
	}
	if ct.lastReq != nil {
		t.Errorf("request was forwarded upstream")
	}
}

// Live-run repro GAP-A2 (#291): /repositories/{id} with a repo-A token.
func TestServeHTTP_GapA2_RepositoriesByIDDeniedForRepoToken(t *testing.T) {
	h, tok, ct := newScopedHandlerWithTransport(t, "owner/a", nil)
	req := httptest.NewRequest("GET", "http://api.github.com/repositories/123456", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "/repositories/123456") {
		t.Errorf("expected path in body, got %s", rr.Body.String())
	}
	if ct.lastReq != nil {
		t.Errorf("request was forwarded upstream")
	}
}

// Live-run repro GAP-A7 (#295): dot segments are rejected before any
// lookup, for every client token (open tokens included).
func TestServeHTTP_GapA7_DotSegmentsRejected(t *testing.T) {
	paths := []string{
		"/repos/owner/a/../../owner/b/contents",
		"/repos/owner/a/./contents",
		"/repos/owner/a//contents",
		"/api/v3/repos/owner/a/../../owner/b/contents",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			h, tok, ct := newScopedHandlerWithTransport(t, "owner/a", nil)
			req := httptest.NewRequest("GET", "http://api.github.com/", nil)
			req.URL.Path = p
			req.Header.Set("Authorization", "Bearer "+tok)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d; body: %s", rr.Code, rr.Body.String())
			}
			if ct.lastReq != nil {
				t.Errorf("request was forwarded upstream")
			}
			if !strings.Contains(rr.Body.String(), "unsafe segment or character") {
				t.Errorf("unexpected body: %s", rr.Body.String())
			}
		})
	}
	t.Run("open token", func(t *testing.T) {
		h, tok := newOpenScopedHandler(t)
		req := httptest.NewRequest("GET", "http://api.github.com/", nil)
		req.URL.Path = "/repos/owner/a/../../owner/b/contents"
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rr.Code)
		}
	})
}

func TestServeHTTP_ScopeOnly_UnmappedDenied(t *testing.T) {
	h, tok := newScopeOnlyHandler(t, map[string]string{"contents": "write"})
	req := httptest.NewRequest("POST", "http://api.github.com/user/repos", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "POST /user/repos") {
		t.Errorf("expected method and path in body, got %s", rr.Body.String())
	}
}

func TestServeHTTP_OpenScoped_UnmappedForwarded(t *testing.T) {
	h, tok := newOpenScopedHandler(t)
	req := httptest.NewRequest("GET", "http://api.github.com/repositories/1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for open token, got %d", rr.Code)
	}
}

func TestDecideREST(t *testing.T) {
	repoA := tokenScopeInfo{Repos: []string{"owner/a"}}
	contentsRO := tokenScopeInfo{Scopes: database.Scopes{"contents": "read"}}
	contentsRW := tokenScopeInfo{Scopes: database.Scopes{"contents": "write"}}
	issuesRW := tokenScopeInfo{Scopes: database.Scopes{"issues": "write"}}
	prRW := tokenScopeInfo{Scopes: database.Scopes{"pull_requests": "write"}}
	adminRW := tokenScopeInfo{Scopes: database.Scopes{"administration": "write"}}
	checksRW := tokenScopeInfo{Scopes: database.Scopes{"checks": "write"}}

	tests := []struct {
		name     string
		si       tokenScopeInfo
		method   string
		path     string
		allowed  bool
		unmapped bool
	}{
		// Non-repository allowlist.
		{"root repo token", repoA, "GET", "/", true, false},
		{"user repo token", repoA, "GET", "/user", true, false},
		{"user head", repoA, "HEAD", "/user", true, false},
		{"rate_limit", contentsRO, "GET", "/rate_limit", true, false},
		{"meta", repoA, "GET", "/meta", true, false},
		{"octocat", repoA, "GET", "/octocat", true, false},
		{"zen", repoA, "GET", "/zen", true, false},
		{"patch user denied", contentsRW, "PATCH", "/user", false, true},
		{"patch user repo token denied", repoA, "PATCH", "/user", false, false},

		// #291: non-repo paths for a repo-restricted token.
		{"repositories id", repoA, "GET", "/repositories/1", false, false},
		{"search", repoA, "GET", "/search/issues", false, false},
		{"user repos", repoA, "GET", "/user/repos", false, false},
		{"org repos", repoA, "GET", "/orgs/x/repos", false, false},
		{"users repos", repoA, "GET", "/users/x/repos", false, false},
		{"org packages mapped but not repo", repoA, "GET", "/orgs/x/packages", false, false},
		{"repos owner only", repoA, "GET", "/repos/owner", false, false},
		{"case repos prefix", repoA, "GET", "/Repos/owner/a", false, false},
		{"other repo", repoA, "GET", "/repos/owner/b/pulls", false, false},
		{"allowed repo", repoA, "GET", "/repos/owner/a/pulls", true, false},
		{"allowed repo case", repoA, "GET", "/repos/OWNER/A", true, false},
		{"repo token unmapped in repo", repoA, "GET", "/repos/owner/a/traffic/views", false, true},

		// #290: unmapped for permission tokens.
		{"search perm token", contentsRO, "GET", "/search/issues", false, true},
		{"repositories perm token", contentsRO, "GET", "/repositories/1", false, true},
		{"gists", contentsRW, "POST", "/gists", false, true},
		{"subscription", contentsRW, "PUT", "/repos/o/r/subscription", false, true},

		// New rules.
		{"delete ref ro", contentsRO, "DELETE", "/repos/o/r/git/refs/heads/x", false, false},
		{"delete ref rw", contentsRW, "DELETE", "/repos/o/r/git/refs/heads/x", true, false},
		{"singular ref", contentsRO, "GET", "/repos/o/r/git/ref/heads/main", true, false},
		{"matching refs", contentsRO, "GET", "/repos/o/r/git/matching-refs/heads/m", true, false},
		{"readme", contentsRO, "GET", "/repos/o/r/readme", true, false},
		{"readme dir", contentsRO, "GET", "/repos/o/r/readme/docs", true, false},
		{"tags", contentsRO, "GET", "/repos/o/r/tags", true, false},
		{"patch release ro", contentsRO, "PATCH", "/repos/o/r/releases/1", false, false},
		{"patch release rw", contentsRW, "PATCH", "/repos/o/r/releases/1", true, false},
		{"delete release rw", contentsRW, "DELETE", "/repos/o/r/releases/1", true, false},
		{"merges ro", contentsRO, "POST", "/repos/o/r/merges", false, false},
		{"merges rw", contentsRW, "POST", "/repos/o/r/merges", true, false},
		{"dispatches ro", contentsRO, "POST", "/repos/o/r/dispatches", false, false},
		{"dispatches rw", contentsRW, "POST", "/repos/o/r/dispatches", true, false},
		{"keys ro token", contentsRW, "POST", "/repos/o/r/keys", false, false},
		{"keys admin", adminRW, "DELETE", "/repos/o/r/keys/1", true, false},
		{"labels create", contentsRW, "POST", "/repos/o/r/labels", false, false},
		{"labels create issues", issuesRW, "POST", "/repos/o/r/labels", true, false},
		{"milestone delete issues", issuesRW, "DELETE", "/repos/o/r/milestones/1", true, false},
		{"issue comment edit", contentsRW, "PATCH", "/repos/o/r/issues/comments/1", false, false},
		{"issue comment edit issues", issuesRW, "PATCH", "/repos/o/r/issues/comments/1", true, false},
		{"pull comment delete", contentsRW, "DELETE", "/repos/o/r/pulls/comments/1", false, false},
		{"pull comment delete pr", prRW, "DELETE", "/repos/o/r/pulls/comments/1", true, false},
		{"update branch", contentsRW, "PUT", "/repos/o/r/pulls/1/update-branch", false, false},
		{"update branch pr", prRW, "PUT", "/repos/o/r/pulls/1/update-branch", true, false},
		{"check run patch", contentsRW, "PATCH", "/repos/o/r/check-runs/1", false, false},
		{"check run patch checks", checksRW, "PATCH", "/repos/o/r/check-runs/1", true, false},
		{"rulesets write", contentsRW, "POST", "/repos/o/r/rulesets", false, false},
		{"rulesets admin", adminRW, "PUT", "/repos/o/r/rulesets/1", true, false},
		{"forks create", contentsRW, "POST", "/repos/o/r/forks", false, false},
		{"forks list metadata", contentsRO, "GET", "/repos/o/r/forks", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := decideREST(tt.si, tt.method, tt.path)
			if d.allowed != tt.allowed {
				t.Fatalf("allowed = %v, want %v (message %q)", d.allowed, tt.allowed, d.message)
			}
			if d.unmapped != tt.unmapped {
				t.Errorf("unmapped = %v, want %v", d.unmapped, tt.unmapped)
			}
			if !d.allowed && d.message == "" {
				t.Error("deny decision has no message")
			}
			if d.unmapped && !strings.Contains(d.message, tt.method+" "+tt.path) {
				t.Errorf("unmapped deny message %q does not name the request", d.message)
			}
		})
	}
}

func TestHasDotSegment(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/", false},
		{"/repos/o/r", false},
		{"/repos/o/r/contents/a.b", false},
		{"/repos/o/r/contents/..a", false},
		{"/repos/o/r/../x", true},
		{"/repos/o/r/./x", true},
		{"/repos/o/r/..", true},
		{"/repos//r", true},
		{"/repos/o/r/contents/", false},
		{"/repos/o/r?/issues", true},
		{"/repos/o/r#/issues", true},
		{"/repos/o/r%41", true},
		{"/repos/o/r\x00", true},
		{"/repos/o/r\x7f", true},
		{"/repos/o/r\\..\\b", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := hasUnsafePathSegment(tt.path); got != tt.want {
				t.Errorf("hasUnsafePathSegment(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestRESTGHCorpus runs every REST request in the gh query corpus through
// decideREST so gh's read commands keep working for suitably scoped tokens.
func TestRESTGHCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "rig", "corpus", "gh", "*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no corpus files found")
	}
	profiles := map[string]tokenScopeInfo{
		"perm-ro": {Scopes: database.Scopes{"contents": "read", "issues": "read", "pull_requests": "read", "metadata": "read", "actions": "read"}},
		"repo":    {Repos: []string{"OWNER/REPO"}},
	}
	// Endpoints that are denied for every scoped token by design: search is
	// cross-repository and has no single permission.
	deniedForScoped := map[string]bool{"GET /search/issues": true}
	// No profile-specific denials: perm-ro holds actions:read, which covers
	// the workflow list since #316.
	deniedForProfile := map[string]map[string]bool{}
	seen := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rest []string `json:"rest"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, entry := range doc.Rest {
			method, path, ok := strings.Cut(entry, " ")
			if !ok {
				t.Fatalf("%s: malformed rest entry %q", f, entry)
			}
			seen++
			for name, si := range profiles {
				t.Run(filepath.Base(f)+"/"+name+"/"+entry, func(t *testing.T) {
					d := decideREST(si, method, path)
					want := !deniedForScoped[entry] && !deniedForProfile[name][entry]
					if d.allowed != want {
						t.Errorf("allowed = %v, want %v (%s)", d.allowed, want, d.message)
					}
					if d.unmapped && !deniedForScoped[entry] {
						t.Errorf("gh REST request is unmapped: %s", d.message)
					}
				})
			}
		}
	}
	if seen == 0 {
		t.Fatal("corpus has no rest entries")
	}
}

// Encoded "?" or "#" in the path must never be forwarded: once decoded and
// re-parsed it would become a delimiter and change the target endpoint.
func TestServeHTTP_EncodedDelimitersRejected(t *testing.T) {
	type mk func(t *testing.T) (*Handler, string, *captureTransport)
	handlers := map[string]mk{
		"perm-only": func(t *testing.T) (*Handler, string, *captureTransport) {
			h, tok := newScopeOnlyHandler(t, map[string]string{"issues": "write"})
			ct := &captureTransport{}
			h.client.Transport = ct
			return h, tok, ct
		},
		"repo-restricted": func(t *testing.T) (*Handler, string, *captureTransport) {
			return newScopedHandlerWithTransport(t, "owner/x?", nil)
		},
	}
	for name, newH := range handlers {
		for _, enc := range []string{"%3F", "%23", "%3f"} {
			t.Run(name+"/"+enc, func(t *testing.T) {
				h, tok, ct := newH(t)
				req := httptest.NewRequest("PATCH", "http://api.github.com/repos/owner/x"+enc+"/issues/1", strings.NewReader(`{}`))
				req.Header.Set("Authorization", "Bearer "+tok)
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("expected 403, got %d; body: %s", rr.Code, rr.Body.String())
				}
				if ct.lastReq != nil {
					t.Errorf("request was forwarded upstream as %s", ct.lastReq.URL)
				}
			})
		}
	}
}

func TestServeHTTP_EncodedCharForwardedEscaped(t *testing.T) {
	h, tok, ct := newScopedHandlerWithTransport(t, "owner/w", map[string]string{"contents": "read"})
	req := httptest.NewRequest("GET", "http://api.github.com/repos/owner/w/git/refs/heads/a%2Bb?per_page=1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if ct.lastReq == nil {
		t.Fatal("request was not forwarded")
	}
	if got := ct.lastReq.URL.EscapedPath(); got != "/repos/owner/w/git/refs/heads/a%2Bb" {
		t.Errorf("upstream escaped path = %q", got)
	}
	if ct.lastReq.URL.RawQuery != "per_page=1" {
		t.Errorf("upstream query = %q", ct.lastReq.URL.RawQuery)
	}
}

func TestUpstreamURL(t *testing.T) {
	tests := []struct{ target, path, want string }{
		{"/repos/o/r/pulls?state=open", "/repos/o/r/pulls", "https://api.github.com/repos/o/r/pulls?state=open"},
		{"/api/v3/repos/o/r/git/refs/heads/a%2Bb", "/repos/o/r/git/refs/heads/a+b", "https://api.github.com/repos/o/r/git/refs/heads/a%2Bb"},
		{"/repos/o/r%3F/issues", "/repos/o/r?/issues", "https://api.github.com/repos/o/r%3F/issues"},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://api.github.com"+tt.target, nil)
			if got := upstreamURL(r, tt.path); got != tt.want {
				t.Errorf("upstreamURL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServeHTTP_UnmappedDeniedMetric(t *testing.T) {
	read := func(method string) float64 {
		m := &dto.Metric{}
		if err := metrics.ScopeUnmappedDeniedTotal.WithLabelValues("proxy", method).Write(m); err != nil {
			t.Fatal(err)
		}
		return m.GetCounter().GetValue()
	}
	t.Run("unmapped increments", func(t *testing.T) {
		h, tok := newScopeOnlyHandler(t, map[string]string{"contents": "write"})
		before := read("PUT")
		req := httptest.NewRequest("PUT", "http://api.github.com/repos/o/r/subscription", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rr.Code)
		}
		if read("PUT")-before != 1 {
			t.Errorf("counter did not increment by 1")
		}
	})
	t.Run("repo allowlist denial does not increment", func(t *testing.T) {
		h, tok := newRepoOnlyHandler(t, "owner/a")
		before := read("GET")
		req := httptest.NewRequest("GET", "http://api.github.com/repos/owner/b/traffic/views", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rr.Code)
		}
		if read("GET") != before {
			t.Errorf("counter incremented on a repo allowlist denial")
		}
	})
}

func TestDecideREST_ActionsAdminRules(t *testing.T) {
	actionsRW := tokenScopeInfo{Scopes: database.Scopes{"actions": "write"}}
	adminRW := tokenScopeInfo{Scopes: database.Scopes{"administration": "write"}}
	envRW := tokenScopeInfo{Scopes: database.Scopes{"environments": "write"}}
	varsRW := tokenScopeInfo{Scopes: database.Scopes{"variables": "write"}}
	tests := []struct {
		name    string
		si      tokenScopeInfo
		method  string
		path    string
		allowed bool
	}{
		{"permissions put actions", actionsRW, "PUT", "/repos/o/r/actions/permissions", false},
		{"permissions put admin", adminRW, "PUT", "/repos/o/r/actions/permissions/workflow", true},
		{"runners register actions", actionsRW, "POST", "/repos/o/r/actions/runners/registration-token", false},
		{"runners delete admin", adminRW, "DELETE", "/repos/o/r/actions/runners/1", true},
		{"runners read admin", adminRW, "GET", "/repos/o/r/actions/runners", true},
		{"variables actions", actionsRW, "POST", "/repos/o/r/actions/variables", false},
		{"variables vars", varsRW, "PATCH", "/repos/o/r/actions/variables/X", true},
		{"env create environments", envRW, "PUT", "/repos/o/r/environments/prod", false},
		{"env create admin", adminRW, "PUT", "/repos/o/r/environments/prod", true},
		{"env subpath environments", envRW, "PUT", "/repos/o/r/environments/prod/deployment-branch-policies/1", true},
		{"runs still actions", actionsRW, "POST", "/repos/o/r/actions/runs/1/rerun", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d := decideREST(tt.si, tt.method, tt.path); d.allowed != tt.allowed {
				t.Errorf("allowed = %v, want %v (%s)", d.allowed, tt.allowed, d.message)
			}
		})
	}
}

// The unsafe-path denial must record a real scope_enforcement duration.
func TestServeHTTP_UnsafePathRecordsScopeEnforcement(t *testing.T) {
	read := func() (uint64, float64) {
		m := &dto.Metric{}
		obs := metrics.ProxyDecisionDuration.WithLabelValues(metrics.StageScopeEnforcement, "proxy")
		if err := obs.(prometheus.Metric).Write(m); err != nil {
			t.Fatal(err)
		}
		return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
	}
	h, tok, _ := newScopedHandlerWithTransport(t, "owner/a", nil)
	beforeCount, beforeSum := read()
	req := httptest.NewRequest("GET", "http://api.github.com/", nil)
	req.URL.Path = "/repos/owner/a/../../owner/b/contents"
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	afterCount, afterSum := read()
	if afterCount-beforeCount != 1 {
		t.Fatalf("expected one scope_enforcement sample, got %d", afterCount-beforeCount)
	}
	if afterSum <= beforeSum {
		t.Errorf("expected a non-zero scope_enforcement duration, sum delta %g", afterSum-beforeSum)
	}
}

// TestDecideREST_ReactionsAndAliases covers the #315 reaction rules and the
// #316/#318 permission aliases end to end through decideREST.
func TestDecideREST_ReactionsAndAliases(t *testing.T) {
	tests := []struct {
		name   string
		scopes database.Scopes
		method string
		path   string
		want   bool
	}{
		{"issue reactions GET with issues:read", database.Scopes{"issues": "read"}, "GET", "/repos/o/r/issues/1/reactions", true},
		{"issue reactions POST with issues:read denied", database.Scopes{"issues": "read"}, "POST", "/repos/o/r/issues/1/reactions", false},
		{"issue reactions POST with issues:write", database.Scopes{"issues": "write"}, "POST", "/repos/o/r/issues/1/reactions", true},
		{"issue reaction DELETE with issues:read denied", database.Scopes{"issues": "read"}, "DELETE", "/repos/o/r/issues/1/reactions/5", false},
		{"issue reaction DELETE with issues:write", database.Scopes{"issues": "write"}, "DELETE", "/repos/o/r/issues/1/reactions/5", true},
		{"issue comment reactions POST with issues:read denied", database.Scopes{"issues": "read"}, "POST", "/repos/o/r/issues/comments/3/reactions", false},
		{"issue comment reactions POST with issues:write", database.Scopes{"issues": "write"}, "POST", "/repos/o/r/issues/comments/3/reactions", true},
		{"PR comment reactions POST with issues:write denied", database.Scopes{"issues": "write"}, "POST", "/repos/o/r/pulls/comments/3/reactions", false},
		{"PR comment reactions POST with pull_requests:write", database.Scopes{"pull_requests": "write"}, "POST", "/repos/o/r/pulls/comments/3/reactions", true},
		{"PR comment reactions GET with pull_requests:read", database.Scopes{"pull_requests": "read"}, "GET", "/repos/o/r/pulls/comments/3/reactions", true},
		{"commit comment reactions GET with contents:read", database.Scopes{"contents": "read"}, "GET", "/repos/o/r/comments/3/reactions", true},
		{"commit comment reactions POST with contents:read denied", database.Scopes{"contents": "read"}, "POST", "/repos/o/r/comments/3/reactions", false},
		{"commit comment reactions POST with contents:write", database.Scopes{"contents": "write"}, "POST", "/repos/o/r/comments/3/reactions", true},
		{"commit comment reaction DELETE with contents:write", database.Scopes{"contents": "write"}, "DELETE", "/repos/o/r/comments/3/reactions/4", true},

		{"workflows list with actions:read", database.Scopes{"actions": "read"}, "GET", "/repos/o/r/actions/workflows", true},
		{"workflows list with deprecated workflows:read alias", database.Scopes{"workflows": "read"}, "GET", "/repos/o/r/actions/workflows", true},
		{"workflows list with workflows:write denied", database.Scopes{"workflows": "write"}, "GET", "/repos/o/r/actions/workflows", false},
		{"workflow dispatch with actions:read denied", database.Scopes{"actions": "read"}, "POST", "/repos/o/r/actions/workflows/ci.yml/dispatches", false},
		{"workflow dispatch with workflows:read alias denied", database.Scopes{"workflows": "read"}, "POST", "/repos/o/r/actions/workflows/ci.yml/dispatches", false},
		{"workflow dispatch with actions:write", database.Scopes{"actions": "write"}, "POST", "/repos/o/r/actions/workflows/ci.yml/dispatches", true},
		{"workflow enable with actions:write", database.Scopes{"actions": "write"}, "PUT", "/repos/o/r/actions/workflows/ci.yml/enable", true},
		{"workflows:read alias does not grant runs write", database.Scopes{"workflows": "read"}, "POST", "/repos/o/r/actions/runs/1/rerun", false},

		{"classic projects GET with repository_projects:read", database.Scopes{"repository_projects": "read"}, "GET", "/repos/o/r/projects", true},
		{"classic projects GET with organization_projects:read", database.Scopes{"organization_projects": "read"}, "GET", "/orgs/o/projects", true},
		{"classic projects POST with repository_projects:read denied", database.Scopes{"repository_projects": "read"}, "POST", "/repos/o/r/projects", false},
		{"classic projects POST with repository_projects:write", database.Scopes{"repository_projects": "write"}, "POST", "/repos/o/r/projects", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := decideREST(tokenScopeInfo{Scopes: tt.scopes}, tt.method, tt.path)
			if d.allowed != tt.want {
				t.Errorf("allowed = %v, want %v (%s)", d.allowed, tt.want, d.message)
			}
			if d.unmapped {
				t.Errorf("unexpectedly unmapped: %s", d.message)
			}
		})
	}
}
