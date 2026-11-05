package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/database"
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
	// The rig's perm-ro profile has no workflows permission, so the workflow
	// list is a permission denial (the endpoint is mapped).
	deniedForProfile := map[string]map[string]bool{
		"perm-ro": {"GET /repos/OWNER/REPO/actions/workflows": true},
	}
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
