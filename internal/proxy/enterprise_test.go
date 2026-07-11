package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
)

// fakeIdentitySource is a test double for ExceptionIdentitySource that records
// calls and returns a fixed token or error.
type fakeIdentitySource struct {
	mu    sync.Mutex
	token string
	err   error
	calls []identityCall
}

type identityCall struct {
	appRecordID string
	owner       string
	repos       []string
	permissions map[string]string
}

func (f *fakeIdentitySource) InstallationTokenForOwner(_ context.Context, appRecordID, owner string, repos []string, permissions map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, identityCall{appRecordID: appRecordID, owner: owner, repos: repos, permissions: permissions})
	return f.token, f.err
}

func staticUsername(name string) UsernameFunc {
	return func(context.Context) string { return name }
}

func TestEnterpriseTargetFromAPIPath(t *testing.T) {
	tests := []struct {
		path      string
		wantOwner string
		wantRepo  string
	}{
		{"/repos/torvalds/linux", "torvalds", "linux"},
		{"/repos/torvalds/linux/pulls", "torvalds", "linux"},
		{"/repos/torvalds/linux/issues/1/comments", "torvalds", "linux"},
		{"/users/torvalds", "torvalds", ""},
		{"/users/torvalds/repos", "torvalds", ""},
		{"/orgs/kubernetes", "kubernetes", ""},
		{"/orgs/kubernetes/teams", "kubernetes", ""},
		{"/repos/torvalds", "", ""},
		{"/repos", "", ""},
		{"/graphql", "", ""},
		{"/search/repositories", "", ""},
		{"/user", "", ""},
		{"/", "", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			owner, repo := enterpriseTargetFromAPIPath(tt.path)
			if owner != tt.wantOwner || repo != tt.wantRepo {
				t.Errorf("enterpriseTargetFromAPIPath(%q) = (%q, %q), want (%q, %q)",
					tt.path, owner, repo, tt.wantOwner, tt.wantRepo)
			}
		})
	}
}

func TestEnterpriseTargetFromWebPath(t *testing.T) {
	tests := []struct {
		path      string
		wantOwner string
		wantRepo  string
	}{
		{"/torvalds/linux.git/info/refs", "torvalds", "linux"},
		{"/torvalds/linux.git/git-receive-pack", "torvalds", "linux"},
		{"/torvalds/linux", "torvalds", "linux"},
		{"/torvalds/linux/releases/download/v1/x.tgz", "torvalds", "linux"},
		{"/torvalds", "torvalds", ""},
		{"/", "", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			owner, repo := enterpriseTargetFromWebPath(tt.path)
			if owner != tt.wantOwner || repo != tt.wantRepo {
				t.Errorf("enterpriseTargetFromWebPath(%q) = (%q, %q), want (%q, %q)",
					tt.path, owner, repo, tt.wantOwner, tt.wantRepo)
			}
		})
	}
}

func TestNewEnterprisePolicy_DisabledWithoutSlug(t *testing.T) {
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseExceptions: []config.EnterpriseException{{Match: []string{"torvalds"}}},
	}, nil, slog.Default())
	if p != nil {
		t.Fatal("expected nil policy when enterprise_slug is empty")
	}

	// Apply on a nil policy must be a no-op.
	hdr := http.Header{}
	if tok := p.Apply(context.Background(), hdr, "torvalds", "linux", nil); tok != "" {
		t.Errorf("expected no identity token from nil policy, got %q", tok)
	}
	if got := hdr.Get(enterpriseHeader); got != "" {
		t.Errorf("nil policy must not set the enterprise header, got %q", got)
	}
}

func TestNewEnterprisePolicy_SkipsMalformedEntries(t *testing.T) {
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{Match: []string{"", "a/b/c"}},                               // all malformed → dropped
			{Match: []string{"good-owner"}, Teams: []string{"no-slash"}}, // teams all malformed → dropped
			{Match: []string{"kept"}},
		},
	}, nil, slog.Default())
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
	if len(p.exceptions) != 1 {
		t.Fatalf("expected 1 compiled exception, got %d", len(p.exceptions))
	}
	if p.match("kept", "") == nil {
		t.Error("expected 'kept' to match")
	}
	if p.match("good-owner", "") != nil {
		t.Error("exception with unusable team gate must be dropped, not applied ungated")
	}
}

func TestEnterprisePolicy_Apply_HeaderBehaviour(t *testing.T) {
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{Match: []string{"torvalds", "kubernetes/website"}},
		},
	}, nil, slog.Default())

	tests := []struct {
		name     string
		owner    string
		repo     string
		wantOmit bool
	}{
		{"owner match", "torvalds", "linux", true},
		{"owner match case-insensitive", "Torvalds", "Linux", true},
		{"owner match without repo", "torvalds", "", true},
		{"repo match", "kubernetes", "website", true},
		{"repo match case-insensitive", "Kubernetes", "Website", true},
		{"same org different repo", "kubernetes", "kubernetes", false},
		{"no match", "golang", "go", false},
		{"no target", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := http.Header{}
			// Pre-set a client-supplied value to verify Apply overrides or
			// removes it in both directions.
			hdr.Set(enterpriseHeader, "spoofed")
			tok := p.Apply(context.Background(), hdr, tt.owner, tt.repo, nil)
			if tok != "" {
				t.Errorf("expected no identity token, got %q", tok)
			}
			got := hdr.Get(enterpriseHeader)
			if tt.wantOmit && got != "" {
				t.Errorf("expected header omitted, got %q", got)
			}
			if !tt.wantOmit && got != "acme" {
				t.Errorf("expected header 'acme', got %q", got)
			}
		})
	}
}

func TestEnterprisePolicy_IdentitySubstitution(t *testing.T) {
	src := &fakeIdentitySource{token: "ghs_managed"}
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{
				Match:    []string{"partner/tool"},
				Identity: config.EnterpriseExceptionIdentity{AppRecordID: "app-uuid-1"},
			},
		},
	}, src, slog.Default())

	hdr := http.Header{}
	tok := p.Apply(context.Background(), hdr, "partner", "tool", nil)
	if tok != "ghs_managed" {
		t.Fatalf("expected managed token, got %q", tok)
	}
	if got := hdr.Get(enterpriseHeader); got != "" {
		t.Errorf("expected header omitted on identity substitution, got %q", got)
	}
	if len(src.calls) != 1 {
		t.Fatalf("expected 1 identity call, got %d", len(src.calls))
	}
	call := src.calls[0]
	if call.appRecordID != "app-uuid-1" || call.owner != "partner" {
		t.Errorf("unexpected identity call: %+v", call)
	}
	if len(call.repos) != 1 || call.repos[0] != "tool" {
		t.Errorf("expected token scoped to repo 'tool', got %v", call.repos)
	}
}

func TestEnterprisePolicy_IdentityError_FailsClosed(t *testing.T) {
	src := &fakeIdentitySource{err: context.DeadlineExceeded}
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{
				Match:    []string{"partner"},
				Identity: config.EnterpriseExceptionIdentity{AppRecordID: "app-uuid-1"},
			},
		},
	}, src, slog.Default())

	hdr := http.Header{}
	tok := p.Apply(context.Background(), hdr, "partner", "tool", nil)
	if tok != "" {
		t.Fatalf("expected no token on identity error, got %q", tok)
	}
	if got := hdr.Get(enterpriseHeader); got != "acme" {
		t.Errorf("identity failure must keep the restriction header, got %q", got)
	}
}

func TestEnterprisePolicy_IdentityWithoutRegistry_FailsClosed(t *testing.T) {
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{
				Match:    []string{"partner"},
				Identity: config.EnterpriseExceptionIdentity{AppRecordID: "app-uuid-1"},
			},
		},
	}, nil, slog.Default())

	hdr := http.Header{}
	if tok := p.Apply(context.Background(), hdr, "partner", "tool", nil); tok != "" {
		t.Fatalf("expected no token without identity source, got %q", tok)
	}
	if got := hdr.Get(enterpriseHeader); got != "acme" {
		t.Errorf("expected restriction header kept, got %q", got)
	}
}

// newTeamPolicy builds a policy with one team-gated exception backed by a fake
// identity source and an httptest team-membership API.
func newTeamPolicy(t *testing.T, memberships map[string]string) (*EnterprisePolicy, *int) {
	t.Helper()
	requestCount := new(int)
	teamAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requestCount++
		if r.Header.Get("Authorization") != "Bearer ghs_members" {
			t.Errorf("expected members:read token, got %q", r.Header.Get("Authorization"))
		}
		state, ok := memberships[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"state": state})
	}))
	t.Cleanup(teamAPI.Close)

	src := &fakeIdentitySource{token: "ghs_members"}
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{
				Match: []string{"partner"},
				Teams: []string{"acme-org/oss-contributors"},
			},
		},
	}, src, slog.Default(), WithTeamAPIBaseURL(teamAPI.URL))
	return p, requestCount
}

func TestEnterprisePolicy_TeamGate(t *testing.T) {
	memberships := map[string]string{
		"/orgs/acme-org/teams/oss-contributors/memberships/alice": "active",
		"/orgs/acme-org/teams/oss-contributors/memberships/carol": "pending",
	}

	tests := []struct {
		name     string
		username UsernameFunc
		wantOmit bool
	}{
		{"active member", staticUsername("alice"), true},
		{"non-member", staticUsername("bob"), false},
		{"pending member", staticUsername("carol"), false},
		{"unresolvable identity", staticUsername(""), false},
		{"nil username func", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newTeamPolicy(t, memberships)
			hdr := http.Header{}
			p.Apply(context.Background(), hdr, "partner", "tool", tt.username)
			got := hdr.Get(enterpriseHeader)
			if tt.wantOmit && got != "" {
				t.Errorf("expected header omitted for team member, got %q", got)
			}
			if !tt.wantOmit && got != "acme" {
				t.Errorf("expected restriction header kept, got %q", got)
			}
		})
	}
}

func TestEnterprisePolicy_TeamGate_CachesVerdict(t *testing.T) {
	p, requestCount := newTeamPolicy(t, map[string]string{
		"/orgs/acme-org/teams/oss-contributors/memberships/alice": "active",
	})

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		hdr := http.Header{}
		p.Apply(ctx, hdr, "partner", "tool", staticUsername("alice"))
		if got := hdr.Get(enterpriseHeader); got != "" {
			t.Fatalf("iteration %d: expected header omitted, got %q", i, got)
		}
	}
	if *requestCount != 1 {
		t.Errorf("expected 1 membership API call (cached), got %d", *requestCount)
	}
}

func TestSubstituteAuthHeader(t *testing.T) {
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:gho_orig"))
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_new"))
	tests := []struct {
		name     string
		original string
		want     string
	}{
		{"bearer", "Bearer gho_orig", "Bearer ghs_new"},
		{"token scheme", "token ghp_orig", "token ghs_new"},
		{"basic", basic, wantBasic},
		{"empty", "", "Bearer ghs_new"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := substituteAuthHeader(tt.original, "ghs_new"); got != tt.want {
				t.Errorf("substituteAuthHeader(%q) = %q, want %q", tt.original, got, tt.want)
			}
		})
	}
}

func TestRawTokenFromAuthValue(t *testing.T) {
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_pass"))
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"bearer gho", "Bearer gho_abc", "gho_abc"},
		{"token ghp", "token ghp_abc", "ghp_abc"},
		{"basic token password", basic, "ghs_pass"},
		{"unresolvable", "Bearer ghx_client", ""},
		{"empty", "", ""},
		{"no scheme", "gho_abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rawTokenFromAuthValue(tt.value); got != tt.want {
				t.Errorf("rawTokenFromAuthValue(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// TestForwardRequest_EnterpriseException_HeaderOmitted exercises the API proxy
// path (forwardRequest) end-to-end: a request targeting an excluded repository
// must reach GitHub without the restriction header.
func TestForwardRequest_EnterpriseException_HeaderOmitted(t *testing.T) {
	gh := config.GitHubConfig{
		EnterpriseSlug: "my-enterprise",
		EnterpriseExceptions: []config.EnterpriseException{
			{Match: []string{"torvalds"}},
		},
	}
	ct := &captureTransport{}
	h := &Handler{
		cfg:        &config.Config{GitHub: gh},
		logger:     slog.Default(),
		client:     &http.Client{Transport: ct, Timeout: 5 * time.Second},
		enterprise: NewEnterprisePolicy(gh, nil, slog.Default()),
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost/repos/torvalds/linux/pulls", nil)
	if status := h.forwardRequest(rr, req, "/repos/torvalds/linux/pulls", "Bearer gho_x"); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if _, ok := ct.lastReq.Header[http.CanonicalHeaderKey(enterpriseHeader)]; ok {
		t.Errorf("expected enterprise header omitted, got %q", ct.lastReq.Header.Get(enterpriseHeader))
	}

	// A non-excluded repo on the same handler keeps the header.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "http://localhost/repos/golang/go/pulls", nil)
	if status := h.forwardRequest(rr, req, "/repos/golang/go/pulls", "Bearer gho_x"); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if got := ct.lastReq.Header.Get(enterpriseHeader); got != "my-enterprise" {
		t.Errorf("expected enterprise header 'my-enterprise', got %q", got)
	}
}

// TestForwardPassthrough_EnterpriseException_IdentitySubstituted exercises the
// api.github.com passthrough path with a raw GitHub token: the restriction
// header must be omitted and the Authorization header replaced with the
// managed identity, preserving the caller's auth scheme.
func TestForwardPassthrough_EnterpriseException_IdentitySubstituted(t *testing.T) {
	gh := config.GitHubConfig{
		EnterpriseSlug: "my-enterprise",
		EnterpriseExceptions: []config.EnterpriseException{
			{
				Match:    []string{"partner/tool"},
				Identity: config.EnterpriseExceptionIdentity{AppRecordID: "app-1"},
			},
		},
	}
	src := &fakeIdentitySource{token: "ghs_managed"}
	ct := &captureTransport{}
	h := &Handler{
		cfg:        &config.Config{GitHub: gh},
		logger:     slog.Default(),
		client:     &http.Client{Transport: ct, Timeout: 5 * time.Second},
		enterprise: NewEnterprisePolicy(gh, src, slog.Default()),
	}

	req := httptest.NewRequest("GET", "http://api.github.com/repos/partner/tool/pulls", nil)
	req.Header.Set("Authorization", "token ghp_usertoken")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if _, ok := ct.lastReq.Header[http.CanonicalHeaderKey(enterpriseHeader)]; ok {
		t.Errorf("expected enterprise header omitted, got %q", ct.lastReq.Header.Get(enterpriseHeader))
	}
	if got := ct.lastReq.Header.Get("Authorization"); got != "token ghs_managed" {
		t.Errorf("expected substituted identity 'token ghs_managed', got %q", got)
	}
}

// TestPassthroughHandler_EnterpriseException covers the github.com git
// passthrough: an excluded repository's git path must go upstream without the
// restriction header and with the managed identity as Basic credentials.
func TestPassthroughHandler_EnterpriseException_GitPush(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/partner/tool.git/git-receive-pack":
			if got := r.Header.Get(enterpriseHeader); got != "" {
				t.Errorf("expected enterprise header omitted for excluded repo, got %q", got)
			}
			// The caller's Bearer scheme is preserved; anonymous callers get
			// Basic x-access-token credentials.
			wantAuth := "Bearer ghs_managed"
			if r.Header.Get("X-Test-Anonymous") == "1" {
				wantAuth = basicAuthIdentityHeader("ghs_managed")
			}
			if got := r.Header.Get("Authorization"); got != wantAuth {
				t.Errorf("expected managed credential %q, got %q", wantAuth, got)
			}
		case "/other/repo.git/git-receive-pack":
			if got := r.Header.Get(enterpriseHeader); got != "my-enterprise" {
				t.Errorf("expected enterprise header for non-excluded repo, got %q", got)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer gho_usertoken" {
				t.Errorf("expected caller credential preserved, got %q", got)
			}
		default:
			t.Errorf("unexpected upstream path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	src := &fakeIdentitySource{token: "ghs_managed"}
	policy := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "my-enterprise",
		EnterpriseExceptions: []config.EnterpriseException{
			{
				Match:    []string{"partner/tool"},
				Identity: config.EnterpriseExceptionIdentity{AppRecordID: "app-1"},
			},
		},
	}, src, slog.Default())
	handler := NewPassthroughHandler(upstream.URL, nil, policy, nil, nil, tlsTransport(upstream))

	for _, path := range []string{"/partner/tool.git/git-receive-pack", "/other/repo.git/git-receive-pack"} {
		req := httptest.NewRequest("POST", "http://github.com"+path, nil)
		req.Header.Set("Authorization", "Bearer gho_usertoken")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rr.Code)
		}
	}

	// Anonymous request to the excluded repo: the managed identity is
	// injected as Basic x-access-token credentials.
	req := httptest.NewRequest("POST", "http://github.com/partner/tool.git/git-receive-pack", nil)
	req.Header.Set("X-Test-Anonymous", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("anonymous: expected 200, got %d", rr.Code)
	}
}
