package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
	"github.com/prometheus/client_golang/prometheus"
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

// fakeViewerResolver returns a UsernameResolver whose GraphQL viewer endpoint
// is a local httptest server that always answers with the given login.
func fakeViewerResolver(t *testing.T, login string) *UsernameResolver {
	t.Helper()
	viewer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"viewer": map[string]string{"login": login}},
		})
	}))
	t.Cleanup(viewer.Close)
	return NewUsernameResolver(nil, slog.Default(), WithGraphQLURL(viewer.URL))
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
	if tok := p.Apply(context.Background(), hdr, "torvalds", "linux", nil, ""); tok != "" {
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
			tok := p.Apply(context.Background(), hdr, tt.owner, tt.repo, nil, "")
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

func TestEnterprisePolicy_Match_RepoRuleTakesPrecedenceOverOwnerRule(t *testing.T) {
	// An ungated owner-wide rule listed first must not shadow a stricter
	// owner/repo rule listed later: the repository rule (here team-gated)
	// wins on specificity, so a non-member keeps the restriction header for
	// the sensitive repo while still enjoying the broad rule elsewhere.
	src := &fakeIdentitySource{token: "ghs_members"}
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{Match: []string{"partner-org"}},
			{Match: []string{"partner-org/sensitive-repo"}, Teams: []string{"acme-org/trusted"}},
		},
	}, src, slog.Default())

	// Non-member targeting the sensitive repo: the team-gated repo rule
	// applies (not the broad owner rule) and fails closed.
	hdr := http.Header{}
	p.Apply(context.Background(), hdr, "partner-org", "sensitive-repo", staticUsername(""), "")
	if got := hdr.Get(enterpriseHeader); got != "acme" {
		t.Errorf("sensitive repo: expected restriction header kept for non-member, got %q", got)
	}

	// The broad owner rule still covers every other repository ungated.
	hdr = http.Header{}
	p.Apply(context.Background(), hdr, "partner-org", "other-repo", nil, "")
	if got := hdr.Get(enterpriseHeader); got != "" {
		t.Errorf("other repo: expected header omitted by owner rule, got %q", got)
	}
}

func TestEnterprisePolicy_EmptyIdentityToken_FailsClosed(t *testing.T) {
	// An identity source returning ("", nil) must be treated as an identity
	// error: the restriction header stays on and the caller's credential is
	// never forwarded with the header omitted.
	src := &fakeIdentitySource{token: ""}
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
	if tok := p.Apply(context.Background(), hdr, "partner", "tool", staticUsername("alice"), ""); tok != "" {
		t.Fatalf("expected no token, got %q", tok)
	}
	if got := hdr.Get(enterpriseHeader); got != "acme" {
		t.Errorf("expected restriction header kept on empty identity token, got %q", got)
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
	tok := p.Apply(context.Background(), hdr, "partner", "tool", staticUsername("alice"), "")
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
	tok := p.Apply(context.Background(), hdr, "partner", "tool", staticUsername("alice"), "")
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
	if tok := p.Apply(context.Background(), hdr, "partner", "tool", staticUsername("alice"), ""); tok != "" {
		t.Fatalf("expected no token without identity source, got %q", tok)
	}
	if got := hdr.Get(enterpriseHeader); got != "acme" {
		t.Errorf("expected restriction header kept, got %q", got)
	}
}

func TestEnterprisePolicy_IdentityAnonymousCaller_FailsClosed(t *testing.T) {
	// Identity substitution must never fire for a caller whose identity
	// cannot be resolved — otherwise anonymous clients could act as the
	// managed App on the excepted target.
	src := &fakeIdentitySource{token: "ghs_managed"}
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{
				Match:    []string{"partner"},
				Identity: config.EnterpriseExceptionIdentity{AppRecordID: "app-uuid-1"},
			},
		},
	}, src, slog.Default())

	for name, fn := range map[string]UsernameFunc{
		"nil username func":     nil,
		"unresolvable identity": staticUsername(""),
	} {
		t.Run(name, func(t *testing.T) {
			hdr := http.Header{}
			if tok := p.Apply(context.Background(), hdr, "partner", "tool", fn, ""); tok != "" {
				t.Fatalf("expected no token for unidentified caller, got %q", tok)
			}
			if got := hdr.Get(enterpriseHeader); got != "acme" {
				t.Errorf("expected restriction header kept, got %q", got)
			}
		})
	}
	if len(src.calls) != 0 {
		t.Errorf("expected no identity minting for unidentified callers, got %d calls", len(src.calls))
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
			p.Apply(context.Background(), hdr, "partner", "tool", tt.username, "")
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
		p.Apply(ctx, hdr, "partner", "tool", staticUsername("alice"), "")
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
		{"fine-grained pat", "Bearer github_pat_abc", "github_pat_abc"},
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
	if status := h.forwardRequest(rr, req, "/repos/torvalds/linux/pulls", "Bearer gho_x", time.Now(), ""); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if _, ok := ct.lastReq.Header[http.CanonicalHeaderKey(enterpriseHeader)]; ok {
		t.Errorf("expected enterprise header omitted, got %q", ct.lastReq.Header.Get(enterpriseHeader))
	}

	// A non-excluded repo on the same handler keeps the header.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "http://localhost/repos/golang/go/pulls", nil)
	if status := h.forwardRequest(rr, req, "/repos/golang/go/pulls", "Bearer gho_x", time.Now(), ""); status != http.StatusOK {
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
		cfg:              &config.Config{GitHub: gh},
		logger:           slog.Default(),
		client:           &http.Client{Transport: ct, Timeout: 5 * time.Second},
		usernameResolver: fakeViewerResolver(t, "alice"),
		enterprise:       NewEnterprisePolicy(gh, src, slog.Default()),
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

	// An anonymous request to the same excepted target must NOT receive the
	// managed identity — the restriction header stays on and no Authorization
	// is injected.
	req = httptest.NewRequest("GET", "http://api.github.com/repos/partner/tool/pulls", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("anonymous: expected 200, got %d", rr.Code)
	}
	if got := ct.lastReq.Header.Get(enterpriseHeader); got != "my-enterprise" {
		t.Errorf("anonymous: expected restriction header kept, got %q", got)
	}
	if got := ct.lastReq.Header.Get("Authorization"); got != "" {
		t.Errorf("anonymous: expected no Authorization injected, got %q", got)
	}
}

// TestPassthroughHandler_EnterpriseException covers the github.com git
// passthrough: an excluded repository's git path must go upstream without the
// restriction header and with the managed identity as Basic credentials.
func TestPassthroughHandler_EnterpriseException_GitPush(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/partner/tool.git/git-receive-pack":
			if r.Header.Get("X-Test-Anonymous") == "1" {
				// Anonymous callers must not receive the managed identity:
				// the restriction header stays on and no credential is added.
				if got := r.Header.Get(enterpriseHeader); got != "my-enterprise" {
					t.Errorf("anonymous: expected restriction header kept, got %q", got)
				}
				if got := r.Header.Get("Authorization"); got != "" {
					t.Errorf("anonymous: expected no Authorization injected, got %q", got)
				}
				break
			}
			if got := r.Header.Get(enterpriseHeader); got != "" {
				t.Errorf("expected enterprise header omitted for excluded repo, got %q", got)
			}
			// The caller's Bearer scheme is preserved on substitution.
			if got := r.Header.Get("Authorization"); got != "Bearer ghs_managed" {
				t.Errorf("expected managed credential, got %q", got)
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
	inner := NewPassthroughHandler(upstream.URL, nil, nil, tlsTransport(upstream))
	handler := NewScopedPassthroughHandler(inner, nil, nil, fakeViewerResolver(t, "alice"), policy, slog.Default())

	for _, path := range []string{"/partner/tool.git/git-receive-pack", "/other/repo.git/git-receive-pack"} {
		req := httptest.NewRequest("POST", "http://github.com"+path, nil)
		req.Header.Set("Authorization", "Bearer gho_usertoken")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rr.Code)
		}
	}

	// Anonymous request to the excluded repo: identity substitution must
	// fail closed (no credential injected, restriction header kept).
	req := httptest.NewRequest("POST", "http://github.com/partner/tool.git/git-receive-pack", nil)
	req.Header.Set("X-Test-Anonymous", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("anonymous: expected 200, got %d", rr.Code)
	}
}

// TestServeHTTP_BorderPolicy_BlocksFineGrainedPAT verifies that recognising
// github_pat_ as a resolvable credential did not open a border-policy bypass:
// with block.github_pat enabled, a fine-grained PAT is rejected before it
// egresses to GitHub.
func TestServeHTTP_BorderPolicy_BlocksFineGrainedPAT(t *testing.T) {
	ct := &captureTransport{}
	h := &Handler{
		cfg:    &config.Config{Block: config.BlockConfig{GithubPat: true}},
		logger: slog.Default(),
		client: &http.Client{Transport: ct, Timeout: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://api.github.com/repos/org/repo", nil)
	req.Header.Set("Authorization", "Bearer github_pat_11ABCDEF0123456789")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked fine-grained PAT, got %d", rr.Code)
	}
	if ct.lastReq != nil {
		t.Error("blocked request must not reach upstream")
	}
}

func TestEnterprisePolicy_TeamGate_CoalescesConcurrentLookups(t *testing.T) {
	// A burst of concurrent requests for the same (org, team, user) after
	// cache expiry must trigger exactly one members:read token mint and one
	// membership API request; the other callers wait on the leader's verdict.
	var apiCalls atomic.Int32
	teamAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		time.Sleep(100 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]string{"state": "active"})
	}))
	t.Cleanup(teamAPI.Close)

	src := &fakeIdentitySource{token: "ghs_members"}
	p := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "acme",
		EnterpriseExceptions: []config.EnterpriseException{
			{Match: []string{"partner"}, Teams: []string{"acme-org/oss"}},
		},
	}, src, slog.Default(), WithTeamAPIBaseURL(teamAPI.URL))

	const workers = 8
	var wg sync.WaitGroup
	results := make([]string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hdr := http.Header{}
			p.Apply(context.Background(), hdr, "partner", "tool", staticUsername("alice"), "")
			results[i] = hdr.Get(enterpriseHeader)
		}(i)
	}
	wg.Wait()

	for i, got := range results {
		if got != "" {
			t.Errorf("worker %d: expected header omitted for team member, got %q", i, got)
		}
	}
	if n := apiCalls.Load(); n != 1 {
		t.Errorf("expected 1 membership API call for concurrent burst, got %d", n)
	}
	src.mu.Lock()
	identityCalls := len(src.calls)
	src.mu.Unlock()
	if identityCalls != 1 {
		t.Errorf("expected 1 members:read token mint for concurrent burst, got %d", identityCalls)
	}
}

// enterpriseStageSampleCount returns the observation count of the
// enterprise_exception decision stage histogram for the given token type.
func enterpriseStageSampleCount(t *testing.T, tokenType string) uint64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "ghp_proxy_decision_duration_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["stage"] == "enterprise_exception" && labels["token_type"] == tokenType {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

// TestScopedPassthrough_EnterpriseStage_LabelsProxyTokenType drives the real
// production chain (scoped handler wrapping the reverse proxy) with a ghx_
// token and asserts the enterprise_exception stage is labeled with the
// managed token type rather than "unknown" — the scoped handler evaluates the
// policy before Authorization is rewritten out of client-token form.
func TestScopedPassthrough_EnterpriseStage_LabelsProxyTokenType(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(enterpriseHeader); got != "" {
			t.Errorf("expected enterprise header omitted for excluded repo, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	policy := NewEnterprisePolicy(config.GitHubConfig{
		EnterpriseSlug: "my-enterprise",
		EnterpriseExceptions: []config.EnterpriseException{
			{Match: []string{"partner/tool"}},
		},
	}, nil, slog.Default())

	inner := NewPassthroughHandler(upstream.URL, nil, nil, tlsTransport(upstream))
	handler, ghxToken := newScopedPassthroughWithPolicy(t, inner, policy)

	before := enterpriseStageSampleCount(t, "proxy")

	req := httptest.NewRequest("POST", "http://github.com/partner/tool.git/git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer "+ghxToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	after := enterpriseStageSampleCount(t, "proxy")
	if after-before != 1 {
		t.Errorf("expected enterprise_exception stage observed once with token_type=proxy, got %d", after-before)
	}
}

// newScopedPassthroughWithPolicy builds a scoped passthrough handler over the
// given inner handler with the given enterprise policy, backed by a real
// token.Service, and returns the handler plus a plaintext open-scoped ghx_
// token.
func newScopedPassthroughWithPolicy(t *testing.T, inner http.Handler, policy *EnterprisePolicy) (http.Handler, string) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()

	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	user := &database.User{GitHubID: 1, GitHubUsername: "testuser", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	encAccess, err := enc.Encrypt("gho_realgithubtoken")
	if err != nil {
		t.Fatal(err)
	}
	gt := &database.GitHubToken{
		UserID:                user.ID,
		AccessToken:           encAccess,
		RefreshToken:          "enc_refresh",
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
	}
	if err := store.UpsertGitHubToken(ctx, gt); err != nil {
		t.Fatal(err)
	}

	tokenSvc := token.NewService(store, 7*24*time.Hour, false)
	result, err := tokenSvc.Create(ctx, token.CreateRequest{
		UserID:        user.ID,
		GitHubTokenID: gt.ID,
		Duration:      24 * time.Hour,
		SessionID:     "enterprise-stage-session",
	})
	if err != nil {
		t.Fatal(err)
	}

	resolver := NewProxyTokenResolver(tokenSvc, store, enc, nil)
	handler := NewScopedPassthroughHandler(inner, tokenSvc, resolver, nil, policy, slog.Default())
	return handler, result.Token
}

func TestEnterprisePolicy_SetTransportNilSafe(t *testing.T) {
	// NewEnterprisePolicy returns nil when the feature is disabled; the
	// server calls SetTransport unconditionally, so it must be nil-safe.
	var p *EnterprisePolicy
	p.SetTransport(http.DefaultTransport)

	disabled := NewEnterprisePolicy(config.GitHubConfig{}, nil, nil)
	if disabled != nil {
		t.Fatalf("expected nil policy when enterprise_slug is empty, got %+v", disabled)
	}
	disabled.SetTransport(http.DefaultTransport)

	// Enabled policy without identity source: teams is nil, still a no-op.
	enabled := NewEnterprisePolicy(config.GitHubConfig{EnterpriseSlug: "corp"}, nil, nil)
	if enabled == nil {
		t.Fatal("expected non-nil policy when enterprise_slug is set")
	}
	enabled.SetTransport(http.DefaultTransport)
}
