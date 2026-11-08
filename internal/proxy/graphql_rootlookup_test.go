package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// scopeStrings renders requiredScopes as sorted "perm:level" strings.
func scopeStrings(reqs []scopeRequirement) []string {
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.permission+":"+r.level)
	}
	sort.Strings(out)
	return out
}

func gqlBody(t *testing.T, query string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestAnalyzeGraphQLRequest_RootLookupTypeConditions covers #324: the root
// lookups node, nodes, resource and search are gated on the type
// conditions of the fragments beneath them.
func TestAnalyzeGraphQLRequest_RootLookupTypeConditions(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		wantScopes  []string
		wantUnknown bool
	}{
		{"nodes issue", `{ nodes(ids: ["I_1"]) { ... on Issue { title body } } }`, []string{"issues:read"}, false},
		{"nodes pull request", `{ nodes(ids: ["PR_1"]) { ... on PullRequest { title body } } }`, []string{"pull_requests:read"}, false},
		{"nodes discussion", `{ nodes(ids: ["D_1"]) { ... on Discussion { title body } } }`, []string{"discussions:read"}, false},
		{"node issue", `{ node(id: "I_1") { ... on Issue { title body } } }`, []string{"issues:read"}, false},
		{"node pull request", `{ node(id: "PR_1") { ... on PullRequest { title body } } }`, []string{"pull_requests:read"}, false},
		{"node discussion", `{ node(id: "D_1") { ... on Discussion { title body } } }`, []string{"discussions:read"}, false},
		{"resource issue", `{ resource(url: "https://github.com/o/r/issues/1") { ... on Issue { title body } } }`, []string{"issues:read"}, false},
		{"resource pull request", `{ resource(url: "https://github.com/o/r/pull/1") { ... on PullRequest { title body } } }`, []string{"pull_requests:read"}, false},
		{"resource discussion", `{ resource(url: "https://github.com/o/r/discussions/1") { ... on Discussion { title body } } }`, []string{"discussions:read"}, false},
		{"two fragments", `{ nodes(ids: ["a"]) { ... on Issue { body } ... on PullRequest { body } } }`, []string{"issues:read", "pull_requests:read"}, false},
		{"repository", `{ node(id: "R_1") { ... on Repository { name } } }`, []string{"metadata:read"}, false},
		{"commit", `{ node(id: "C_1") { ... on Commit { message } } }`, []string{"contents:read"}, false},
		{"release", `{ node(id: "RE_1") { ... on Release { name } } }`, []string{"contents:read"}, false},
		{"check run", `{ node(id: "CR_1") { ... on CheckRun { name } } }`, []string{"checks:read"}, false},
		{"check suite", `{ node(id: "CS_1") { ... on CheckSuite { conclusion } } }`, []string{"checks:read"}, false},
		{"status context", `{ node(id: "SC_1") { ... on StatusContext { state } } }`, []string{"statuses:read"}, false},
		{"user", `{ node(id: "U_1") { ... on User { login } } }`, []string{"metadata:read"}, false},
		{"organization", `{ node(id: "O_1") { ... on Organization { login } } }`, []string{"metadata:read"}, false},
		{"bot", `{ node(id: "B_1") { ... on Bot { login } } }`, []string{"metadata:read"}, false},
		{"team", `{ node(id: "T_1") { ... on Team { name } } }`, []string{"metadata:read"}, false},
		{"named fragment", `query { nodes(ids: ["a"]) { ...F } } fragment F on Issue { body }`, []string{"issues:read"}, false},
		{"named fragment via fragment", `query { nodes(ids: ["a"]) { ...G } } fragment G on Issue { ...H } fragment H on Issue { body }`, []string{"issues:read"}, false},
		{"untyped inline fragment wrapping typed", `{ nodes(ids: ["a"]) { ... @include(if: true) { ... on Issue { body } } } }`, []string{"issues:read"}, false},
		{"search issue", `{ search(query: "x", type: ISSUE, first: 1) { issueCount nodes { ... on Issue { body } } } }`, []string{"issues:read"}, false},
		{"search edges", `{ search(query: "x", type: ISSUE, first: 1) { edges { cursor node { ... on PullRequest { body } } } pageInfo { hasNextPage } } }`, []string{"pull_requests:read"}, false},

		{"nodes no fragment", `{ nodes(ids: ["a"]) { id } }`, nil, true},
		{"node no fragment typename only", `{ node(id: "a") { __typename } }`, nil, true},
		{"unmapped type condition", `{ nodes(ids: ["a"]) { ... on Gist { description } } }`, nil, true},
		{"interface type condition", `{ nodes(ids: ["a"]) { ... on Node { ... on Issue { body } } } }`, []string{"issues:read"}, true},
		{"direct field beside fragment", `{ nodes(ids: ["a"]) { body ... on Issue { title } } }`, []string{"issues:read"}, true},
		{"named fragment unmapped", `query { nodes(ids: ["a"]) { ...F } } fragment F on Gist { description }`, nil, true},
		{"search no fragment", `{ search(query: "x", type: ISSUE, first: 1) { nodes { __typename } } }`, nil, true},
		{"search counts only", `{ search(query: "x", type: REPOSITORY, first: 1) { repositoryCount } }`, nil, true},
		{"search unknown field", `{ search(query: "x", type: ISSUE, first: 1) { secretThing { a } } }`, nil, true},
		{"undefined named fragment", `{ nodes(ids: ["a"]) { ...Missing } }`, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := analyzeGraphQLRequest([]byte(gqlBody(t, tc.query)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotScopes := scopeStrings(got.requiredScopes)
			want := tc.wantScopes
			if want == nil {
				want = []string{}
			}
			if strings.Join(gotScopes, ",") != strings.Join(want, ",") {
				t.Errorf("requiredScopes = %v, want %v", gotScopes, want)
			}
			if (len(got.unknownFields) > 0) != tc.wantUnknown {
				t.Errorf("unknownFields = %v, wantUnknown %v", got.unknownFields, tc.wantUnknown)
			}
			if len(got.crossRepoFields) == 0 {
				t.Errorf("root lookup must stay cross-repo for repo-scoped tokens")
			}
		})
	}
}

// TestAnalyzeGraphQLRequest_NestedNodesUnchanged confirms Connection.nodes
// keeps its pagination-helper behaviour.
func TestAnalyzeGraphQLRequest_NestedNodesUnchanged(t *testing.T) {
	q := `{ repository(owner: "o", name: "r") { issues(first: 1) { nodes { title } edges { cursor } } } }`
	got, err := analyzeGraphQLRequest([]byte(gqlBody(t, q)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.unknownFields) != 0 || len(got.crossRepoFields) != 0 {
		t.Fatalf("nested nodes changed: unknown=%v cross=%v", got.unknownFields, got.crossRepoFields)
	}
	if s := scopeStrings(got.requiredScopes); strings.Join(s, ",") != "issues:read" {
		t.Fatalf("scopes = %v", s)
	}
}

func postGraphQL(t *testing.T, h http.Handler, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(gqlBody(t, query)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestServeHTTP_GraphQL_RootLookupFragments is the handler-level matrix
// from #324.
func TestServeHTTP_GraphQL_RootLookupFragments(t *testing.T) {
	queries := map[string]string{
		"nodes Issue":         `{ nodes(ids: ["I_1"]) { ... on Issue { title body } } }`,
		"nodes PullRequest":   `{ nodes(ids: ["PR_1"]) { ... on PullRequest { title body } } }`,
		"nodes Discussion":    `{ nodes(ids: ["D_1"]) { ... on Discussion { title body } } }`,
		"node Issue":          `{ node(id: "I_1") { ... on Issue { title body } } }`,
		"resource Issue":      `{ resource(url: "https://github.com/o/r/issues/1") { ... on Issue { title body } } }`,
		"nodes named Issue":   `query { nodes(ids: ["I_1"]) { ...F } } fragment F on Issue { body }`,
		"nodes nested Issue":  `{ nodes(ids: ["I_1"]) { ... @include(if: true) { ... on Issue { body } } } }`,
		"nodes no fragment":   `{ nodes(ids: ["I_1"]) { id } }`,
		"nodes unmapped Gist": `{ nodes(ids: ["G_1"]) { ... on Gist { description } } }`,
	}
	tests := []struct {
		query  string
		scopes map[string]string
		want   int
	}{
		{"nodes Issue", map[string]string{"metadata": "read"}, http.StatusForbidden},
		{"nodes Issue", map[string]string{"issues": "read"}, http.StatusOK},
		{"nodes PullRequest", map[string]string{"metadata": "read"}, http.StatusForbidden},
		{"nodes PullRequest", map[string]string{"issues": "read"}, http.StatusForbidden},
		{"nodes PullRequest", map[string]string{"pull_requests": "read"}, http.StatusOK},
		{"nodes Discussion", map[string]string{"metadata": "read"}, http.StatusForbidden},
		{"nodes Discussion", map[string]string{"issues": "read"}, http.StatusForbidden},
		{"nodes Discussion", map[string]string{"discussions": "read"}, http.StatusOK},
		{"node Issue", map[string]string{"metadata": "read"}, http.StatusForbidden},
		{"node Issue", map[string]string{"issues": "read"}, http.StatusOK},
		{"resource Issue", map[string]string{"metadata": "read"}, http.StatusForbidden},
		{"resource Issue", map[string]string{"issues": "read"}, http.StatusOK},
		{"nodes named Issue", map[string]string{"metadata": "read"}, http.StatusForbidden},
		{"nodes named Issue", map[string]string{"issues": "read"}, http.StatusOK},
		{"nodes nested Issue", map[string]string{"metadata": "read"}, http.StatusForbidden},
		{"nodes nested Issue", map[string]string{"issues": "read"}, http.StatusOK},
		{"nodes no fragment", map[string]string{"issues": "read"}, http.StatusForbidden},
		{"nodes unmapped Gist", map[string]string{"issues": "read"}, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.query+"/"+scopeKey(tc.scopes), func(t *testing.T) {
			h, tok := newScopeOnlyHandler(t, tc.scopes)
			rr := postGraphQL(t, h, tok, queries[tc.query])
			if rr.Code != tc.want {
				t.Fatalf("got %d, want %d; body: %s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func scopeKey(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+":"+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// TestServeHTTP_GraphQL_RepoScoped_RootLookupDenied keeps the repo-scoped
// column of #324: cross-repo root lookups are denied even with a mapped
// fragment.
func TestServeHTTP_GraphQL_RepoScoped_RootLookupDenied(t *testing.T) {
	for _, q := range []string{
		`{ nodes(ids: ["I_1"]) { ... on Issue { title body } } }`,
		`{ node(id: "I_1") { ... on Issue { title body } } }`,
		`{ resource(url: "https://github.com/o/r/issues/1") { ... on Issue { title body } } }`,
	} {
		h, tok := newScopedHandler(t, "goodtune/ghp", map[string]string{"issues": "read"})
		rr := postGraphQL(t, h, tok, q)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s: got %d, want 403; body: %s", q, rr.Code, rr.Body.String())
		}
	}
}

// TestAnalyzeGraphQLRequest_RootLookupNestedFragmentsGated: a fragment
// nested inside a mapped root-lookup fragment must equal the enclosing type
// or be gated itself. GitHub's validator rejects these non-overlapping
// spreads today, but the analyzer must not rely on that.
func TestAnalyzeGraphQLRequest_RootLookupNestedFragmentsGated(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		wantScopes  []string
		wantUnknown bool
	}{
		{"named Issue inside Bot", `query { node(id: "a") { ... on Bot { ...F } } } fragment F on Issue { body }`, []string{"issues:read", "metadata:read"}, false},
		{"PullRequest inside Issue", `{ node(id: "a") { ... on Issue { ... on PullRequest { body } } } }`, []string{"issues:read", "pull_requests:read"}, false},
		{"same type nested", `{ node(id: "a") { ... on Issue { ... on Issue { body } } } }`, []string{"issues:read"}, false},
		{"untyped nested", `{ node(id: "a") { ... on Issue { ... @include(if: true) { body } } } }`, []string{"issues:read"}, false},
		{"interface nested", `{ node(id: "a") { ... on Issue { ... on Closable { closed } } } }`, []string{"issues:read"}, true},
		{"unmapped nested", `{ node(id: "a") { ... on Issue { ... on Gist { description } } } }`, []string{"issues:read"}, true},
		{"deep under untyped", `{ node(id: "a") { ... on Bot { ... { ... on Issue { body } } } } }`, []string{"issues:read", "metadata:read"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := analyzeGraphQLRequest([]byte(gqlBody(t, tc.query)))
			if err != nil {
				t.Fatal(err)
			}
			if s := strings.Join(scopeStrings(got.requiredScopes), ","); s != strings.Join(tc.wantScopes, ",") {
				t.Errorf("requiredScopes = %s, want %v", s, tc.wantScopes)
			}
			if (len(got.unknownFields) > 0) != tc.wantUnknown {
				t.Errorf("unknownFields = %v, wantUnknown %v", got.unknownFields, tc.wantUnknown)
			}
		})
	}
}

func TestServeHTTP_GraphQL_RootLookupNestedFragmentProbes(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		scopes map[string]string
	}{
		{"Bot then named Issue, metadata:read", `query { node(id: "a") { ... on Bot { ...F } } } fragment F on Issue { body }`, map[string]string{"metadata": "read"}},
		{"Issue then PullRequest, issues:read", `{ node(id: "a") { ... on Issue { ... on PullRequest { body } } } }`, map[string]string{"issues": "read"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, tok := newScopeOnlyHandler(t, tc.scopes)
			rr := postGraphQL(t, h, tok, tc.query)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("got %d, want 403; body: %s", rr.Code, rr.Body.String())
			}
		})
	}
}
