package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/database"
)

// TestGraphQLVerdict_CrossRepoSubtrees covers the metadata-only subtree rule
// (#339), the parent-aware issues/pullRequests rule (#340) and the
// introspection-only exemption (#342) for repository-restricted tokens, and
// checks that permission-only tokens are unaffected.
func TestGraphQLVerdict_CrossRepoSubtrees(t *testing.T) {
	repoA := tokenScopeInfo{Repos: []string{"o/r"}}
	permRO := tokenScopeInfo{Scopes: database.Scopes{
		"contents": "read", "issues": "read", "pull_requests": "read", "metadata": "read",
	}}
	const pin = `repository(owner:"o",name:"r")`

	tests := []struct {
		name     string
		si       tokenScopeInfo
		query    string
		want     string
		wantMsg  string
		wantRepo string
	}{
		// #339 metadata-only subtrees.
		{"headRepository metadata allowed", repoA, `{` + pin + `{pullRequest(number:1){headRepository{id name nameWithOwner url owner{login}}}}}`, reasonAllow, "", "o/r"},
		{"headRepositoryOwner metadata allowed", repoA, `{` + pin + `{pullRequest(number:1){headRepositoryOwner{id login ...on User{name}}}}}`, reasonAllow, "", "o/r"},
		{"headRepository issues denied", repoA, `{` + pin + `{pullRequest(number:1){headRepository{issues(first:1){nodes{body}}}}}}`, reasonCrossRepo, "headRepository.issues", ""},
		{"headRepository object denied", repoA, `{` + pin + `{pullRequest(number:1){headRepository{object(expression:"HEAD:README.md"){id}}}}}`, reasonCrossRepo, "headRepository.object", ""},
		{"headRepository refs denied", repoA, `{` + pin + `{pullRequest(number:1){headRepository{defaultBranchRef{name} refs(first:1,refPrefix:"refs/heads/"){nodes{name}}}}}}`, reasonCrossRepo, "headRepository.refs", ""},
		{"headRepository nested in fragment denied", repoA, `{` + pin + `{pullRequest(number:1){headRepository{...F}}}} fragment F on Repository{pullRequests(first:1){nodes{body}}}`, reasonCrossRepo, "headRepository.pullRequests", ""},
		{"headRepositoryOwner user issues denied", repoA, `{` + pin + `{pullRequest(number:1){headRepositoryOwner{...on User{issues(first:1){nodes{body}}}}}}}`, reasonCrossRepo, "headRepositoryOwner.issues", ""},
		{"Repository.parent metadata allowed", repoA, `{` + pin + `{parent{name nameWithOwner owner{login} url}}}`, reasonAllow, "", "o/r"},
		{"Repository.parent issues denied", repoA, `{` + pin + `{parent{issues(first:1){nodes{body}}}}}`, reasonCrossRepo, "parent.issues", ""},
		{"Issue.parent gh shape allowed", repoA, `{` + pin + `{issue(number:1){parent{id number title url state repository{nameWithOwner}}}}}`, reasonAllow, "", "o/r"},
		{"Issue.parent body denied", repoA, `{` + pin + `{issue(number:1){parent{body}}}}`, reasonCrossRepo, "parent.body", ""},
		{"Issue.parent comments denied", repoA, `{` + pin + `{issue(number:1){parent{comments(first:1){nodes{body}}}}}}`, reasonCrossRepo, "parent.comments", ""},
		{"subIssues gh shape allowed", repoA, `{` + pin + `{issue(number:1){subIssues(first:100){nodes{id number title url state repository{nameWithOwner}} totalCount}}}}`, reasonAllow, "", "o/r"},
		{"subIssues body denied", repoA, `{` + pin + `{issue(number:1){subIssues(first:1){nodes{body}}}}}`, reasonCrossRepo, "subIssues.body", ""},
		{"blockedBy body denied", repoA, `{` + pin + `{issue(number:1){blockedBy(first:1){nodes{body}}}}}`, reasonCrossRepo, "blockedBy.body", ""},
		{"blocking body denied", repoA, `{` + pin + `{issue(number:1){blocking(first:1){nodes{body}}}}}`, reasonCrossRepo, "blocking.body", ""},
		{"perm-only headRepository issues still scope-checked", permRO, `{` + pin + `{pullRequest(number:1){headRepository{issues(first:1){nodes{body}}}}}}`, reasonAllow, "", "o/r"},

		// #340 parent-aware issues/pullRequests.
		{"issues under pinned repository allowed", repoA, `{` + pin + `{issues(first:1){nodes{body}}}}`, reasonAllow, "", "o/r"},
		{"pullRequests under pinned repository fragment allowed", repoA, `{` + pin + `{...on Repository{pullRequests(first:1){nodes{body}}}}}`, reasonAllow, "", "o/r"},
		{"author user issues denied", repoA, `{` + pin + `{issue(number:1){author{...on User{issues(first:1){nodes{body}}}}}}}`, reasonCrossRepo, "author.issues", ""},
		{"author user pullRequests denied", repoA, `{` + pin + `{issue(number:1){author{...on User{pullRequests(first:1){nodes{body}}}}}}}`, reasonCrossRepo, "author.pullRequests", ""},
		{"viewer issues beside pinned repository denied", repoA, `{` + pin + `{name} viewer{issues(first:1){nodes{body}}}}`, reasonCrossRepo, "viewer.issues", ""},
		{"assignees user pullRequests denied", repoA, `{` + pin + `{issue(number:1){assignees(first:1){nodes{pullRequests(first:1){nodes{body}}}}}}}`, reasonCrossRepo, "nodes.pullRequests", ""},
		{"owner user pullRequests denied", repoA, `{` + pin + `{owner{...on User{pullRequests(first:1){nodes{body}}}}}}`, reasonCrossRepo, "owner.pullRequests", ""},
		{"user commitComments denied", repoA, `{` + pin + `{name} user(login:"x"){commitComments(first:1){nodes{body}}}}`, reasonCrossRepo, "user.commitComments", ""},
		{"Issue.repository issues denied", repoA, `{` + pin + `{issue(number:1){repository{issues(first:1){nodes{body}}}}}}`, reasonCrossRepo, "repository.issues", ""},
		{"perm-only viewer issues allowed", permRO, `{viewer{issues(first:1){nodes{body}}}}`, reasonAllow, "", ""},

		// #342 introspection-only operations.
		{"PullRequest_fields2 allowed", repoA, `query PullRequest_fields2 { WorkflowRun: __type(name: "WorkflowRun") { fields(includeDeprecated: true) { name } } }`, reasonAllow, "", ""},
		{"Release_fields allowed", repoA, `query Release_fields{Release: __type(name: "Release"){fields{name}}}`, reasonAllow, "", ""},
		{"schema with unmapped child still unmapped", repoA, `{__typename __schema{queryType{name}}}`, reasonUnmapped, "queryType", ""},
		{"typename only allowed", repoA, `{__typename}`, reasonAllow, "", ""},
		{"introspection via root fragment allowed", repoA, `query{...F} fragment F on Query{__type(name:"X"){name}}`, reasonAllow, "", ""},
		{"introspection plus viewer denied", repoA, `{__type(name:"X"){name} viewer{login}}`, reasonNoRepoRef, "must reference repository(owner, name)", ""},
		{"introspection plus other repo denied", repoA, `{__type(name:"X"){name} repository(owner:"o",name:"other"){name}}`, reasonRepoNotAllowed, "o/other", "o/other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"query": tt.query})
			if err != nil {
				t.Fatal(err)
			}
			d := graphQLVerdict(body, tt.si)
			if d.Reason != tt.want {
				t.Fatalf("Reason = %q, want %q (msg %q)", d.Reason, tt.want, d.Message)
			}
			if !strings.Contains(d.Message, tt.wantMsg) {
				t.Errorf("Message = %q, want substring %q", d.Message, tt.wantMsg)
			}
			if d.Repo != tt.wantRepo {
				t.Errorf("Repo = %q, want %q", d.Repo, tt.wantRepo)
			}
		})
	}
}

// TestAnalyzeGraphQLRequest_MetadataOnlySubtreeKeepsScope checks that the
// metadata-only rule adds a cross-repo entry without dropping the scope the
// subtree field and its children require.
func TestAnalyzeGraphQLRequest_MetadataOnlySubtreeKeepsScope(t *testing.T) {
	body := `{"query":"{ repository(owner:\"o\",name:\"r\"){ pullRequest(number:1){ headRepository{ issues(first:1){ nodes{ body } } } } } }"}`
	a, err := analyzeGraphQLRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !a.satisfiedBy(database.Scopes{"pull_requests": "read", "issues": "read"}) {
		t.Errorf("expected pull_requests:read + issues:read to satisfy, required %v", a.requiredScopes)
	}
	if a.satisfiedBy(database.Scopes{"pull_requests": "read"}) {
		t.Errorf("expected issues:read to be required, required %v", a.requiredScopes)
	}
	if strings.Join(a.crossRepoFields, ",") != "headRepository.issues" {
		t.Errorf("crossRepoFields = %v, want [headRepository.issues]", a.crossRepoFields)
	}
	if a.introspectionOnly {
		t.Error("introspectionOnly = true for a repository query")
	}
}

func TestAnalyzeGraphQLRequest_IntrospectionOnly(t *testing.T) {
	tests := []struct {
		query string
		want  bool
	}{
		{`{__type(name:"X"){name}}`, true},
		{`{__typename}`, true},
		{`{__type(name:"X"){name} viewer{login}}`, false},
		{`{viewer{login}}`, false},
		{`mutation{__typename}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"query": tt.query})
			if err != nil {
				t.Fatal(err)
			}
			a, err := analyzeGraphQLRequest(body)
			if err != nil {
				t.Fatal(err)
			}
			if a.introspectionOnly != tt.want {
				t.Errorf("introspectionOnly = %v, want %v", a.introspectionOnly, tt.want)
			}
		})
	}
}

// TestServeHTTP_GraphQL_RepoScoped_CrossRepoSubtrees runs the #341 reviewer
// probes through the handler with a repository-restricted token.
func TestServeHTTP_GraphQL_RepoScoped_CrossRepoSubtrees(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantCode int
		wantBody string
	}{
		{"author user issues", `{ repository(owner: "goodtune", name: "ghp") { issue(number: 1) { author { ...on User { issues(first: 1) { nodes { body } } } } } } }`, http.StatusForbidden, "author.issues"},
		{"viewer issues beside pinned repository", `{ repository(owner: "goodtune", name: "ghp") { name } viewer { issues(first: 1) { nodes { body } } } }`, http.StatusForbidden, "viewer.issues"},
		{"headRepository nameWithOwner", `{ repository(owner: "goodtune", name: "ghp") { pullRequest(number: 1) { headRepository { nameWithOwner } } } }`, http.StatusOK, ""},
		{"headRepository issues", `{ repository(owner: "goodtune", name: "ghp") { pullRequest(number: 1) { headRepository { issues(first: 1) { nodes { body } } } } } }`, http.StatusForbidden, "headRepository.issues"},
		{"Repository.parent issues", `{ repository(owner: "goodtune", name: "ghp") { parent { issues(first: 1) { nodes { body } } } } }`, http.StatusForbidden, "parent.issues"},
		{"PullRequest_fields2 introspection", `query PullRequest_fields2 { WorkflowRun: __type(name: "WorkflowRun") { fields(includeDeprecated: true) { name } } }`, http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")
			body, err := json.Marshal(map[string]string{"query": tt.query})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer "+ghpToken)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rr.Code, tt.wantCode, rr.Body.String())
			}
			if tt.wantBody != "" && !strings.Contains(rr.Body.String(), tt.wantBody) {
				t.Errorf("body %q does not name %q", rr.Body.String(), tt.wantBody)
			}
		})
	}
}
