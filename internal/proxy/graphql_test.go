package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/database"
)

func TestAnalyzeGraphQLRequest_ViewerOnly(t *testing.T) {
	body := []byte(`{"query":"{ viewer { login } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.hasMutation || got.hasSubscription {
		t.Errorf("expected query operation only, got mutation=%v subscription=%v", got.hasMutation, got.hasSubscription)
	}
	if len(got.requiredScopes) != 0 {
		t.Errorf("expected no required scopes for { viewer { login } }, got %v", got.requiredScopes)
	}
	if len(got.referencedRepos) != 0 {
		t.Errorf("expected no referenced repos, got %v", got.referencedRepos)
	}
	if len(got.crossRepoFields) != 0 {
		t.Errorf("expected no cross-repo fields, got %v", got.crossRepoFields)
	}
	if len(got.unknownFields) != 0 {
		t.Errorf("expected no unknown fields, got %v", got.unknownFields)
	}
}

func TestAnalyzeGraphQLRequest_RepositoryArgsExtracted(t *testing.T) {
	body := []byte(`{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { id name } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"goodtune/ghp"}
	if !reflect.DeepEqual(got.referencedRepos, want) {
		t.Errorf("referencedRepos = %v, want %v", got.referencedRepos, want)
	}
	if len(got.unknownFields) != 0 {
		t.Errorf("expected no unknown fields, got %v", got.unknownFields)
	}
}

func TestAnalyzeGraphQLRequest_RepositoryArgsAreLiteralOnly(t *testing.T) {
	// owner is a variable reference rather than a literal string. The
	// analyzer must not trust the variable name as the repository identity.
	body := []byte(`{"query":"query Q($owner: String!) { repository(owner: $owner, name: \"ghp\") { id } }","variables":{"owner":"goodtune"}}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.referencedRepos) != 0 {
		t.Errorf("variable-driven owner must not produce a referencedRepos entry, got %v", got.referencedRepos)
	}
}

func TestAnalyzeGraphQLRequest_PullRequestRequiresScope(t *testing.T) {
	body := []byte(`{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { pullRequests(first: 10) { nodes { number } } } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []scopeRequirement{{permission: "pull_requests", level: "read"}}
	if !reflect.DeepEqual(got.requiredScopes, want) {
		t.Errorf("requiredScopes = %v, want %v", got.requiredScopes, want)
	}
}

func TestAnalyzeGraphQLRequest_MutationRequiresWriteScope(t *testing.T) {
	body := []byte(`{"query":"mutation { createIssue(input: {repositoryId: \"abc\", title: \"hello\"}) { issue { id } } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.hasMutation {
		t.Fatalf("expected mutation flag")
	}
	want := []scopeRequirement{{permission: "issues", level: "write"}}
	if !reflect.DeepEqual(got.requiredScopes, want) {
		t.Errorf("requiredScopes = %v, want %v", got.requiredScopes, want)
	}
}

func TestAnalyzeGraphQLRequest_UnknownMutationDeniedByDefault(t *testing.T) {
	body := []byte(`{"query":"mutation { destroyTheUniverse { ok } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.hasMutation {
		t.Fatalf("expected mutation flag")
	}
	if len(got.unknownFields) == 0 {
		t.Fatalf("expected destroyTheUniverse to be flagged as unknown")
	}
}

func TestAnalyzeGraphQLRequest_CrossRepoFieldsFlagged(t *testing.T) {
	body := []byte(`{"query":"{ search(query: \"x\", type: REPOSITORY, first: 5) { repositoryCount } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"search"}
	if !reflect.DeepEqual(got.crossRepoFields, want) {
		t.Errorf("crossRepoFields = %v, want %v", got.crossRepoFields, want)
	}
}

func TestAnalyzeGraphQLRequest_FragmentsResolved(t *testing.T) {
	body := []byte(`{"query":"query { repository(owner: \"goodtune\", name: \"ghp\") { ...PR } } fragment PR on Repository { pullRequests(first: 1) { nodes { number } } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []scopeRequirement{{permission: "pull_requests", level: "read"}}
	if !reflect.DeepEqual(got.requiredScopes, want) {
		t.Errorf("requiredScopes = %v, want %v", got.requiredScopes, want)
	}
}

func TestAnalyzeGraphQLRequest_FragmentAtMutationRootStillScoped(t *testing.T) {
	// When a mutation operation pulls in its root fields via a fragment
	// spread, those fields must still be classified as mutation root
	// fields so mutationScopeRequirements is consulted (rather than the
	// query field-name map).
	body := []byte(`{"query":"mutation { ...M } fragment M on Mutation { createIssue(input: {repositoryId: \"abc\", title: \"x\"}) { issue { id } } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.hasMutation {
		t.Fatalf("expected mutation flag")
	}
	want := []scopeRequirement{{permission: "issues", level: "write"}}
	if !reflect.DeepEqual(got.requiredScopes, want) {
		t.Errorf("requiredScopes = %v, want %v", got.requiredScopes, want)
	}
	if len(got.unknownFields) != 0 {
		t.Errorf("expected createIssue not to be flagged unknown via fragment, got %v", got.unknownFields)
	}
}

func TestAnalyzeGraphQLRequest_RecursiveFragmentSpreadIsSafe(t *testing.T) {
	// A self-referential fragment must not drive the analyzer into
	// infinite recursion. (The query is technically illegal under the
	// GraphQL spec, but the parser still produces an AST and we must not
	// hang on it.)
	body := []byte(`{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { ...R } } fragment R on Repository { ...R }"}`)
	if _, err := analyzeGraphQLRequest(body); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnalyzeGraphQLRequest_NodesInsideConnectionIsNotCrossRepo(t *testing.T) {
	// `nodes` is a Connection helper when nested under a connection
	// field; it is only cross-repository when used as a root selection
	// (`{ nodes(ids: [...]) { ... } }`). The repo-scoped analysis must
	// not flag the inner case.
	body := []byte(`{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { pullRequests(first: 1) { nodes { number } } } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.crossRepoFields) != 0 {
		t.Errorf("nested `nodes` should not be flagged cross-repo, got %v", got.crossRepoFields)
	}
}

func TestAnalyzeGraphQLRequest_RootNodesIsCrossRepo(t *testing.T) {
	// Root-level `nodes(ids: ...)` is the cross-repository form.
	body := []byte(`{"query":"{ nodes(ids: [\"abc\"]) { __typename } }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.crossRepoFields) == 0 {
		t.Fatalf("expected root-level `nodes` to be flagged cross-repo")
	}
}

func TestAnalyzeGraphQLRequest_OperationNameSelectsOnlyOne(t *testing.T) {
	// The document defines two operations; only `Wanted` should be
	// analysed. `Unwanted` references unknown fields that would otherwise
	// fail deny-by-default.
	q := "query Wanted { viewer { login } } query Unwanted { mysteryRoot { id } }"
	body := []byte(`{"query":` + jsonString(q) + `,"operationName":"Wanted"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.unknownFields) != 0 {
		t.Errorf("only the named operation should be analysed; got unknown fields %v", got.unknownFields)
	}
}

func TestAnalyzeGraphQLRequest_OperationNameMissingErrors(t *testing.T) {
	q := "query A { viewer { login } } query B { viewer { login } }"
	body := []byte(`{"query":` + jsonString(q) + `,"operationName":"C"}`)
	if _, err := analyzeGraphQLRequest(body); err == nil {
		t.Fatal("expected error when operationName does not match any operation")
	}
}

func TestAnalyzeGraphQLRequest_MultipleOperationsRequireOperationName(t *testing.T) {
	q := "query A { viewer { login } } query B { viewer { login } }"
	body := []byte(`{"query":` + jsonString(q) + `}`)
	if _, err := analyzeGraphQLRequest(body); err == nil {
		t.Fatal("expected error when document has multiple operations and operationName is omitted")
	}
}

// jsonString escapes s as a JSON string literal (including surrounding
// double quotes) so it can be embedded directly into a hand-written JSON
// fragment in tests.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestAnalyzeGraphQLRequest_SubscriptionFlagged(t *testing.T) {
	body := []byte(`{"query":"subscription { whatever }"}`)
	got, err := analyzeGraphQLRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.hasSubscription {
		t.Fatalf("expected subscription flag")
	}
}

func TestAnalyzeGraphQLRequest_InvalidJSON(t *testing.T) {
	if _, err := analyzeGraphQLRequest([]byte(`not json`)); err == nil {
		t.Fatal("expected error for non-JSON body")
	}
}

func TestAnalyzeGraphQLRequest_UnparseableQuery(t *testing.T) {
	if _, err := analyzeGraphQLRequest([]byte(`{"query":"not a graphql query"}`)); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestAnalyzeGraphQLRequest_EmptyQuery(t *testing.T) {
	if _, err := analyzeGraphQLRequest([]byte(`{"query":""}`)); err == nil {
		t.Fatal("expected error for empty query")
	}
}

func TestAnalysisSatisfiedBy(t *testing.T) {
	a := graphQLAnalysis{
		requiredScopes: []scopeRequirement{
			{permission: "issues", level: "read"},
			{permission: "pull_requests", level: "write"},
		},
	}
	tests := []struct {
		name   string
		scopes database.Scopes
		want   bool
	}{
		{"missing both", database.Scopes{}, false},
		{"missing one", database.Scopes{"issues": "read"}, false},
		{"exact match", database.Scopes{"issues": "read", "pull_requests": "write"}, true},
		{"write covers read", database.Scopes{"issues": "write", "pull_requests": "write"}, true},
		{"read does not cover write", database.Scopes{"issues": "read", "pull_requests": "read"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.satisfiedBy(tc.scopes); got != tc.want {
				t.Errorf("satisfiedBy(%v) = %v, want %v", tc.scopes, got, tc.want)
			}
		})
	}
}

// --- handler-level integration tests ---

func TestServeHTTP_GraphQL_RepoScoped_AllowsAllowlistedRepo(t *testing.T) {
	h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")

	body := `{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { name } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for repo-scoped token referencing the allowlisted repo, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_RepoScoped_DeniesOtherRepo(t *testing.T) {
	h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")

	body := `{"query":"{ repository(owner: \"someone\", name: \"else\") { name } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "someone/else") {
		t.Errorf("expected error message to name the denied repo, got: %s", rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_RepoScoped_DeniesCrossRepoField(t *testing.T) {
	h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")

	body := `{"query":"{ search(query: \"x\", type: REPOSITORY, first: 1) { repositoryCount } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-repo field on repo-scoped token, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "search") {
		t.Errorf("expected error message to name the cross-repo field, got: %s", rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_RepoScoped_DeniesQueryWithoutRepoArg(t *testing.T) {
	// A repo-scoped token with a top-level query that does not pin a repo
	// (e.g. `{ viewer { login } }`) must be rejected: the proxy cannot prove
	// the response stays inside the allowlist.
	h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")

	body := `{"query":"{ viewer { login } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "repository-restricted") {
		t.Errorf("expected error to mention repository restriction, got: %s", rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_PermissionScoped_AllowsCoveredQuery(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"pull_requests": "read",
	})

	body := `{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { pullRequests(first: 1) { nodes { number } } } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when token's scopes cover the query, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_PermissionScoped_DeniesUncoveredQuery(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"contents": "read",
	})

	body := `{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { issues(first: 1) { nodes { number } } } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when token lacks issues:read, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "issues:read") {
		t.Errorf("expected error to name the missing scope, got: %s", rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_PermissionScoped_DeniesMutationWithoutWriteScope(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"issues": "read",
	})

	body := `{"query":"mutation { createIssue(input: {repositoryId: \"abc\", title: \"x\"}) { issue { id } } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for mutation without write scope, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "issues:write") {
		t.Errorf("expected error to name issues:write requirement, got: %s", rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_PermissionScoped_AllowsMutationWithWriteScope(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"issues": "write",
	})

	body := `{"query":"mutation { createIssue(input: {repositoryId: \"abc\", title: \"x\"}) { issue { id } } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for issues:write mutation, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_PermissionScoped_DeniesUnknownMutation(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"issues": "write",
	})

	body := `{"query":"mutation { destroyTheUniverse { ok } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (deny-by-default) for unknown mutation, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "destroyTheUniverse") {
		t.Errorf("expected error to name the unmapped field, got: %s", rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_PermissionScoped_DeniesUnknownQueryField(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"contents": "read",
	})

	body := `{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { topSecretField { id } } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown field, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "topSecretField") {
		t.Errorf("expected error to name the unmapped field, got: %s", rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_OpenScoped_BypassesAnalysis(t *testing.T) {
	// An open-scoped token must pass even queries that would fail static
	// analysis (e.g. unknown fields), because the underlying credential
	// continues to gate access at GitHub's end.
	h, ghpToken := newOpenScopedHandler(t)

	body := `{"query":"{ unknownField { somethingElse } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for open-scoped token, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_RejectsInvalidJSON(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"issues": "read",
	})

	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(`not json`))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON body, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTP_GraphQL_RejectsOversizedBody(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{
		"issues": "read",
	})

	// Build a body larger than maxGraphQLBodyBytes.
	big := strings.Repeat("a", maxGraphQLBodyBytes+1024)
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", rr.Code)
	}
}
