package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/database"
)

// ghRepoQuery is the shape gh 2.102.0 sends for `gh repo view` (#297).
const ghRepoQuery = "query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { name owner { id login } description } }"

func TestAnalyzeGraphQLRequest_VariablePinning(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantRepos []string
		wantUnpin bool
	}{
		{
			name:      "string variables pin the repository",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":"REPO"},"operationName":"RepositoryInfo"}`,
			wantRepos: []string{"OWNER/REPO"},
		},
		{
			name:      "nullable String variables pin the repository",
			body:      `{"query":"query Q($o: String, $n: String) { repository(owner: $o, name: $n) { id } }","variables":{"o":"a","n":"b"}}`,
			wantRepos: []string{"a/b"},
		},
		{
			name:      "mixed literal and variable",
			body:      `{"query":"query Q($n: String!) { repository(owner: \"a\", name: $n) { id } }","variables":{"n":"b"}}`,
			wantRepos: []string{"a/b"},
		},
		{
			name:      "nested repository lookup with variables is pinned",
			body:      `{"query":"query Q($o: String!, $n: String!) { viewer { login } repository(owner: \"a\", name: \"b\") { id } organization(login: \"a\") { login } r2: repository(owner: $o, name: $n) { issues(first: 1) { nodes { repository { id } } } } }","variables":{"o":"c","n":"d"}}`,
			wantRepos: []string{"a/b", "c/d"},
		},
		{
			name:      "variables absent",
			body:      `{"query":` + jsonString(ghRepoQuery) + `}`,
			wantUnpin: true,
		},
		{
			name:      "variables null",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":null}`,
			wantUnpin: true,
		},
		{
			name:      "variables not an object",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":"owner"}`,
			wantUnpin: true,
		},
		{
			name:      "variable key missing",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER"}}`,
			wantUnpin: true,
		},
		{
			name:      "variable value null",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":null}}`,
			wantUnpin: true,
		},
		{
			name:      "variable value number",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":1}}`,
			wantUnpin: true,
		},
		{
			name:      "variable value object",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":{"x":"REPO"}}}`,
			wantUnpin: true,
		},
		{
			name:      "variable value array",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":["REPO"]}}`,
			wantUnpin: true,
		},
		{
			name:      "default value is not used",
			body:      `{"query":"query Q($o: String = \"a\", $n: String = \"b\") { repository(owner: $o, name: $n) { id } }","variables":{}}`,
			wantUnpin: true,
		},
		{
			name:      "undeclared variable",
			body:      `{"query":"query Q { repository(owner: $o, name: $n) { id } }","variables":{"o":"a","n":"b"}}`,
			wantUnpin: true,
		},
		{
			name:      "variable declared with a non-String type",
			body:      `{"query":"query Q($o: ID!, $n: String!) { repository(owner: $o, name: $n) { id } }","variables":{"o":"a","n":"b"}}`,
			wantUnpin: true,
		},
		{
			name:      "variable declared as a list",
			body:      `{"query":"query Q($o: [String], $n: String!) { repository(owner: $o, name: $n) { id } }","variables":{"o":"a","n":"b"}}`,
			wantUnpin: true,
		},
		{
			name:      "duplicate key in variables",
			body:      `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":"REPO","owner":"EVIL"}}`,
			wantUnpin: true,
		},
		{
			name:      "multiple operations",
			body:      `{"query":` + jsonString(ghRepoQuery+" query Other { viewer { login } }") + `,"variables":{"owner":"OWNER","name":"REPO"},"operationName":"RepositoryInfo"}`,
			wantUnpin: true,
		},
		{
			name:      "extra non-repository argument is ignored",
			body:      `{"query":"query Q($o: String!, $n: String!) { repository(owner: $o, name: $n, followRenames: true) { id } }","variables":{"o":"a","n":"b"}}`,
			wantRepos: []string{"a/b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := analyzeGraphQLRequest([]byte(tt.body))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.hasUnpinnedRepositoryLookup != tt.wantUnpin {
				t.Errorf("hasUnpinnedRepositoryLookup = %v, want %v", got.hasUnpinnedRepositoryLookup, tt.wantUnpin)
			}
			if tt.wantRepos != nil && !reflect.DeepEqual(got.referencedRepos, tt.wantRepos) {
				t.Errorf("referencedRepos = %v, want %v", got.referencedRepos, tt.wantRepos)
			}
			if tt.wantUnpin {
				for _, r := range got.referencedRepos {
					if strings.Contains(r, "EVIL") || r == "OWNER/REPO" || r == "a/b" {
						t.Errorf("unpinned lookup leaked into referencedRepos: %v", got.referencedRepos)
					}
				}
			}
		})
	}
}

func TestGraphQLVerdict_VariablePinning(t *testing.T) {
	repo := tokenScopeInfo{Repos: []string{"OWNER/REPO"}}
	perm := tokenScopeInfo{Scopes: database.Scopes{"contents": "write", "issues": "write"}}
	tests := []struct {
		name, body string
		si         tokenScopeInfo
		want       string
	}{
		{"variables name the allowed repo", `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":"REPO"}}`, repo, reasonAllow},
		{"variables name the allowed repo, other case", `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"owner","name":"repo"}}`, repo, reasonAllow},
		{"variables name another repo", `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"someone","name":"else"}}`, repo, reasonRepoNotAllowed},
		{"variables absent", `{"query":` + jsonString(ghRepoQuery) + `}`, repo, reasonUnpinned},
		{"variable null", `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":null}}`, repo, reasonUnpinned},
		{"variable int", `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":5}}`, repo, reasonUnpinned},
		{"variable object", `{"query":` + jsonString(ghRepoQuery) + `,"variables":{"owner":"OWNER","name":{}}}`, repo, reasonUnpinned},
		{"literal allowed plus variable other", `{"query":"query Q($o: String!, $n: String!) { a: repository(owner: \"OWNER\", name: \"REPO\") { name } b: repository(owner: $o, name: $n) { name } }","variables":{"o":"someone","n":"else"}}`, repo, reasonRepoNotAllowed},
		// #299: __typename at a mutation root needs no scope.
		{"typename beside mapped mutation", `{"query":"mutation { __typename addComment(input: {subjectId: \"x\", body: \"y\"}) { clientMutationId } }"}`, perm, reasonAllow},
		{"typename only mutation", `{"query":"mutation { __typename }"}`, perm, reasonMutationUnscoped},
		{"typename only mutation, repo token", `{"query":"mutation { __typename }"}`, repo, reasonMutationRepo},
		{"unmapped mutation beside typename", `{"query":"mutation { __typename deleteRepository(input: {}) { clientMutationId } }"}`, perm, reasonUnmapped},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := graphQLVerdict([]byte(tt.body), tt.si)
			if d.Reason != tt.want {
				t.Errorf("reason = %q, want %q (%s)", d.Reason, tt.want, d.Message)
			}
		})
	}
}

// bodyCaptureTransport records the exact bytes forwarded upstream.
type bodyCaptureTransport struct {
	body []byte
}

func (b *bodyCaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		b.body = data
	}
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	return rec.Result(), nil
}

func TestServeHTTP_GraphQL_RepoScoped_VariablePinning(t *testing.T) {
	tests := []struct {
		name       string
		variables  string
		wantStatus int
		wantMsg    string
	}{
		{"allowed repo", `{"owner":"goodtune","name":"ghp"}`, http.StatusOK, ""},
		{"disallowed repo", `{"owner":"someone","name":"else"}`, http.StatusForbidden, "not scoped to someone/else"},
		{"null value", `{"owner":"goodtune","name":null}`, http.StatusForbidden, "literal string arguments"},
		{"duplicate key", `{"owner":"goodtune","name":"ghp","owner":"someone"}`, http.StatusForbidden, "literal string arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")
			bt := &bodyCaptureTransport{}
			h.client.Transport = bt

			// Odd spacing makes any re-encoding visible.
			body := `{ "query" : ` + jsonString(ghRepoQuery) + ` ,  "variables":` + tt.variables + ` }`
			req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+ghpToken)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantMsg != "" && !strings.Contains(rr.Body.String(), tt.wantMsg) {
				t.Errorf("body %q does not contain %q", rr.Body.String(), tt.wantMsg)
			}
			if tt.wantStatus == http.StatusOK {
				if !bytes.Equal(bt.body, []byte(body)) {
					t.Errorf("forwarded body differs from analysed body:\n got %q\nwant %q", bt.body, body)
				}
			} else if bt.body != nil {
				t.Errorf("denied request reached upstream")
			}
		})
	}
}

func TestAnalyzeGraphQLRequest_StrictEnvelope(t *testing.T) {
	q := jsonString(ghRepoQuery)
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"long s raw", `{"query":` + q + `,"variables":{"owner":"evil","name":"x"},"variableſ":{"owner":"OWNER","name":"REPO"}}`, true},
		{"long s escaped", `{"query":` + q + `,"variables":{"owner":"evil","name":"x"},"variableſ":{"owner":"OWNER","name":"REPO"}}`, true},
		{"Query and query", `{"query":"{ viewer { login } }","Query":` + q + `}`, true},
		{"operationName and OperationName", `{"query":` + q + `,"operationName":"RepositoryInfo","OperationName":"X"}`, true},
		{"unknown key", `{"query":` + q + `,"foo":1}`, true},
		{"duplicate query", `{"query":"{ viewer { login } }","query":` + q + `}`, true},
		{"duplicate variables", `{"query":` + q + `,"variables":{"owner":"OWNER","name":"REPO"},"variables":{"owner":"EVIL","name":"REPO"}}`, true},
		{"body not an object", `["query"]`, true},
		{"extensions allowed", `{"query":` + q + `,"variables":{"owner":"OWNER","name":"REPO"},"extensions":{"persistedQuery":{}}}`, false},
		{"query not a string", `{"query":1}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := analyzeGraphQLRequest([]byte(tt.body))
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServeHTTP_GraphQL_StrictEnvelopeRejectedBeforeUpstream(t *testing.T) {
	q := jsonString(ghRepoQuery)
	bodies := map[string]string{
		"long s":        `{"query":` + q + `,"variables":{"owner":"evil","name":"x"},"variableſ":{"owner":"goodtune","name":"ghp"}}`,
		"Query":         `{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { name } }","Query":"{ viewer { login } }"}`,
		"OperationName": `{"query":` + q + `,"variables":{"owner":"goodtune","name":"ghp"},"OperationName":"X"}`,
		"unknown key":   `{"query":` + q + `,"variables":{"owner":"goodtune","name":"ghp"},"foo":1}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			h, ghpToken := newRepoOnlyHandler(t, "goodtune/ghp")
			bt := &bodyCaptureTransport{}
			h.client.Transport = bt
			req := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+ghpToken)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "request envelope") {
				t.Errorf("body %q does not explain the envelope error", rr.Body.String())
			}
			if bt.body != nil {
				t.Errorf("rejected request reached upstream")
			}
		})
	}
}
