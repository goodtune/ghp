package exec

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

func TestGraphQL_PostsQueryAndVariables(t *testing.T) {
	var method, uri string
	var got map[string]any
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, uri = r.Method, r.RequestURI
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	s := &scenario.Scenario{ID: "x", Kind: "graphql",
		Query:     `query { repository(owner:"{{.RepoA.Owner}}", name:"x") { id } }`,
		Variables: map[string]any{"o": "{{.RepoA.Owner}}", "id": "$int:RepoA.ID"}}
	if _, err := (graphqlExecutor{}).Run(context.Background(), s, tok, env); err != nil {
		t.Fatal(err)
	}
	if method != "POST" || uri != "/api/graphql" {
		t.Fatalf("%s %s", method, uri)
	}
	if got["query"] != `query { repository(owner:"a-owner", name:"x") { id } }` {
		t.Errorf("query = %v", got["query"])
	}
	vars := got["variables"].(map[string]any)
	if vars["o"] != "a-owner" || vars["id"] != float64(900000101) {
		t.Errorf("variables = %v", vars)
	}
}

func TestGraphQL_StepRejectsGET(t *testing.T) {
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	s := &scenario.Scenario{ID: "x", Kind: "graphql", Steps: []scenario.Request{{Name: "s", Path: "/graphql"}}}
	if _, err := (graphqlExecutor{}).Run(context.Background(), s, tok, env); err == nil {
		t.Fatal("want error for GET graphql step")
	}
}

func TestGraphQL_StepRejectsNonGraphQLPath(t *testing.T) {
	calls := 0
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	for _, p := range []string{"/repos/w-owner/w-repo/x", "/graphql?x=1"} {
		s := &scenario.Scenario{ID: "x", Kind: "graphql", Steps: []scenario.Request{{Name: "s", Method: "POST", Path: p,
			Body: map[string]any{"query": "{ viewer { login } }"}, Expect: &scenario.Expect{Status: 200}}}}
		if _, err := (graphqlExecutor{}).Run(context.Background(), s, tok, env); err == nil || !strings.Contains(err.Error(), "/graphql") {
			t.Errorf("path %q: err = %v, want path error", p, err)
		}
	}
	if calls != 0 {
		t.Fatalf("sent %d requests, want 0", calls)
	}
	// Empty and /graphql paths are both accepted.
	for _, p := range []string{"", "/graphql"} {
		s := &scenario.Scenario{ID: "x", Kind: "graphql", Steps: []scenario.Request{{Name: "s", Method: "POST", Path: p,
			Body: map[string]any{"query": "{ viewer { login } }"}, Expect: &scenario.Expect{Status: 200}}}}
		if _, err := (graphqlExecutor{}).Run(context.Background(), s, tok, env); err != nil {
			t.Errorf("path %q: %v", p, err)
		}
	}
}
