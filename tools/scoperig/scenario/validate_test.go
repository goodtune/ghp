package scenario

import (
	"strings"
	"testing"
)

func baseTree() *Tree {
	return &Tree{
		Claims: map[string]Claim{"C1": {ID: "C1"}, "GAP-A1": {ID: "GAP-A1"}},
		Profiles: map[string]Profile{
			"p":   {Name: "p", Type: "proxy", Repositories: []string{"{{.RepoA}}"}, Duration: "2h"},
			"w":   {Name: "w", Type: "proxy", Repositories: []string{"{{.RepoW}}"}, Duration: "1h"},
			"all": {Name: "all", Type: "proxy", Duration: "30m"},
		},
	}
}

func withScenarios(ss ...*Scenario) *Tree {
	t := baseTree()
	for _, s := range ss {
		if s.File == "" {
			s.File = "x.yaml"
		}
		s.Normalise()
	}
	t.Scenarios = ss
	return t
}

func requireErr(t *testing.T, errs []error, subs ...string) {
	t.Helper()
	for _, e := range errs {
		ok := true
		for _, s := range subs {
			if !strings.Contains(e.Error(), s) {
				ok = false
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("no error containing %q in %v", subs, errs)
}

func requireNoErr(t *testing.T, errs []error) {
	t.Helper()
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestValidate_OK(t *testing.T) {
	tree, err := Load("testdata/ok")
	if err != nil {
		t.Fatal(err)
	}
	requireNoErr(t, Validate(tree, nil))
}

func TestValidate_WriteOutsideW(t *testing.T) {
	errs := Validate(withScenarios(&Scenario{ID: "S1", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "POST", Path: "/repos/{{.RepoA}}/issues"}), nil)
	requireErr(t, errs, "S1", "x.yaml", "RepoW")

	errs = Validate(withScenarios(&Scenario{ID: "S2", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "GET", Path: "/repos/{{.RepoA}}/issues",
		Cleanup: []Request{{Method: "DELETE", Path: "/repos/{{.RepoB}}/git/refs/x"}}}), nil)
	requireErr(t, errs, "S2", "cleanup", "RepoW")

	// GET outside W and writes inside W are fine.
	requireNoErr(t, Validate(withScenarios(&Scenario{ID: "S3", Claim: "C1", Profile: "p", Kind: "rest",
		Steps: []Request{
			{Method: "GET", Path: "/repos/{{.RepoB}}/pulls"},
			{Name: "s", Method: "post", Path: "/repos/{{.RepoW}}/issues", Capture: map[string]string{"n": "$.number"}},
			{Method: "PATCH", Path: "/repos/{{.RepoW}}/issues/{{.Step.s.n}}"},
		}}), nil))
}

func TestValidate_GAPA1Exception(t *testing.T) {
	ok := &Scenario{ID: "GAP-A1.delete-ref-contents-ro", Claim: "GAP-A1", Profile: "w", Kind: "rest",
		Method: "DELETE", Path: "/repos/{{.RepoW}}/git/refs/heads/absent"}
	requireNoErr(t, Validate(withScenarios(ok), nil))
	bad := &Scenario{ID: "GAP-A1.delete-ref-contents-ro", Claim: "GAP-A1", Profile: "w", Kind: "rest",
		Method: "DELETE", Path: "/repos/{{.RepoA}}/git/refs/heads/absent"}
	requireErr(t, Validate(withScenarios(bad), nil), "GAP-A1", "RepoW")
}

func TestValidate_KnownNeedsObserved(t *testing.T) {
	errs := Validate(withScenarios(&Scenario{ID: "S1", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "GET", Path: "/user", KnownIssue: "https://github.com/goodtune/ghp/issues/12"}), nil)
	requireErr(t, errs, "S1", "observed")

	errs = Validate(withScenarios(&Scenario{ID: "S2", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "GET", Path: "/user", Observed: &Expect{Status: 200}}), nil)
	requireErr(t, errs, "S2", "known_issue")

	errs = Validate(withScenarios(&Scenario{ID: "S3", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "GET", Path: "/user", KnownIssue: "https://github.com/other/ghp/issues/1", Observed: &Expect{Status: 200}}), nil)
	requireErr(t, errs, "S3", "known_issue")

	requireNoErr(t, Validate(withScenarios(&Scenario{ID: "S4", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "GET", Path: "/user", KnownIssue: "https://github.com/goodtune/ghp/issues/12", Observed: &Expect{Status: 200}}), nil))
}

func TestValidate_TokenAPIPath(t *testing.T) {
	requireNoErr(t, Validate(withScenarios(&Scenario{ID: "T1", Claim: "C1", Kind: "token_api",
		Request: &Request{Method: "POST", Path: "/api/tokens", Body: map[string]any{"duration": `{{add .Instance.MaxDuration "1h"}}`}}}), nil))
	errs := Validate(withScenarios(&Scenario{ID: "T2", Claim: "C1", Kind: "token_api",
		Request: &Request{Method: "POST", Path: "/repos/{{.RepoW}}/issues"}}), nil)
	requireErr(t, errs, "T2", "/api/tokens")
	errs = Validate(withScenarios(&Scenario{ID: "T3", Claim: "C1", Kind: "token_api",
		Request: &Request{Method: "GET", Path: "/user"}}), nil)
	requireErr(t, errs, "T3", "/api/tokens")
}

func TestValidate_UnknownClaimAndProfile(t *testing.T) {
	errs := Validate(withScenarios(&Scenario{ID: "S1", Claim: "NOPE", Profile: "missing", Kind: "rest",
		Method: "GET", Path: "/user"}), nil)
	requireErr(t, errs, "S1", "claim", "NOPE")
	requireErr(t, errs, "S1", "profile", "missing")

	errs = Validate(withScenarios(&Scenario{ID: "S2", Claim: "C1", Kind: "rest", Method: "GET", Path: "/user"}), nil)
	requireErr(t, errs, "S2", "profile")

	errs = Validate(withScenarios(&Scenario{ID: "S3", Claim: "C1", Profile: "p", Kind: "soap"}), nil)
	requireErr(t, errs, "S3", "kind")
}

func TestValidate_Requires(t *testing.T) {
	errs := Validate(withScenarios(&Scenario{ID: "S1", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "GET", Path: "/user", Requires: []string{"repo_w_push", "teleport"}}), nil)
	requireErr(t, errs, "S1", "teleport")
	if len(errs) != 1 {
		t.Errorf("want 1 error, got %v", errs)
	}
}

func TestValidate_Profiles(t *testing.T) {
	tree := withScenarios()
	tree.Profiles["agent"] = Profile{Name: "agent", Type: "agent", Duration: "1h"}
	tree.Profiles["long"] = Profile{Name: "long", Type: "proxy", Duration: "3h"}
	tree.Profiles["bad"] = Profile{Name: "bad", Type: "proxy", Duration: "soon"}
	tree.Profiles["empty"] = Profile{Name: "empty", Type: "proxy"}
	tree.Profiles["lifecycle-default"] = Profile{Name: "lifecycle-default", Type: "proxy"}
	tree.Profiles["badrepo"] = Profile{Name: "badrepo", Type: "proxy", Duration: "1h", Repositories: []string{"{{.Nope}}"}}
	errs := Validate(tree, nil)
	requireErr(t, errs, "agent", "type")
	requireErr(t, errs, "long", "2h")
	requireErr(t, errs, "bad", "duration")
	requireErr(t, errs, "empty", "duration")
	requireErr(t, errs, "badrepo", "Nope")
	for _, e := range errs {
		if strings.Contains(e.Error(), `"lifecycle-default"`) {
			t.Errorf("lifecycle-default flagged: %v", e)
		}
	}
	if len(errs) != 5 {
		t.Errorf("want 5 errors, got %d: %v", len(errs), errs)
	}
}

func TestValidate_GraphQLMutation(t *testing.T) {
	mut := `mutation { addStar(input:{starrableId:"x"}) { clientMutationId } }`
	requireNoErr(t, Validate(withScenarios(
		&Scenario{ID: "G1", Claim: "C1", Profile: "w", Kind: "graphql", Query: mut},
		&Scenario{ID: "G3", Claim: "C1", Profile: "p", Kind: "graphql",
			Query: `query { repository(owner:"{{.RepoA.Owner}}", name:"{{.RepoA.Name}}") { id } }`},
	), nil))
	requireErr(t, Validate(withScenarios(
		&Scenario{ID: "G2", Claim: "C1", Profile: "all", Kind: "graphql", Query: mut}), nil), "G2", "mutationWriteAllowlist")
	requireErr(t, Validate(withScenarios(
		&Scenario{ID: "G4", Claim: "C1", Profile: "p", Kind: "graphql", Query: mut}), nil), "G4", "RepoW")
	requireErr(t, Validate(withScenarios(
		&Scenario{ID: "G5", Claim: "C1", Profile: "w", Kind: "graphql",
			Query: `mutation { x: repository(owner: "{{.RepoA.Owner}}", name: "{{.RepoA.Name}}") { id } }`}), nil), "G5", "a-owner")
}

func TestValidate_TemplateErrorsAndSorting(t *testing.T) {
	errs := Validate(withScenarios(
		&Scenario{ID: "Z", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/repos/{{.Nope}}"},
		&Scenario{ID: "A", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/x",
			Expect: &Expect{BodyContains: []string{"{{.Missing}}"}}},
	), nil)
	if len(errs) != 2 {
		t.Fatalf("want 2 errors, got %v", errs)
	}
	if !strings.Contains(errs[0].Error(), `"A"`) || !strings.Contains(errs[1].Error(), `"Z"`) {
		t.Errorf("not sorted by scenario: %v", errs)
	}
}

func ghScenario(id, repo string, args ...string) *Scenario {
	return &Scenario{ID: id, Claim: "C1", Profile: "p", Kind: "gh", Repo: repo, Args: args}
}

func TestValidate_GHWrites(t *testing.T) {
	bad := []*Scenario{
		ghScenario("GH1", "", "issue", "create", "--repo", "{{.RepoA}}", "--title", "x"),
		ghScenario("GH2", "", "api", "-X", "POST", "repos/{{.RepoA}}/issues", "-f", "title=x"),
		ghScenario("GH3", "", "api", "repos/{{.RepoB}}/labels", "-f", "name=x"),
		ghScenario("GH4", "", "pr", "merge", "1", "-R", "github.com/{{.RepoA}}"),
		ghScenario("GH5", "", "issue", "create", "--title", "x"),
		ghScenario("GH6", "A", "issue", "close", "1"),
		ghScenario("GH7", "", "repo", "delete", "{{.RepoB}}", "--yes"),
		ghScenario("GH8", "", "api", "graphql", "-f", `query=mutation { addStar(input:{starrableId:"x"}) { clientMutationId } }`),
		ghScenario("GH9", "", "api", "--method=DELETE", "/repos/{{.RepoA}}/git/refs/heads/x"),
		ghScenario("GH10", "", "pr", "create", "-R{{.RepoA}}"),
	}
	for _, s := range bad {
		t.Run(s.ID, func(t *testing.T) {
			requireErr(t, Validate(withScenarios(s), nil), s.ID, "gh:")
		})
	}
	good := []*Scenario{
		ghScenario("OK1", "W", "issue", "create", "--title", "x"),
		ghScenario("OK2", "", "issue", "create", "--repo", "{{.RepoW}}", "--title", "x"),
		ghScenario("OK3", "", "api", "-X", "POST", "repos/{{.RepoW}}/issues", "-f", "title=x"),
		ghScenario("OK4", "A", "pr", "list"),
		ghScenario("OK5", "", "api", "repos/{{.RepoB}}/pulls"),
		ghScenario("OK6", "", "api", "graphql", "-f", `query=query { repository(owner:"{{.RepoA.Owner}}", name:"{{.RepoA.Name}}") { id } }`),
		ghScenario("OK7", "", "search", "issues", "foo"),
	}
	for _, s := range good {
		t.Run(s.ID, func(t *testing.T) {
			requireNoErr(t, Validate(withScenarios(s), nil))
		})
	}
}

func TestValidate_GraphQLMutationTargets(t *testing.T) {
	mutVar := `mutation($id: ID!) { createIssue(input:{repositoryId:$id, title:"x"}) { issue { number } } }`
	cases := []struct {
		name string
		s    *Scenario
		want string
	}{
		{"node id via variable", &Scenario{ID: "M1", Claim: "C1", Profile: "w", Kind: "graphql", Query: mutVar,
			Variables: map[string]any{"id": "{{.RepoA.NodeID}}"}}, "RepoA"},
		{"node id via repositoryId variable", &Scenario{ID: "M2", Claim: "C1", Profile: "w", Kind: "graphql",
			Query:     `mutation($repositoryId: ID!) { createIssue(input:{repositoryId:$repositoryId, title:"x"}) { clientMutationId } }`,
			Variables: map[string]any{"repositoryId": "R_other"}}, "repositoryId"},
		{"node id via literal", &Scenario{ID: "M3", Claim: "C1", Profile: "w", Kind: "graphql",
			Query: `mutation { createIssue(input:{repositoryId:"{{.RepoA.NodeID}}", title:"x"}) { clientMutationId } }`}, "RepoA"},
		{"database id literal", &Scenario{ID: "M4", Claim: "C1", Profile: "w", Kind: "graphql",
			Query: `mutation { x(input:{id:{{.RepoB.ID}}}) { clientMutationId } }`}, "RepoB"},
		{"empty repos not allowlisted", &Scenario{ID: "M5", Claim: "C1", Profile: "all", Kind: "graphql", Query: mutVar,
			Variables: map[string]any{"id": "{{.RepoW.NodeID}}"}}, "mutationWriteAllowlist"},
		{"name-first repository", &Scenario{ID: "M6", Claim: "C1", Profile: "w", Kind: "graphql",
			Query: `mutation { r: repository(name: "{{.RepoA.Name}}", first: 1, owner: "{{.RepoA.Owner}}") { id } }`}, "a-owner/a-repo"},
		{"owner/name text", &Scenario{ID: "M7", Claim: "C1", Profile: "w", Kind: "graphql",
			Query: `mutation { x(input:{body:"see {{.RepoA}}"}) { clientMutationId } }`}, "a-owner/a-repo"},
		{"graphql step", &Scenario{ID: "M8", Claim: "C1", Profile: "w", Kind: "graphql",
			Steps: []Request{{Method: "POST", Path: "/graphql", Body: map[string]any{"query": mutVar,
				"variables": map[string]any{"id": "{{.RepoA.NodeID}}"}}}}}, "RepoA"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireErr(t, Validate(withScenarios(c.s), nil), c.s.ID, c.want)
		})
	}

	// Allowed: W profile, W node id; and an allowlisted unrestricted profile
	// using a repositoryId captured from a prior step.
	requireNoErr(t, Validate(withScenarios(
		&Scenario{ID: "OK1", Claim: "C1", Profile: "w", Kind: "graphql", Query: mutVar,
			Variables: map[string]any{"id": "{{.RepoW.NodeID}}"}},
		&Scenario{ID: "GQL-C31.createissue-rw-allowed", Claim: "C1", Profile: "all", Kind: "graphql",
			Steps: []Request{
				{Name: "q", Method: "POST", Path: "/graphql",
					Body:    map[string]any{"query": `query { repository(owner:"{{.RepoW.Owner}}", name:"{{.RepoW.Name}}") { id } }`},
					Capture: map[string]string{"rid": "$.data.repository.id"}},
				{Method: "POST", Path: "/graphql", Body: map[string]any{
					"query":     `mutation($repositoryId: ID!) { createIssue(input:{repositoryId:$repositoryId, title:"x"}) { issue { number } } }`,
					"variables": map[string]any{"repositoryId": "{{.Step.q.rid}}"}}},
			}},
	), nil))
}

func TestValidate_PathNormalisation(t *testing.T) {
	for _, p := range []string{
		"/repos/{{.RepoW}}/../../{{.RepoA}}/issues",
		"/repos/{{.RepoW}}/%2e%2e/%2E%2E/{{.RepoA}}/issues",
		"/repos/{{.RepoW}}/%252e%252e/x",
		"/repos/{{.RepoW}}/./issues",
	} {
		t.Run(p, func(t *testing.T) {
			requireErr(t, Validate(withScenarios(&Scenario{ID: "P", Claim: "C1", Profile: "p", Kind: "rest",
				Method: "POST", Path: p}), nil), "P")
		})
	}
	// GET traversal is also rejected (dot segments are never legitimate).
	requireErr(t, Validate(withScenarios(&Scenario{ID: "P2", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "GET", Path: "/repos/{{.RepoW}}/../x"}), nil), "P2", "dot segment")
	requireNoErr(t, Validate(withScenarios(&Scenario{ID: "P3", Claim: "C1", Profile: "p", Kind: "rest",
		Method: "POST", Path: "/repos/{{.RepoW}}/issues?x=1"}), nil))
}

func TestValidate_EmptyMethod(t *testing.T) {
	requireErr(t, Validate(withScenarios(&Scenario{ID: "E1", Claim: "C1", Profile: "p", Kind: "rest",
		Steps: []Request{{Path: "/repos/{{.RepoW}}/issues", Body: map[string]any{"title": "x"}}}}), nil), "E1", "method is required")
	// Empty method without a body is GET: allowed outside W.
	requireNoErr(t, Validate(withScenarios(&Scenario{ID: "E2", Claim: "C1", Profile: "p", Kind: "rest",
		Steps: []Request{{Path: "/repos/{{.RepoA}}/issues"}}}), nil))
}

func TestValidate_TokenAPIPathExact(t *testing.T) {
	for _, p := range []string{"/api/tokens", "/api/tokens/abc", "/api/tokens?x=1"} {
		requireNoErr(t, Validate(withScenarios(&Scenario{ID: "T", Claim: "C1", Kind: "token_api",
			Request: &Request{Method: "POST", Path: p}}), nil))
	}
	for _, p := range []string{"/api/tokensfoo", "/api/tokens/../x"} {
		requireErr(t, Validate(withScenarios(&Scenario{ID: "T", Claim: "C1", Kind: "token_api",
			Request: &Request{Method: "POST", Path: p}}), nil), "T")
	}
	// Cleanup entries of token_api scenarios follow the same rule.
	requireErr(t, Validate(withScenarios(&Scenario{ID: "T2", Claim: "C1", Kind: "token_api",
		Request: &Request{Method: "POST", Path: "/api/tokens"},
		Cleanup: []Request{{Method: "DELETE", Path: "/repos/{{.RepoW}}/x"}}}), nil), "T2", "cleanup", "/api/tokens")
}
