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
		&Scenario{ID: "G2", Claim: "C1", Profile: "all", Kind: "graphql", Query: mut},
		&Scenario{ID: "G3", Claim: "C1", Profile: "p", Kind: "graphql",
			Query: `query { repository(owner:"{{.RepoA.Owner}}", name:"{{.RepoA.Name}}") { id } }`},
	), nil))
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
