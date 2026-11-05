package corpus

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
)

func loadPRList(t *testing.T) []ghdebug.Exchange {
	t.Helper()
	f, err := os.Open("../ghdebug/testdata/pr_list.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ex, err := ghdebug.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return ex
}

func TestBuild_PRList(t *testing.T) {
	f, err := Build("2.102.0", "pr list", "cli", "cli", loadPRList(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.GraphQL) != 1 {
		t.Fatalf("got %d entries, want 1", len(f.GraphQL))
	}
	e := f.GraphQL[0]
	if e.Operation != "PullRequestList" {
		t.Errorf("Operation = %q", e.Operation)
	}
	if e.Body.Variables["owner"] != "OWNER" {
		t.Errorf("owner = %v", e.Body.Variables["owner"])
	}
	if len(e.Expect) != 3 {
		t.Errorf("Expect has %d keys, want 3", len(e.Expect))
	}
	for _, p := range Profiles {
		if e.Expect[p].Verdict != "allow" {
			t.Errorf("Expect[%s] = %+v", p, e.Expect[p])
		}
	}
}

func TestBuild_CopiesPrevExpect(t *testing.T) {
	prev := &File{GraphQL: []Entry{{
		Operation: "PullRequestList",
		Expect:    map[string]Expectation{"open": {Verdict: "allow"}, "perm-ro": {Verdict: "deny", KnownIssue: "#1"}, "repo": {Verdict: "allow"}},
	}}}
	f, err := Build("2.102.0", "pr list", "cli", "cli", loadPRList(t), prev)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.GraphQL[0].Expect["perm-ro"]; got.Verdict != "deny" || got.KnownIssue != "#1" {
		t.Errorf("perm-ro = %+v", got)
	}
}

func TestBuild_RESTPathsAndInterleaved(t *testing.T) {
	ex := []ghdebug.Exchange{
		{Method: "GET", Path: "/repos/Cli/cli/pulls/14927"},
		{Method: "GET", Path: "/repos/cli/cli/readme"},
		{Method: "GET", Path: "/repos/cli/cli/readme"},
		{Method: "GET", Path: "/search/issues?q=x"},
		{Method: "POST", Path: "/graphql", Interleaved: true, GraphQL: &ghdebug.GraphQLRequest{Query: "query X { a }", OperationName: "X"}},
	}
	f, err := Build("2.102.0", "x", "cli", "cli", ex, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /repos/OWNER/REPO/pulls/1", "GET /repos/OWNER/REPO/readme", "GET /search/issues"}
	if len(f.REST) != len(want) {
		t.Fatalf("REST = %v", f.REST)
	}
	for i := range want {
		if f.REST[i] != want[i] {
			t.Errorf("REST[%d] = %q, want %q", i, f.REST[i], want[i])
		}
	}
	if len(f.GraphQL) != 0 || len(f.SkippedInterleaved) != 1 || f.SkippedInterleaved[0] != "POST /graphql X" {
		t.Errorf("graphql=%v skipped=%v", f.GraphQL, f.SkippedInterleaved)
	}
}

func TestBuild_RejectsIdentityInPath(t *testing.T) {
	ex := []ghdebug.Exchange{{Method: "GET", Path: "/users/goodtune"}}
	if _, err := Build("2.102.0", "x", "goodtune", "ghp", ex, nil); err != nil {
		t.Fatalf("owner segment should be replaced: %v", err)
	}
	ex = []ghdebug.Exchange{{Method: "GET", Path: "/orgs/goodtune-x/ghp-y"}}
	if _, err := Build("2.102.0", "x", "goodtune", "ghp", ex, nil); err == nil {
		t.Fatal("want error for surviving identity")
	}
}

func TestMarshal_Deterministic(t *testing.T) {
	f, err := Build("2.102.0", "pr list", "cli", "cli", loadPRList(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Marshal(f)
	if !bytes.Equal(a, b) || !bytes.HasSuffix(a, []byte("}\n")) {
		t.Fatal("non-deterministic or missing trailing newline")
	}
}

func TestBuild_ReplacesNodeIDs(t *testing.T) {
	legacy := base64.StdEncoding.EncodeToString([]byte("011:PullRequest12345678"))
	ex := []ghdebug.Exchange{{Method: "POST", Path: "/graphql", GraphQL: &ghdebug.GraphQLRequest{
		Query: "query Q { a }", OperationName: "Q",
		Variables: map[string]any{"id": "PR_kwDOAbCdEf4", "repoId": "R_kgDOAbCdEf", "nested": map[string]any{"ids": []any{legacy, "plain"}}},
	}}}
	f, err := Build("2.102.0", "x", "cli", "cli", ex, nil)
	if err != nil {
		t.Fatal(err)
	}
	v := f.GraphQL[0].Body.Variables
	if v["id"] != "NODE_ID" {
		t.Errorf("id = %v", v["id"])
	}
	if v["repoId"] != "NODE_ID" {
		t.Errorf("repoId = %v", v["repoId"])
	}
	ids := v["nested"].(map[string]any)["ids"].([]any)
	if ids[0] != "NODE_ID" || ids[1] != "plain" {
		t.Errorf("ids = %v", ids)
	}
	ex[0].GraphQL.Variables = nil
	ex[0].GraphQL.Query = `query Q { node(id: "PR_kwDOAbCdEf4") { id } }`
	if _, err := Build("2.102.0", "x", "cli", "cli", ex, nil); err == nil {
		t.Fatal("want error for node ID left in query")
	}
}

func TestBuild_RejectsIdentityInCommand(t *testing.T) {
	if _, err := Build("2.102.0", "api repos cli cli", "cli", "cli", nil, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestCommandName(t *testing.T) {
	for in, want := range map[string]string{
		"api_repos_cli_cli":  "api repos OWNER REPO",
		"api_repos_Good_ghp": "api repos OWNER REPO",
		"pr_list":            "pr list",
	} {
		owner, repo := "cli", "cli"
		if in == "api_repos_Good_ghp" {
			owner, repo = "good", "ghp"
		}
		if got := CommandName(in, owner, repo); got != want {
			t.Errorf("CommandName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpectFor_FillsMissingProfiles(t *testing.T) {
	prev := &File{GraphQL: []Entry{{Operation: "Q", Expect: map[string]Expectation{"perm-ro": {Verdict: "deny"}}}}}
	e := expectFor("Q", prev)
	if len(e) != 3 || e["open"].Verdict != "allow" || e["perm-ro"].Verdict != "deny" {
		t.Errorf("got %+v", e)
	}
}

func TestContainsNodeID_KG(t *testing.T) {
	if !containsNodeID([]byte(`{"q":"node(id: \"R_kgDOAbCdEf\")"}`)) {
		t.Fatal("R_kg node ID not detected")
	}
}
