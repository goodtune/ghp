package corpus

import (
	"bytes"
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
	defer f.Close()
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
