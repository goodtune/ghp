package ghdebug

import (
	"os"
	"strings"
	"testing"
)

func TestParse_PRList(t *testing.T) {
	f, err := os.Open("testdata/pr_list.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ex, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex) != 2 {
		t.Fatalf("got %d exchanges, want 2", len(ex))
	}
	rest := ex[0]
	if rest.Method != "GET" || rest.Path != "/repos/cli/cli/readme" || rest.GraphQL != nil || rest.Status != 200 {
		t.Errorf("rest exchange = %+v", rest)
	}
	if !strings.Contains(rest.ResponseBody, `"README.md"`) {
		t.Errorf("rest body = %q", rest.ResponseBody)
	}
	g := ex[1]
	if g.Path != "/graphql" || g.Method != "POST" || g.URL != "https://api.github.com/graphql" {
		t.Errorf("graphql exchange = %+v", g)
	}
	if g.GraphQL == nil {
		t.Fatal("GraphQL nil")
	}
	if g.GraphQL.OperationName != "PullRequestList" {
		t.Errorf("OperationName = %q", g.GraphQL.OperationName)
	}
	if g.GraphQL.Variables["owner"] != "cli" {
		t.Errorf("owner = %v", g.GraphQL.Variables["owner"])
	}
	if !strings.Contains(g.GraphQL.Query, "repository(owner: $owner") || strings.Contains(g.GraphQL.Query, "GraphQL variables") {
		t.Errorf("query = %q", g.GraphQL.Query)
	}
	if g.Status != 200 {
		t.Errorf("Status = %d", g.Status)
	}
	if got := g.RequestHeaders.Get("Authorization"); got != "[REDACTED]" {
		t.Errorf("Authorization = %q", got)
	}
	if !strings.HasPrefix(g.ResponseBody, "{") || !strings.HasSuffix(g.ResponseBody, "}") {
		t.Errorf("body = %q", g.ResponseBody)
	}
}

func TestParse_Edge(t *testing.T) {
	tests := []struct {
		name, in   string
		status     int
		op         string
		bodyHas    string
		bodyHasNot string
	}{
		{
			name:   "denied and anonymous json body graphql",
			in:     "* Request at x\n* Request to https://h/graphql\n> POST /graphql HTTP/1.1\n> Authorization: bearer ghx_test00000000\n\n{\"query\":\"query { viewer { login } }\"}\n\n< HTTP/2.0 403 Forbidden\n\n{\"message\":\"no ghx_test00000000\"}\n",
			status: 403, bodyHas: "ghx_[REDACTED]", bodyHasNot: "ghx_test0",
		},
		{
			name: "mutation name", status: 200, op: "AddLabel",
			in: "* Request at x\n* Request to https://h/graphql\n> POST /graphql HTTP/1.1\n\nGraphQL query:\nmutation AddLabel($id: ID!) { x }\nGraphQL variables: {}\n\n< HTTP/2.0 200 OK\n\n{}\n",
		},
		{name: "no response", status: 0, in: "* Request at x\n* Request to https://h/user\n> GET /user HTTP/1.1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex, err := Parse(strings.NewReader(tt.in))
			if err != nil || len(ex) != 1 {
				t.Fatalf("ex=%v err=%v", ex, err)
			}
			e := ex[0]
			if e.Status != tt.status {
				t.Errorf("Status = %d", e.Status)
			}
			if tt.op != "" && (e.GraphQL == nil || e.GraphQL.OperationName != tt.op) {
				t.Errorf("GraphQL = %+v", e.GraphQL)
			}
			if tt.bodyHas != "" && !strings.Contains(e.ResponseBody, tt.bodyHas) {
				t.Errorf("body = %q", e.ResponseBody)
			}
			if tt.bodyHasNot != "" && strings.Contains(e.ResponseBody, tt.bodyHasNot) {
				t.Errorf("body leaked: %q", e.ResponseBody)
			}
			if e.RequestHeaders.Get("Authorization") != "" && e.RequestHeaders.Get("Authorization") != "[REDACTED]" {
				t.Errorf("auth leaked")
			}
		})
	}
}

func TestParse_BodyCap(t *testing.T) {
	in := "* Request at x\n* Request to https://h/a\n> GET /a HTTP/1.1\n\n< HTTP/2.0 200 OK\n\n" + strings.Repeat("a", 100*1024) + "\n"
	ex, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(ex[0].ResponseBody) != maxBody {
		t.Errorf("len = %d", len(ex[0].ResponseBody))
	}
}

func TestFirstDenied(t *testing.T) {
	ex := []Exchange{{Status: 200}, {Status: 0}, {Status: 403, Path: "/a"}, {Status: 404, Path: "/b"}}
	if d := FirstDenied(ex); d == nil || d.Path != "/a" {
		t.Errorf("got %+v", d)
	}
	if FirstDenied(ex[:2]) != nil {
		t.Error("want nil")
	}
}
