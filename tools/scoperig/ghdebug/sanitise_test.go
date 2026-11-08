package ghdebug

import (
	"encoding/json"
	"testing"
)

func TestSanitise(t *testing.T) {
	g := GraphQLRequest{
		Query: "query Q { x }",
		Variables: map[string]any{
			"owner": "cli", "repo": "cli", "name": "cli", "number": json.Number("14938"),
			"prNumber": json.Number("1"), "issueNumber": json.Number("2"), "selector": "123",
			"endCursor": "Y3Vy", "limit": json.Number("30"), "pr_number": json.Number("14927"),
			"viewerQuery": "repo:cli/cli is:pr",
		},
		OperationName: "Q",
	}
	out, err := Sanitise(g, "cli", "cli")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"owner": "OWNER", "repo": "REPO", "name": "REPO", "number": json.Number("1"),
		"prNumber": json.Number("1"), "issueNumber": json.Number("1"), "selector": "1", "endCursor": nil, "pr_number": json.Number("1"), "viewerQuery": "repo:OWNER/REPO is:pr"}
	for k, v := range want {
		if out.Variables[k] != v {
			t.Errorf("%s = %#v, want %#v", k, out.Variables[k], v)
		}
	}
	if out.Variables["limit"] != json.Number("30") {
		t.Errorf("limit = %#v", out.Variables["limit"])
	}
	if g.Variables["owner"] != "cli" {
		t.Error("input mutated")
	}

	if _, err := Sanitise(GraphQLRequest{Query: "query { x(a: \"ghx_aaaaaaaaaaaa\") }"}, "o", "r"); err == nil {
		t.Error("want error for token in query")
	}
	if _, err := Sanitise(GraphQLRequest{Query: "q", Variables: map[string]any{"body": []any{"gho_aaaaaaaaaaaa"}}}, "o", "r"); err == nil {
		t.Error("want error for token in variables")
	}
	if _, err := Sanitise(GraphQLRequest{Query: "q", Variables: map[string]any{"login": "Octo"}}, "octo", "hello"); err == nil {
		t.Error("want error for owner in unknown variable")
	}
	out2, err := Sanitise(GraphQLRequest{Query: "q", Variables: map[string]any{"q": "repo:OCTO/Hello x"}}, "octo", "hello")
	if err != nil || out2.Variables["q"] != "repo:OWNER/REPO x" {
		t.Errorf("case-insensitive slug: %v %v", out2.Variables["q"], err)
	}
}

// Names with leading or trailing non-word characters must still be caught
// (a \b anchor never matches next to them).
func TestSanitise_IdentityNonWordEdges(t *testing.T) {
	for _, tc := range []struct{ owner, repo, leak string }{
		{"octo", ".github", "see .github here"},
		{"octo", "repo-", "x repo- y"},
		{"-octo", "r", "user -octo"},
		{"octo", "_r_", "(_r_)"},
		{"octo", "hello", "HELLO"},
	} {
		t.Run(tc.owner+"/"+tc.repo, func(t *testing.T) {
			if _, err := Sanitise(GraphQLRequest{Query: "q", Variables: map[string]any{"login": tc.leak}}, tc.owner, tc.repo); err == nil {
				t.Errorf("identity %q survived in variables", tc.leak)
			}
			if _, err := Sanitise(GraphQLRequest{Query: "query { x(a: \"" + tc.leak + "\") }"}, tc.owner, tc.repo); err == nil {
				t.Errorf("identity %q survived in query", tc.leak)
			}
		})
	}
	// Substrings of longer words are not identities.
	if _, err := Sanitise(GraphQLRequest{Query: "query { client }"}, "cli", "cli"); err != nil {
		t.Errorf("substring flagged: %v", err)
	}
}
