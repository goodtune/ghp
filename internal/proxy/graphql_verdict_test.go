package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/database"
)

func TestGraphQLVerdict(t *testing.T) {
	issuesRead := tokenScopeInfo{Scopes: database.Scopes{"issues": "read"}}
	repoOR := tokenScopeInfo{Repos: []string{"o/r"}}

	// deny:mutation_unscoped is not covered: every mutation that maps to no
	// scope is an unmapped mutation root field, so the unknown-fields check
	// (deny:unmapped) rejects it first. No input reaches that branch today.
	tests := []struct {
		name         string
		si           tokenScopeInfo
		query        string
		wantReason   string
		wantStatus   int
		wantMsg      string
		wantRepo     string
		wantAnalyzed bool
	}{
		{"open shortcut", tokenScopeInfo{}, `{viewer{login}}`, reasonAllow, 0, "", "", false},
		{"parse error", issuesRead, `{`, reasonParse, 400, "Invalid request: graphql:", "", true},
		{"subscription", issuesRead, `subscription{x}`, reasonSubscription, 403, "subscriptions are not supported", "", true},
		{"unmapped", issuesRead, `{repository(owner:"o",name:"r"){foo{bar}}}`, reasonUnmapped, 403, "unmapped fields: foo", "", true},
		// The brief's original input (root `search`) is also an unmapped field,
		// so it hits deny:unmapped first. Root `nodes` is always-allowed but
		// cross-repo at root, so it reaches the cross-repo branch.
		{"cross repo", repoOR, `{nodes(ids:["x"]){id}}`, reasonCrossRepo, 403, "cross-repository fields: nodes", "", true},
		{"mutation repo", repoOR, `mutation{createIssue(input:{repositoryId:"x",title:"t"}){issue{id}}}`, reasonMutationRepo, 403, "mutations are not supported", "", true},
		{"unpinned", repoOR, `query($o:String!){repository(owner:$o,name:"r"){name}}`, reasonUnpinned, 403, "literal string arguments", "", true},
		{"no repo ref", repoOR, `{viewer{login}}`, reasonNoRepoRef, 403, "must reference repository(owner, name)", "", true},
		{"repo not allowed", repoOR, `{repository(owner:"o",name:"other"){name}}`, reasonRepoNotAllowed, 403, "Token is not scoped to o/other", "o/other", true},
		{"missing scope", issuesRead, `{repository(owner:"o",name:"r"){pullRequests(first:1){nodes{number}}}}`, reasonMissingScope, 403, "pull_requests:read", "", true},
		{"allow repo", repoOR, `{repository(owner:"o",name:"r"){name}}`, reasonAllow, 0, "", "o/r", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"query": tt.query})
			if err != nil {
				t.Fatal(err)
			}
			d := graphQLVerdict(body, tt.si)
			if d.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q (msg %q)", d.Reason, tt.wantReason, d.Message)
			}
			if d.Status != tt.wantStatus {
				t.Errorf("Status = %d, want %d", d.Status, tt.wantStatus)
			}
			if d.Allow != (tt.wantReason == reasonAllow) {
				t.Errorf("Allow = %v", d.Allow)
			}
			if !strings.Contains(d.Message, tt.wantMsg) {
				t.Errorf("Message = %q, want substring %q", d.Message, tt.wantMsg)
			}
			if d.Repo != tt.wantRepo {
				t.Errorf("Repo = %q, want %q", d.Repo, tt.wantRepo)
			}
			if d.Analyzed != tt.wantAnalyzed {
				t.Errorf("Analyzed = %v, want %v", d.Analyzed, tt.wantAnalyzed)
			}
		})
	}
}
