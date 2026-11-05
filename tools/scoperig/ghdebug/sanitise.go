package ghdebug

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/redact"
)

var (
	ownerKeys  = map[string]bool{"owner": true}
	repoKeys   = map[string]bool{"repo": true, "name": true}
	numberKeys = map[string]bool{"number": true, "prNumber": true, "pr_number": true, "issueNumber": true, "selector": true}
	nilKeys    = map[string]bool{"endCursor": true}
)

// Sanitise replaces concrete owner/repo/number values in Variables with
// OWNER, REPO and 1, clears endCursor, and rewrites "owner/repo" inside other
// string values to "OWNER/REPO". It returns an error if a token-shaped string
// remains in the query, operation name or any variable. g is not modified.
func Sanitise(g GraphQLRequest, owner, repo string) (GraphQLRequest, error) {
	out := GraphQLRequest{Query: g.Query, OperationName: g.OperationName}
	if g.Variables != nil {
		out.Variables = make(map[string]any, len(g.Variables))
		for k, v := range g.Variables {
			switch {
			case ownerKeys[k]:
				out.Variables[k] = "OWNER"
			case repoKeys[k]:
				out.Variables[k] = "REPO"
			case numberKeys[k]:
				if _, isStr := v.(string); isStr {
					out.Variables[k] = "1"
				} else {
					out.Variables[k] = json.Number("1")
				}
			case nilKeys[k]:
				out.Variables[k] = nil
			default:
				out.Variables[k] = replaceSlug(v, owner, repo)
			}
		}
	}
	if redact.Contains([]byte(out.Query)) || redact.Contains([]byte(out.OperationName)) {
		return GraphQLRequest{}, errors.New("ghdebug: token-shaped string in GraphQL query")
	}
	if out.Variables != nil {
		b, err := json.Marshal(out.Variables)
		if err != nil {
			return GraphQLRequest{}, fmt.Errorf("ghdebug: encode variables: %w", err)
		}
		if redact.Contains(b) {
			return GraphQLRequest{}, errors.New("ghdebug: token-shaped string in GraphQL variables")
		}
	}
	return out, nil
}

func replaceSlug(v any, owner, repo string) any {
	switch t := v.(type) {
	case string:
		if owner != "" && repo != "" {
			return strings.ReplaceAll(t, owner+"/"+repo, "OWNER/REPO")
		}
		return t
	case []any:
		cp := make([]any, len(t))
		for i, e := range t {
			cp[i] = replaceSlug(e, owner, repo)
		}
		return cp
	case map[string]any:
		cp := make(map[string]any, len(t))
		for k, e := range t {
			cp[k] = replaceSlug(e, owner, repo)
		}
		return cp
	}
	return v
}
