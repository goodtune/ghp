package ghdebug

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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
// OWNER, REPO and 1, clears endCursor, and rewrites "owner/repo"
// (case-insensitive) to "OWNER/REPO" in the query and in other string values.
// It fails closed: it returns an error if a token-shaped string, or the real
// owner, repo or owner/repo, remains in the query, operation name or any
// variable. g is not modified.
func Sanitise(g GraphQLRequest, owner, repo string) (GraphQLRequest, error) {
	slug := slugPattern(owner, repo)
	out := GraphQLRequest{Query: replaceSlug(g.Query, slug).(string), OperationName: g.OperationName}
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
				out.Variables[k] = replaceSlug(v, slug)
			}
		}
	}
	ident := identityPattern(owner, repo)
	text := []byte(out.Query + "\n" + out.OperationName)
	if redact.Contains(text) {
		return GraphQLRequest{}, errors.New("ghdebug: token-shaped string in GraphQL query")
	}
	if ident != nil && ident.Match(text) {
		return GraphQLRequest{}, errors.New("ghdebug: owner or repo name remains in GraphQL query")
	}
	if out.Variables != nil {
		b, err := json.Marshal(out.Variables)
		if err != nil {
			return GraphQLRequest{}, fmt.Errorf("ghdebug: encode variables: %w", err)
		}
		if redact.Contains(b) {
			return GraphQLRequest{}, errors.New("ghdebug: token-shaped string in GraphQL variables")
		}
		if ident != nil && ident.Match(b) {
			return GraphQLRequest{}, errors.New("ghdebug: owner or repo name remains in GraphQL variables")
		}
	}
	return out, nil
}

// slugPattern matches "owner/repo" case-insensitively; nil if either is empty.
func slugPattern(owner, repo string) *regexp.Regexp {
	if owner == "" || repo == "" {
		return nil
	}
	return regexp.MustCompile(`(?i)` + regexp.QuoteMeta(owner+"/"+repo))
}

// identityPattern matches the owner or repo as a whole word,
// case-insensitively. The anchors are "start of text or a non-word
// character" on each side rather than \b: \b needs a word character next to
// the boundary, so a name that starts or ends with a non-word character
// (".github", "repo-") would never match and the check would fail open.
func identityPattern(owner, repo string) *regexp.Regexp {
	var alts []string
	for _, s := range []string{owner, repo} {
		if s != "" {
			alts = append(alts, regexp.QuoteMeta(s))
		}
	}
	if len(alts) == 0 {
		return nil
	}
	return regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])(?:` + strings.Join(alts, "|") + `)(?:$|[^A-Za-z0-9_])`)
}

func replaceSlug(v any, slug *regexp.Regexp) any {
	switch t := v.(type) {
	case string:
		if slug == nil {
			return t
		}
		return slug.ReplaceAllLiteralString(t, "OWNER/REPO")
	case []any:
		cp := make([]any, len(t))
		for i, e := range t {
			cp[i] = replaceSlug(e, slug)
		}
		return cp
	case map[string]any:
		cp := make(map[string]any, len(t))
		for k, e := range t {
			cp[k] = replaceSlug(e, slug)
		}
		return cp
	}
	return v
}
