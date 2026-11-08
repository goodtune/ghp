package scenario

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/corpus"
)

// corpusDenyMessages maps each corpus verdict to the fixed text of the GHP
// denial it produces (internal/proxy/graphql_verdict.go). "allow" and
// "parse" are handled separately.
var corpusDenyMessages = map[string]string{
	"deny:subscription":      "GraphQL subscriptions are not supported",
	"deny:unmapped":          "GraphQL request references unmapped fields",
	"deny:cross_repo":        "uses cross-repository fields",
	"deny:mutation_repo":     "GraphQL mutations are not supported for repository-scoped tokens",
	"deny:unpinned":          "must use literal string arguments",
	"deny:no_repo_ref":       "must reference repository(owner, name)",
	"deny:repo_not_allowed":  "Token is not scoped to",
	"deny:mutation_unscoped": "GraphQL mutation could not be statically scoped",
	"deny:missing_scope":     "Token does not grant required GraphQL scopes",
}

// corpusExpect returns the expectation for a corpus verdict. An allowed
// request must reach GitHub (200, not a GHP denial); GitHub may still report
// GraphQL errors for the placeholder numbers, which is not GHP's verdict.
func corpusExpect(verdict string) (*Expect, error) {
	f, t := false, true
	switch verdict {
	case "allow":
		return &Expect{Status: 200, GHPDenial: &f}, nil
	case "parse":
		return &Expect{Status: 400}, nil
	}
	msg, ok := corpusDenyMessages[verdict]
	if !ok {
		return nil, fmt.Errorf("unknown corpus verdict %q", verdict)
	}
	return &Expect{Status: 403, GHPDenial: &t, BodyContains: []string{msg}}, nil
}

// expandCorpus replaces a kind "corpus" generator with one graphql scenario
// per corpus entry and corpus profile. The corpus placeholders OWNER, REPO
// and NODE_ID in variables become fixture A's owner, name and node ID. The
// generated IDs are "<gen>.<file>.<operation>.<corpus profile>". Every
// corpus profile must be mapped to a rig profile, so a new corpus profile
// cannot be skipped silently.
func expandCorpus(root string, g *Scenario) ([]*Scenario, error) {
	where := fmt.Sprintf("%s: scenario %q", g.File, g.ID)
	if g.Query != "" || len(g.Steps) > 0 || g.Method != "" || g.Path != "" || g.Profile != "" || g.Expect != nil ||
		g.Request != nil || len(g.Args) > 0 || g.Variables != nil || g.KnownIssue != "" || g.Observed != nil ||
		len(g.Cleanup) > 0 || g.OperationName != "" {
		return nil, fmt.Errorf("%s: kind corpus takes only id, claim, doc, description, requires, corpus and corpus_profiles", where)
	}
	if g.Corpus == "" || !filepath.IsLocal(g.Corpus) {
		return nil, fmt.Errorf("%s: corpus %q must be a directory inside the rig root", where, g.Corpus)
	}
	files, err := filepath.Glob(filepath.Join(root, g.Corpus, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("%s: glob corpus: %w", where, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no corpus files in %s", where, g.Corpus)
	}
	sort.Strings(files)
	var out []*Scenario
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		var f corpus.File
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", where, path, err)
		}
		stem := strings.TrimSuffix(filepath.Base(path), ".json")
		for _, e := range f.GraphQL {
			op := strings.Trim(e.Operation, "()")
			profs := make([]string, 0, len(e.Expect))
			for p := range e.Expect {
				profs = append(profs, p)
			}
			sort.Strings(profs)
			for _, cp := range profs {
				x := e.Expect[cp]
				rp, ok := g.CorpusProfiles[cp]
				if !ok {
					return nil, fmt.Errorf("%s: %s %s: corpus profile %q has no entry in corpus_profiles", where, stem, e.Operation, cp)
				}
				want, err := corpusExpect(x.Verdict)
				if err != nil {
					return nil, fmt.Errorf("%s: %s %s %s: %w", where, stem, e.Operation, cp, err)
				}
				s := &Scenario{
					ID:    fmt.Sprintf("%s.%s.%s.%s", g.ID, stem, op, cp),
					Claim: g.Claim, Doc: g.Doc,
					Description: fmt.Sprintf("gh %s %s replayed with profile %s (corpus %s); corpus verdict %s.",
						f.Command, e.Operation, rp, cp, x.Verdict),
					Profile: rp, Kind: "graphql", Requires: g.Requires,
					Query:         escapeTemplate(e.Body.Query),
					OperationName: e.Body.OperationName,
					Expect:        want,
					File:          g.File,
				}
				if len(e.Body.Variables) > 0 {
					s.Variables = corpusVars(e.Body.Variables).(map[string]any)
				}
				if x.KnownIssue != "" {
					obs, err := corpusExpect(x.Current)
					if err != nil {
						return nil, fmt.Errorf("%s: %s %s %s: current: %w", where, stem, e.Operation, cp, err)
					}
					s.KnownIssue, s.Observed = x.KnownIssue, obs
				}
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// escapeTemplate makes s expand to itself as a text/template.
func escapeTemplate(s string) string {
	return strings.ReplaceAll(s, "{{", `{{"{{"}}`)
}

// corpusVars rewrites the corpus placeholders in every string value.
func corpusVars(x any) any {
	switch t := x.(type) {
	case string:
		t = escapeTemplate(t)
		t = strings.ReplaceAll(t, corpus.NodeIDPlaceholder, "{{.RepoA.NodeID}}")
		t = strings.ReplaceAll(t, "OWNER", "{{.RepoA.Owner}}")
		return strings.ReplaceAll(t, "REPO", "{{.RepoA.Name}}")
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			out[k] = corpusVars(v)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, v := range t {
			out[i] = corpusVars(v)
		}
		return out
	}
	return x
}
