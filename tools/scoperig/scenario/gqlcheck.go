package scenario

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// mutationWriteAllowlist names the reviewed scenarios that may send a
// GraphQL mutation with a token whose profile has no repository
// restriction. Every entry must be reviewed: such a token could write to any
// repository the credential can reach, so the scenario's own literals and
// variables (checked below) are the only guard. Keep this list short.
var mutationWriteAllowlist = map[string]bool{
	"GQL-C31.createissue-ro-denied":  true,
	"GQL-C31.createissue-rw-allowed": true,
}

var (
	mutationWordRE = regexp.MustCompile(`^\s*mutation\b`)
	repoIDKeyRE    = regexp.MustCompile(`(?i)^repositoryids?$`)
)

// gqlFacts is what checkGraphQL learns from a parsed document.
type gqlFacts struct {
	mutation bool
	pairs    [][2]string // owner/name pairs from any argument list or object
	strings  []string    // every string, int and enum literal
	repoIDs  []*ast.Value
}

func parseGraphQL(q string) (*gqlFacts, error) {
	doc, err := parser.ParseQuery(&ast.Source{Input: q})
	if err != nil {
		return nil, err
	}
	f := &gqlFacts{}
	var walkVal func(name string, v *ast.Value)
	walkVal = func(name string, v *ast.Value) {
		if v == nil {
			return
		}
		if repoIDKeyRE.MatchString(name) {
			f.repoIDs = append(f.repoIDs, v)
		}
		switch v.Kind {
		case ast.StringValue, ast.BlockValue, ast.IntValue, ast.EnumValue:
			f.strings = append(f.strings, v.Raw)
		case ast.ObjectValue:
			var owner, nm string
			for _, c := range v.Children {
				if c.Value != nil && c.Value.Kind == ast.StringValue {
					switch c.Name {
					case "owner":
						owner = c.Value.Raw
					case "name":
						nm = c.Value.Raw
					}
				}
				walkVal(c.Name, c.Value)
			}
			if owner != "" && nm != "" {
				f.pairs = append(f.pairs, [2]string{owner, nm})
			}
		case ast.ListValue:
			for _, c := range v.Children {
				walkVal(name, c.Value)
			}
		}
	}
	var walkSel func(ss ast.SelectionSet)
	walkSel = func(ss ast.SelectionSet) {
		for _, sel := range ss {
			switch x := sel.(type) {
			case *ast.Field:
				var owner, nm string
				for _, a := range x.Arguments {
					if a.Value != nil && a.Value.Kind == ast.StringValue {
						switch a.Name {
						case "owner":
							owner = a.Value.Raw
						case "name":
							nm = a.Value.Raw
						}
					}
					walkVal(a.Name, a.Value)
				}
				if owner != "" && nm != "" {
					f.pairs = append(f.pairs, [2]string{owner, nm})
				}
				walkSel(x.SelectionSet)
			case *ast.InlineFragment:
				walkSel(x.SelectionSet)
			}
		}
	}
	for _, op := range doc.Operations {
		if op.Operation == ast.Mutation {
			f.mutation = true
		}
		for _, vd := range op.VariableDefinitions {
			walkVal(vd.Variable, vd.DefaultValue)
		}
		walkSel(op.SelectionSet)
	}
	for _, fr := range doc.Fragments {
		walkSel(fr.SelectionSet)
	}
	return f, nil
}

// graphQLRepoPairs returns the owner/name pairs from a parsed query, for use by
// callers that only need repository references.
func graphQLRepoPairs(q string) ([][2]string, error) {
	f, err := parseGraphQL(q)
	if err != nil {
		return nil, err
	}
	return f.pairs, nil
}

// forbiddenIdents returns the identifiers of A and B that must never appear
// in a mutation.
func forbiddenIdents(v *Vars) map[string]string {
	out := map[string]string{}
	for label, r := range map[string]RepoRef{"RepoA": v.RepoA, "RepoB": v.RepoB} {
		if r.Owner != "" && r.Name != "" {
			out[strings.ToLower(r.String())] = label
		}
		if r.NodeID != "" {
			out[strings.ToLower(r.NodeID)] = label
		}
		if r.ID != 0 {
			out[strconv.FormatInt(r.ID, 10)] = label
		}
	}
	return out
}

// checkGraphQL applies the mutation rule to one GraphQL document and its
// expanded variables. rawVars are the unexpanded variables, used to accept
// repositoryId values captured from an earlier step.
func checkGraphQL(where, scenarioID, q string, vars, rawVars map[string]any, prof *Profile, v *Vars, add func(string, ...any)) {
	f, err := parseGraphQL(q)
	if err != nil {
		if mutationWordRE.MatchString(q) || strings.Contains(q, "mutation") {
			add("%s: cannot parse GraphQL that looks like a mutation: %v", where, err)
		}
		return
	}
	if !f.mutation {
		return
	}
	w := v.RepoW.String()

	// (a)/(b) profile restriction.
	if prof != nil {
		switch {
		case len(prof.Repositories) == 0:
			if !mutationWriteAllowlist[scenarioID] {
				add("%s: graphql mutation with unrestricted profile %q needs a reviewed entry in mutationWriteAllowlist", where, prof.Name)
			}
		case len(prof.Repositories) == 1:
			if r, err := Expand(prof.Repositories[0], v); err != nil || r != w {
				add("%s: graphql mutation needs a profile restricted to exactly [{{.RepoW}}]; profile %q has %v", where, prof.Name, prof.Repositories)
			}
		default:
			add("%s: graphql mutation needs a profile restricted to exactly [{{.RepoW}}]; profile %q has %v", where, prof.Name, prof.Repositories)
		}
	}

	// (c) no A/B identifiers anywhere.
	bad := forbiddenIdents(v)
	for _, p := range f.pairs {
		if p[0]+"/"+p[1] != w {
			add("%s: graphql mutation references %s/%s; only {{.RepoW}} is allowed", where, p[0], p[1])
		}
	}
	hits := map[string]bool{}
	for _, lit := range f.strings {
		if label, ok := bad[strings.ToLower(lit)]; ok {
			hits[fmt.Sprintf("literal %q (%s)", lit, label)] = true
		}
	}
	for _, sv := range flattenStrings(vars) {
		if label, ok := bad[strings.ToLower(sv)]; ok {
			hits[fmt.Sprintf("variable value %q (%s)", sv, label)] = true
		}
	}
	lower := strings.ToLower(q)
	for ident, label := range bad {
		if strings.Contains(ident, "/") && strings.Contains(lower, ident) {
			hits[fmt.Sprintf("text %q (%s)", ident, label)] = true
		}
	}
	keys := make([]string, 0, len(hits))
	for k := range hits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add("%s: graphql mutation contains %s; mutations may only target {{.RepoW}}", where, k)
	}

	// repositoryId values must come from W.
	for _, val := range f.repoIDs {
		if val.Kind == ast.Variable {
			continue // checked through vars below
		}
		if val.Raw != v.RepoW.NodeID {
			add("%s: graphql mutation repositoryId literal %q must be {{.RepoW.NodeID}}", where, val.Raw)
		}
	}
	checkRepoIDVars(where, vars, rawVars, v, add)
}

func checkRepoIDVars(where string, vars, raw map[string]any, v *Vars, add func(string, ...any)) {
	for k, val := range vars {
		var rv any
		if raw != nil {
			rv = raw[k]
		}
		if repoIDKeyRE.MatchString(k) {
			for i, s := range flattenStrings(val) {
				rs := flattenStrings(rv)
				fromStep := i < len(rs) && strings.Contains(rs[i], ".Step.")
				if s != v.RepoW.NodeID && !fromStep {
					add("%s: variable %s=%q must be {{.RepoW.NodeID}} or captured from a step", where, k, s)
				}
			}
			continue
		}
		if m, ok := val.(map[string]any); ok {
			rm, _ := rv.(map[string]any)
			checkRepoIDVars(where, m, rm, v, add)
		}
	}
}

func flattenStrings(x any) []string {
	switch t := x.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []string
		for _, k := range keys {
			out = append(out, flattenStrings(t[k])...)
		}
		return out
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, flattenStrings(e)...)
		}
		return out
	default:
		b, _ := json.Marshal(t)
		return []string{strings.Trim(string(b), `"`)}
	}
}
