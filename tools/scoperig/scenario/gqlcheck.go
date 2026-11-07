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
	repoIDKeyRE = regexp.MustCompile(`(?i)^repositoryids?$`)
)

// gqlFacts is what checkGraphQL learns from a parsed document.
type gqlFacts struct {
	mutation bool
	pairs    [][2]string // owner/name pairs from any argument list or object
	strings  []string    // every string, int and enum literal
	repoIDs  []*ast.Value
	varRefs  []string // names of variables referenced in arguments
}

// GraphQLReadOnly reports whether q parses and every operation in it is a
// query (no mutation or subscription). Unparseable documents are not
// read-only. The runner uses it to decide whether a POST may be re-sent
// after a transport error.
func GraphQLReadOnly(q string) bool {
	doc, err := parser.ParseQuery(&ast.Source{Input: q})
	if err != nil || len(doc.Operations) == 0 {
		return false
	}
	for _, op := range doc.Operations {
		if op.Operation != ast.Query {
			return false
		}
	}
	return true
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
		case ast.Variable:
			f.varRefs = append(f.varRefs, v.Raw)
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
//
// sc and before identify where step captures may come from: only steps of
// sc with index < before (before < 0 means any step).
func checkGraphQL(where string, sc *Scenario, before int, q string, vars, rawVars map[string]any, prof *Profile, v *Vars, add func(string, ...any)) {
	scenarioID := sc.ID
	f, err := parseGraphQL(q)
	if err != nil {
		if strings.Contains(q, "mutation") {
			add("%s: cannot parse GraphQL that looks like a mutation: %v", where, err)
		}
		return
	}
	if !f.mutation {
		return
	}
	w := v.RepoW.String()

	// A mutation may only use variables that have a value here; otherwise
	// the runner (or gh nested -f syntax) could supply an unchecked value.
	seenVar := map[string]bool{}
	for _, name := range f.varRefs {
		if seenVar[name] {
			continue
		}
		seenVar[name] = true
		if val, ok := vars[name]; !ok || val == nil {
			add("%s: graphql mutation references variable $%s with no value", where, name)
		}
	}

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
			// Resolve the variable by its name in the query, whatever the
			// name is.
			ev, rv := vars[val.Raw], rawVars[val.Raw]
			es, rs := flattenStrings(ev), flattenStrings(rv)
			if len(es) == 0 {
				add("%s: repositoryId variable $%s has no value; it must be {{.RepoW.NodeID}} or a step capture", where, val.Raw)
			}
			for i, e := range es {
				r := ""
				if i < len(rs) {
					r = rs[i]
				}
				checkRepoIDValue(where, "$"+val.Raw, e, r, sc, before, v, add)
			}
			continue
		}
		if val.Raw != v.RepoW.NodeID {
			add("%s: graphql mutation repositoryId literal %q must be {{.RepoW.NodeID}}", where, val.Raw)
		}
	}
	checkRepoIDVars(where, vars, rawVars, sc, before, v, add)
}

var stepRefRE = regexp.MustCompile(`^\{\{\s*\.Step\.(\w+)\.(\w+)\s*\}\}$`)

// checkRepoIDValue accepts a repositoryId value only if it is W's node ID or
// exactly a capture from an earlier step whose query pins only W.
func checkRepoIDValue(where, name, expanded, raw string, sc *Scenario, before int, v *Vars, add func(string, ...any)) {
	if expanded == v.RepoW.NodeID {
		return
	}
	m := stepRefRE.FindStringSubmatch(raw)
	if m == nil {
		add("%s: repositoryId %s=%q must be {{.RepoW.NodeID}} or exactly {{.Step.<step>.<capture>}}", where, name, expanded)
		return
	}
	for i, st := range sc.Steps {
		if before >= 0 && i >= before {
			break
		}
		if st.Name != m[1] {
			continue
		}
		if _, ok := st.Capture[m[2]]; !ok {
			add("%s: repositoryId %s: step %q has no capture %q", where, name, m[1], m[2])
			return
		}
		bm, _ := st.Body.(map[string]any)
		rq, _ := bm["query"].(string)
		q, err := Expand(rq, v)
		if err != nil {
			add("%s: repositoryId %s: step %q query: %v", where, name, m[1], err)
			return
		}
		f, err := parseGraphQL(q)
		if err != nil || len(f.pairs) == 0 {
			add("%s: repositoryId %s: step %q must be a GraphQL query pinning repository(owner, name) to {{.RepoW}}", where, name, m[1])
			return
		}
		for _, p := range f.pairs {
			if p[0]+"/"+p[1] != v.RepoW.String() {
				add("%s: repositoryId %s: step %q references %s/%s, not {{.RepoW}}", where, name, m[1], p[0], p[1])
			}
		}
		return
	}
	add("%s: repositoryId %s: no earlier step named %q", where, name, m[1])
}

func checkRepoIDVars(where string, vars, raw map[string]any, sc *Scenario, before int, v *Vars, add func(string, ...any)) {
	for k, val := range vars {
		var rv any
		if raw != nil {
			rv = raw[k]
		}
		if repoIDKeyRE.MatchString(k) {
			rs := flattenStrings(rv)
			for i, s := range flattenStrings(val) {
				r := ""
				if i < len(rs) {
					r = rs[i]
				}
				checkRepoIDValue(where, k, s, r, sc, before, v, add)
			}
			continue
		}
		if m, ok := val.(map[string]any); ok {
			rm, _ := rv.(map[string]any)
			checkRepoIDVars(where, m, rm, sc, before, v, add)
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
