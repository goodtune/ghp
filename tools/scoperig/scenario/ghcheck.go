package scenario

import (
	"regexp"
	"strings"
)

// ghReadOnly lists gh subcommands (group + action) that never write.
// "search *" and "api" are handled separately.
var ghReadOnly = map[string]bool{
	"repo view": true, "repo list": true,
	"pr list": true, "pr view": true, "pr status": true, "pr checks": true, "pr diff": true,
	"issue list": true, "issue view": true,
	"release list": true, "release view": true,
	"label list": true,
	"run list":   true, "run view": true,
	"workflow list": true, "workflow view": true,
	"auth status": true,
}

// ghFlagsWithValue are flags whose next argument is a value, not a
// positional. Unknown flags are assumed to take no value; that only makes
// repo extraction stricter (more positionals are inspected).
var ghFlagsWithValue = map[string]bool{
	"-R": true, "--repo": true, "-X": true, "--method": true, "-f": true, "-F": true,
	"--field": true, "--raw-field": true, "--input": true, "-H": true, "--header": true,
	"-q": true, "--jq": true, "-t": true, "--template": true, "--json": true, "-L": true,
	"--limit": true, "-s": true, "--state": true, "-l": true, "--label": true,
	"-a": true, "--assignee": true, "-A": true, "--author": true, "-B": true, "--base": true,
	"--hostname": true, "-b": true, "--body": true, "--title": true,
}

var (
	ghRepoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	ghURLRE  = regexp.MustCompile(`^https?://[^/]+/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)`)
)

type ghArgs struct {
	positionals []string
	flags       map[string][]string
}

func parseGHArgs(args []string) ghArgs {
	g := ghArgs{flags: map[string][]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			g.positionals = append(g.positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "--") && strings.Contains(a, "=") {
			k, val, _ := strings.Cut(a, "=")
			g.flags[k] = append(g.flags[k], val)
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 2 && !strings.HasPrefix(a, "--") {
			// short flag with attached value, e.g. -XPOST, -Rowner/name
			k := a[:2]
			if ghFlagsWithValue[k] {
				g.flags[k] = append(g.flags[k], strings.TrimPrefix(a[2:], "="))
				continue
			}
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if ghFlagsWithValue[a] && i+1 < len(args) {
				g.flags[a] = append(g.flags[a], args[i+1])
				i++
			} else {
				g.flags[a] = append(g.flags[a], "")
			}
			continue
		}
		g.positionals = append(g.positionals, a)
	}
	return g
}

func (g ghArgs) all(names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, g.flags[n]...)
	}
	return out
}

func repoFromSpec(spec string) string {
	if m := ghURLRE.FindStringSubmatch(spec); m != nil {
		return m[1] + "/" + strings.TrimSuffix(m[2], ".git")
	}
	parts := strings.Split(strings.Trim(spec, "/"), "/")
	if len(parts) == 3 { // host/owner/name
		parts = parts[1:]
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0] + "/" + parts[1]
	}
	return spec
}

// checkGH applies the write target rule to a gh invocation. repoKey is the
// scenario's repo: field (A, B or W), which the runner exports as the
// default repository.
func checkGH(args, rawArgs []string, sc *Scenario, prof *Profile, v *Vars, add func(string, ...any)) {
	repoKey := sc.Repo
	if len(args) > 0 && args[0] == "gh" {
		args = args[1:]
		rawArgs = rawArgs[1:]
	}
	g := parseGHArgs(args)
	rg := parseGHArgs(rawArgs)
	pos := g.positionals

	var refs []string
	switch repoKey {
	case "":
	case "A":
		refs = append(refs, v.RepoA.String())
	case "B":
		refs = append(refs, v.RepoB.String())
	case "W":
		refs = append(refs, v.RepoW.String())
	default:
		add("gh: repo %q must be A, B or W", repoKey)
	}
	for _, r := range g.all("-R", "--repo") {
		refs = append(refs, repoFromSpec(r))
	}

	group, action := "", ""
	if len(pos) > 0 {
		group = pos[0]
	}
	if len(pos) > 1 {
		action = pos[1]
	}

	read := false
	switch {
	case group == "search":
		read = true
		for _, p := range pos[1:] {
			if ghRepoRE.MatchString(p) || ghURLRE.MatchString(p) {
				refs = append(refs, repoFromSpec(p))
			}
		}
	case group == "api":
		endpoint := strings.TrimPrefix(action, "/")
		if endpoint == "graphql" {
			checkGHGraphQL(g, rg, sc, prof, v, add)
			return
		}
		read = true
		for _, m := range g.all("-X", "--method") {
			if !strings.EqualFold(m, "GET") {
				read = false
			}
		}
		if len(g.all("-f", "-F", "--field", "--raw-field", "--input")) > 0 {
			read = false
		}
		ep := strings.SplitN(endpoint, "?", 2)[0]
		clean, err := normalisePath("/" + ep)
		if err != nil {
			add("gh: api endpoint: %v", err)
			return
		}
		if !read {
			// Non-GET api calls must target W's REST namespace; no other
			// endpoint (user/starred, repositories/<id>, orgs, ...) is allowed.
			if !strings.HasPrefix(clean, "/repos/"+v.RepoW.String()+"/") {
				add("gh: write api endpoint %q must start with repos/{{.RepoW}}/", endpoint)
			}
			return
		}
		for _, p := range pos[2:] {
			if ghRepoRE.MatchString(p) || ghURLRE.MatchString(p) {
				refs = append(refs, repoFromSpec(p))
			}
		}
	default:
		read = ghReadOnly[group+" "+action]
		for _, p := range pos[min(2, len(pos)):] {
			if ghRepoRE.MatchString(p) || ghURLRE.MatchString(p) {
				refs = append(refs, repoFromSpec(p))
			}
		}
	}
	if read {
		return
	}
	if len(refs) == 0 {
		add("gh: write command %q names no repository; writes must target {{.RepoW}}", strings.Join(args, " "))
		return
	}
	w := v.RepoW.String()
	for _, r := range refs {
		if r != w {
			add("gh: write command %q references %s; writes must target {{.RepoW}}", strings.Join(args, " "), r)
		}
	}
}

// checkGHGraphQL treats `gh api graphql` like a graphql scenario: the query
// must parse (fail closed), and mutations go through checkGraphQL with the
// -f/-F key=value fields as variables.
func checkGHGraphQL(g, rg ghArgs, sc *Scenario, prof *Profile, v *Vars, add func(string, ...any)) {
	if len(g.all("--input")) > 0 {
		add("gh: api graphql --input is not allowed; pass the query with -f query=")
		return
	}
	fields := g.all("-f", "-F", "--field", "--raw-field")
	rawFields := rg.all("-f", "-F", "--field", "--raw-field")
	vars, rawVars := map[string]any{}, map[string]any{}
	query, queries := "", 0
	for i, fv := range fields {
		k, val, _ := strings.Cut(fv, "=")
		if k == "query" {
			query = val
			queries++
			continue
		}
		vars[k] = val
		if i < len(rawFields) {
			_, rv, _ := strings.Cut(rawFields[i], "=")
			rawVars[k] = rv
		}
	}
	if queries != 1 || strings.HasPrefix(query, "@") {
		add("gh: api graphql needs exactly one inline -f query=")
		return
	}
	if _, err := parseGraphQL(query); err != nil {
		add("gh: api graphql query does not parse: %v", err)
		return
	}
	checkGraphQL("gh: api graphql", sc, -1, query, vars, rawVars, prof, v, add)
}
