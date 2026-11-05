package scenario

import (
	"fmt"
	"regexp"
	"strings"
)

// ghReadOnly lists gh subcommands (group + action) that never write. They
// keep a permissive argument parser; "search *" is also read-only.
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

// ghFlag describes one known flag: its short and long names and whether it
// takes a value.
type ghFlag struct {
	short, long string
	value       bool
}

// ghCommonFlags apply to every repo-scoped subcommand.
var ghCommonFlags = []ghFlag{{"-R", "--repo", true}}

// ghFlagTable lists, for every subcommand that may be used in a write
// scenario (and for api), every flag gh accepts and its arity, taken from
// `gh <cmd> --help`. The parser fails closed: a write or api invocation
// with a flag not listed here is rejected, because guessing arity wrongly
// lets a flag swallow the real endpoint or --repo value.
var ghFlagTable = map[string][]ghFlag{
	"api": {
		{"", "--allow-escape-sequences", false}, {"", "--cache", true},
		{"-F", "--field", true}, {"-H", "--header", true},
		// --hostname is deliberately absent: the rig must only reach the proxy.
		{"-i", "--include", false}, {"", "--input", true}, {"-q", "--jq", true},
		{"-X", "--method", true}, {"", "--paginate", false}, {"-p", "--preview", true},
		{"-f", "--raw-field", true}, {"", "--silent", false}, {"", "--slurp", false},
		{"-t", "--template", true}, {"", "--verbose", false},
	},
	"pr merge": {
		{"", "--admin", false}, {"-A", "--author-email", true}, {"", "--auto", false},
		{"-b", "--body", true}, {"-F", "--body-file", true}, {"-d", "--delete-branch", false},
		{"", "--disable-auto", false}, {"", "--match-head-commit", true}, {"-m", "--merge", false},
		{"-r", "--rebase", false}, {"-s", "--squash", false}, {"-t", "--subject", true},
	},
	"issue create": {
		{"-a", "--assignee", true}, {"", "--attach", true}, {"", "--blocked-by", true},
		{"", "--blocking", true}, {"-b", "--body", true}, {"-F", "--body-file", true},
		{"-e", "--editor", false}, {"-l", "--label", true}, {"-m", "--milestone", true},
		{"", "--parent", true}, {"-p", "--project", true}, {"", "--recover", true},
		{"-T", "--template", true}, {"-t", "--title", true}, {"", "--type", true},
		{"-w", "--web", false},
	},
	"pr create": {
		{"-a", "--assignee", true}, {"", "--attach", true}, {"-B", "--base", true},
		{"-b", "--body", true}, {"-F", "--body-file", true}, {"-d", "--draft", false},
		{"", "--dry-run", false}, {"-e", "--editor", false}, {"-f", "--fill", false},
		{"", "--fill-first", false}, {"", "--fill-verbose", false}, {"-H", "--head", true},
		{"-l", "--label", true}, {"-m", "--milestone", true}, {"", "--no-maintainer-edit", false},
		{"-p", "--project", true}, {"", "--recover", true}, {"-r", "--reviewer", true},
		{"-T", "--template", true}, {"-t", "--title", true}, {"-w", "--web", false},
	},
	"label create": {
		{"-c", "--color", true}, {"-d", "--description", true}, {"-f", "--force", false},
	},
	"release create": {
		{"", "--discussion-category", true}, {"-d", "--draft", false},
		{"", "--fail-on-no-commits", false}, {"", "--generate-notes", false},
		{"", "--latest", false}, {"-n", "--notes", true}, {"-F", "--notes-file", true},
		{"", "--notes-from-tag", false}, {"", "--notes-start-tag", true},
		{"-p", "--prerelease", false}, {"", "--target", true}, {"-t", "--title", true},
		{"", "--verify-tag", false},
	},
	"issue close": {
		{"-c", "--comment", true}, {"", "--duplicate-of", true}, {"-r", "--reason", true},
	},
	"pr close": {
		{"-c", "--comment", true}, {"-d", "--delete-branch", false},
	},
	"issue comment": ghCommentFlags,
	"pr comment":    ghCommentFlags,
}

var ghCommentFlags = []ghFlag{
	{"", "--attach", true}, {"-b", "--body", true}, {"-F", "--body-file", true},
	{"", "--create-if-none", false}, {"", "--delete-last", false}, {"", "--edit-last", false},
	{"-e", "--editor", false}, {"-w", "--web", false}, {"", "--yes", false},
}

var (
	ghRepoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	ghURLRE  = regexp.MustCompile(`^https?://[^/]+/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)`)
)

type ghArgs struct {
	positionals []string
	flags       map[string][]string // keyed by long name in strict mode
}

func (g ghArgs) all(names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, g.flags[n]...)
	}
	return out
}

// ghLooseValueFlags is only used by the permissive parser for read-only
// subcommands, where a mis-parse cannot cause a write.
var ghLooseValueFlags = map[string]bool{
	"-R": true, "--repo": true, "-q": true, "--jq": true, "-t": true, "--template": true,
	"--json": true, "-L": true, "--limit": true, "-s": true, "--state": true, "-l": true,
	"--label": true, "-a": true, "--assignee": true, "-A": true, "--author": true,
	"-B": true, "--base": true, "--hostname": true, "-S": true, "--search": true,
}

func parseGHLoose(args []string) ghArgs {
	g := ghArgs{flags: map[string][]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			g.positionals = append(g.positionals, args[i+1:]...)
			return g
		case strings.HasPrefix(a, "--") && strings.Contains(a, "="):
			k, val, _ := strings.Cut(a, "=")
			g.flags[k] = append(g.flags[k], val)
		case strings.HasPrefix(a, "-") && a != "-":
			if ghLooseValueFlags[a] && i+1 < len(args) {
				g.flags[a] = append(g.flags[a], args[i+1])
				i++
			} else if len(a) > 2 && !strings.HasPrefix(a, "--") && ghLooseValueFlags[a[:2]] {
				g.flags[a[:2]] = append(g.flags[a[:2]], strings.TrimPrefix(a[2:], "="))
			} else {
				g.flags[a] = append(g.flags[a], "")
			}
		default:
			g.positionals = append(g.positionals, a)
		}
	}
	return g
}

// parseGHStrict parses args against table and returns an error for any
// unknown flag, bundled short flags, or a value flag with no value.
// Flag values are stored under the long name.
func parseGHStrict(args []string, cmd string, table []ghFlag) (ghArgs, error) {
	byName := map[string]ghFlag{}
	for _, f := range append(append([]ghFlag{}, ghCommonFlags...), table...) {
		if f.short != "" {
			byName[f.short] = f
		}
		byName[f.long] = f
	}
	g := ghArgs{flags: map[string][]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			g.positionals = append(g.positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			g.positionals = append(g.positionals, a)
			continue
		}
		name, val, hasVal := a, "", false
		if strings.HasPrefix(a, "--") {
			name, val, hasVal = strings.Cut(a, "=")
		} else if len(a) > 2 {
			name, val, hasVal = a[:2], strings.TrimPrefix(a[2:], "="), true
		}
		f, ok := byName[name]
		if !ok {
			return g, fmt.Errorf("unknown flag %q for gh %s; add it to ghFlagTable", name, cmd)
		}
		if !f.value {
			if hasVal {
				return g, fmt.Errorf("flag %q for gh %s takes no value (bundled short flags are not supported)", a, cmd)
			}
			g.flags[f.long] = append(g.flags[f.long], "")
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return g, fmt.Errorf("flag %q for gh %s needs a value", name, cmd)
			}
			i++
			val = args[i]
		}
		g.flags[f.long] = append(g.flags[f.long], val)
	}
	return g, nil
}

// repoFromSpec resolves OWNER/REPO, HOST/OWNER/REPO or a GitHub URL to
// "owner/name". ok is false when spec does not resolve.
func repoFromSpec(spec string) (string, bool) {
	if m := ghURLRE.FindStringSubmatch(spec); m != nil {
		return m[1] + "/" + strings.TrimSuffix(m[2], ".git"), true
	}
	parts := strings.Split(spec, "/")
	if len(parts) == 3 { // host/owner/name
		parts = parts[1:]
	}
	if len(parts) == 2 && ghRepoRE.MatchString(parts[0]+"/"+parts[1]) {
		return parts[0] + "/" + parts[1], true
	}
	return "", false
}

// checkGH applies the write target rule to a gh invocation. The scenario's
// repo: field (A, B or W) is exported by the runner as the default repo.
func checkGH(args, rawArgs []string, sc *Scenario, prof *Profile, v *Vars, add func(string, ...any)) {
	if len(args) > 0 && args[0] == "gh" {
		args, rawArgs = args[1:], rawArgs[1:]
	}
	joined := strings.Join(args, " ")
	if len(args) == 0 {
		add("gh: no arguments")
		return
	}

	var refs []string
	switch sc.Repo {
	case "":
	case "A":
		refs = append(refs, v.RepoA.String())
	case "B":
		refs = append(refs, v.RepoB.String())
	case "W":
		refs = append(refs, v.RepoW.String())
	default:
		add("gh: repo %q must be A, B or W", sc.Repo)
	}

	// Never print the credential into rig output.
	for _, a := range args {
		if a == "--show-token" || strings.HasPrefix(a, "--show-token=") {
			add("gh: --show-token is not allowed (it prints the credential)")
			return
		}
	}
	if len(args) > 1 && args[0] == "auth" && args[1] == "token" {
		add("gh: auth token is not allowed (it prints the credential)")
		return
	}
	if args[0] == "api" {
		checkGHAPI(args[1:], rawArgs[1:], sc, prof, v, add)
		return
	}
	if args[0] == "search" || (len(args) > 1 && ghReadOnly[args[0]+" "+args[1]]) {
		return // read-only: permissive parsing cannot cause a write
	}

	// Everything else is a write and is parsed strictly.
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		add("gh: write command %q must start with <group> <action>", joined)
		return
	}
	cmd := args[0] + " " + args[1]
	table, ok := ghFlagTable[cmd]
	if !ok {
		add("gh: subcommand %q has no entry in ghFlagTable; it cannot be used in a write scenario", cmd)
		return
	}
	g, err := parseGHStrict(args[2:], cmd, table)
	if err != nil {
		add("gh: %v", err)
		return
	}
	for _, r := range g.flags["--repo"] {
		if strings.HasPrefix(r, "-") {
			add("gh: --repo value %q looks like a flag", r)
			return
		}
		rr, ok := repoFromSpec(r)
		if !ok {
			add("gh: --repo value %q is not OWNER/REPO, HOST/OWNER/REPO or a URL", r)
			return
		}
		refs = append(refs, rr)
	}
	for _, p := range g.positionals {
		if !strings.Contains(p, "/") {
			continue
		}
		rr, ok := repoFromSpec(p)
		if !ok {
			add("gh: positional %q looks like a repository reference but does not resolve", p)
			continue
		}
		refs = append(refs, rr)
	}
	requireW(joined, refs, v, add)
}

func requireW(joined string, refs []string, v *Vars, add func(string, ...any)) {
	if len(refs) == 0 {
		add("gh: write command %q names no repository; writes must target {{.RepoW}}", joined)
		return
	}
	for _, r := range refs {
		if r != v.RepoW.String() {
			add("gh: write command %q references %s; writes must target {{.RepoW}}", joined, r)
		}
	}
}

// checkGHAPI handles `gh api`. It is always parsed strictly.
func checkGHAPI(args, rawArgs []string, sc *Scenario, prof *Profile, v *Vars, add func(string, ...any)) {
	g, err := parseGHStrict(args, "api", ghFlagTable["api"])
	if err != nil {
		add("gh: %v", err)
		return
	}
	rg, _ := parseGHStrict(rawArgs, "api", ghFlagTable["api"])
	if len(g.positionals) != 1 {
		add("gh: api needs exactly one endpoint, got %q", g.positionals)
		return
	}
	if len(g.flags["--repo"]) > 0 {
		add("gh: api does not take --repo")
		return
	}
	for _, fv := range g.all("--raw-field", "--field") {
		k, val, _ := strings.Cut(fv, "=")
		if strings.HasPrefix(val, "@") {
			add("gh: api field %q: @file values (local file upload) are not allowed", k)
			return
		}
		if strings.Contains(k, "[") {
			add("gh: api field %q: nested field syntax not supported in scenarios", k)
			return
		}
	}
	endpoint := strings.TrimPrefix(g.positionals[0], "/")
	if endpoint == "graphql" {
		checkGHGraphQL(g, rg, sc, prof, v, add)
		return
	}
	write := len(g.all("--raw-field", "--field", "--input")) > 0
	for _, m := range g.all("--method") {
		if !strings.EqualFold(m, "GET") {
			write = true
		}
	}
	ep := strings.SplitN(endpoint, "?", 2)[0]
	clean, err := normalisePath("/"+ep, false)
	if err != nil {
		add("gh: api endpoint: %v", err)
		return
	}
	if write && !strings.HasPrefix(clean, "/repos/"+v.RepoW.String()+"/") {
		// Non-GET api calls must target W's REST namespace; no other
		// endpoint (user/starred, repositories/<id>, orgs, ...) is allowed.
		add("gh: write api endpoint %q must start with repos/{{.RepoW}}/", endpoint)
	}
}

func checkGHGraphQL(g, rg ghArgs, sc *Scenario, prof *Profile, v *Vars, add func(string, ...any)) {
	if len(g.all("--input")) > 0 {
		add("gh: api graphql --input is not allowed; pass the query with -f query=")
		return
	}
	fields := g.all("--raw-field", "--field")
	rawFields := rg.all("--raw-field", "--field")
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
