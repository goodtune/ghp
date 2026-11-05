package scenario

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	validKinds        = map[string]bool{"rest": true, "graphql": true, "gh": true, "token_api": true}
	validCapabilities = map[string]bool{"repo_w_push": true, "repo_create": true, "github_vhost": true, "agent_installation": true}
	knownIssueRE      = regexp.MustCompile(`^https://github\.com/goodtune/ghp/issues/\d+$`)
	mutationRE        = regexp.MustCompile(`\bmutation\b`)
	gqlRepoLiteralRE  = regexp.MustCompile(`owner\s*:\s*"([^"]*)"\s*,?\s*name\s*:\s*"([^"]*)"`)
)

// gapA1ProbeID is the one scenario allowed to send a forwarded write with a
// read-only token. Its path must still target RepoW.
const gapA1ProbeID = "GAP-A1.delete-ref-contents-ro"

// maxProfileDuration bounds every profile so leaked tokens expire quickly.
const maxProfileDuration = 2 * time.Hour

// PlaceholderVars returns Vars with fixed fake values for static validation.
func PlaceholderVars() *Vars {
	f := FixtureVals{IssueNumber: 1, PRNumber: 2, ReleaseID: 3, Branch: "branch", Label: "label",
		PRTitle: "pr", IssueTitle: "issue", ReleaseTag: "v0"}
	return &Vars{
		RunID: "run", Host: "ghp.example", Login: "login",
		RepoA:   RepoRef{Owner: "a-owner", Name: "a-repo", ID: 1},
		RepoB:   RepoRef{Owner: "b-owner", Name: "b-repo", ID: 2},
		RepoW:   RepoRef{Owner: "w-owner", Name: "w-repo", ID: 3},
		Fixture: map[string]FixtureVals{"A": f, "B": f, "W": f},
		Instance: InstanceVals{Host: "ghp.example", ManagementHost: "mgmt.ghp.example",
			DefaultDuration: time.Hour, MaxDuration: 168 * time.Hour},
		Step: map[string]map[string]string{},
	}
}

type scenarioError struct {
	id, file, msg string
}

func (e *scenarioError) Error() string {
	return fmt.Sprintf("%s: scenario %q: %s", e.file, e.id, e.msg)
}

// Validate statically checks the tree and returns every problem found,
// profile errors first (sorted by name) then scenario errors sorted by ID.
// If v is nil, PlaceholderVars is used. Step values are pre-populated from
// each scenario's capture names, so v.Step is ignored.
func Validate(t *Tree, v *Vars) []error {
	if v == nil {
		v = PlaceholderVars()
	}
	var errs []error

	names := make([]string, 0, len(t.Profiles))
	for n := range t.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := t.Profiles[n]
		perr := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("profiles.yaml: profile %q: %s", n, fmt.Sprintf(format, a...)))
		}
		if p.Type != "proxy" {
			perr("type %q not supported (only proxy)", p.Type)
		}
		if p.Duration == "" {
			if n != "lifecycle-default" {
				perr("duration is required (empty only for lifecycle-default)")
			}
		} else if d, err := time.ParseDuration(p.Duration); err != nil {
			perr("bad duration %q: %v", p.Duration, err)
		} else if d <= 0 || d > maxProfileDuration {
			perr("duration %s must be > 0 and <= 2h", p.Duration)
		}
		for _, r := range p.Repositories {
			if _, err := Expand(r, v); err != nil {
				perr("repositories: %v", err)
			}
		}
	}

	scen := make([]*Scenario, len(t.Scenarios))
	copy(scen, t.Scenarios)
	sort.SliceStable(scen, func(i, j int) bool { return scen[i].ID < scen[j].ID })
	for _, s := range scen {
		for _, msg := range validateScenario(t, s, v) {
			errs = append(errs, &scenarioError{id: s.ID, file: s.File, msg: msg})
		}
	}
	return errs
}

func validateScenario(t *Tree, s *Scenario, base *Vars) []string {
	var msgs []string
	add := func(format string, a ...any) { msgs = append(msgs, fmt.Sprintf(format, a...)) }

	// Copy vars and pre-populate Step from capture names.
	vv := *base
	v := &vv
	v.Step = map[string]map[string]string{}
	for _, r := range append(append([]Request{}, s.Steps...), s.Cleanup...) {
		if len(r.Capture) == 0 {
			continue
		}
		if v.Step[r.Name] == nil {
			v.Step[r.Name] = map[string]string{}
		}
		for c := range r.Capture {
			v.Step[r.Name][c] = "0"
		}
	}
	if s.Request != nil && len(s.Request.Capture) > 0 {
		if v.Step[s.Request.Name] == nil {
			v.Step[s.Request.Name] = map[string]string{}
		}
		for c := range s.Request.Capture {
			v.Step[s.Request.Name][c] = "0"
		}
	}

	// Rule 1: references and kind.
	if _, ok := t.Claims[s.Claim]; !ok {
		add("claim %q not found in claims.yaml", s.Claim)
	}
	var prof *Profile
	if s.Kind != "token_api" {
		if s.Profile == "" {
			add("profile is required for kind %q", s.Kind)
		} else if p, ok := t.Profiles[s.Profile]; !ok {
			add("profile %q not found in profiles.yaml", s.Profile)
		} else {
			prof = &p
		}
	} else if s.Profile != "" {
		if _, ok := t.Profiles[s.Profile]; !ok {
			add("profile %q not found in profiles.yaml", s.Profile)
		}
	}
	if !validKinds[s.Kind] {
		add("kind %q must be one of rest, graphql, gh, token_api", s.Kind)
	}

	// Rule 2: known_issue <=> observed.
	if (s.KnownIssue != "") != (s.Observed != nil) {
		add("known_issue and observed must be set together (known_issue=%q, observed set=%v)", s.KnownIssue, s.Observed != nil)
	}
	if s.KnownIssue != "" && !knownIssueRE.MatchString(s.KnownIssue) {
		add("known_issue %q must match https://github.com/goodtune/ghp/issues/<n>", s.KnownIssue)
	}

	// Rule 3: capabilities.
	for _, r := range s.Requires {
		if !validCapabilities[r] {
			add("requires %q is not one of repo_w_push, repo_create, github_vhost, agent_installation", r)
		}
	}

	// Rules 5 and 6: write targets and template expansion.
	wPrefix := "/repos/" + v.RepoW.String() + "/"
	exp := func(where, in string) (string, bool) {
		out, err := Expand(in, v)
		if err != nil {
			add("%s: %v", where, err)
			return "", false
		}
		return out, true
	}
	checkReq := func(where string, r *Request) {
		path, ok := exp(where+" path", r.Path)
		if _, err := ExpandAny(r.Headers, v); err != nil {
			add("%s headers: %v", where, err)
		}
		if _, err := ExpandAny(r.Body, v); err != nil {
			add("%s body: %v", where, err)
		}
		checkExpect(where+" expect", r.Expect, v, add)
		if !ok {
			return
		}
		method := strings.ToUpper(r.Method)
		if s.Kind == "token_api" {
			if !strings.HasPrefix(path, "/api/tokens") {
				add("%s: token_api path %q must start with /api/tokens", where, path)
			}
			return
		}
		if method == "GET" || method == "HEAD" {
			return
		}
		if !strings.HasPrefix(path, wPrefix) {
			add("%s: %s %q must target /repos/{{.RepoW}}/ (write target rule)", where, method, path)
		}
	}
	for i := range s.Steps {
		checkReq(fmt.Sprintf("steps[%d]", i), &s.Steps[i])
	}
	for i := range s.Cleanup {
		checkReq(fmt.Sprintf("cleanup[%d]", i), &s.Cleanup[i])
	}
	if s.Request != nil {
		checkReq("request", s.Request)
	} else if s.Kind == "token_api" {
		add("token_api scenario needs a request")
	}
	// Normalise copies the rest shorthand Expect into Steps[0]; Steps are
	// the source of truth, so do not report the same problem twice.
	if !(len(s.Steps) > 0 && s.Steps[0].Expect == s.Expect) {
		checkExpect("expect", s.Expect, v, add)
	}
	checkExpect("observed", s.Observed, v, add)
	if _, err := ExpandAny(s.Args, v); err != nil {
		add("args: %v", err)
	}
	if _, err := ExpandAny(map[string]any(s.Variables), v); err != nil {
		add("variables: %v", err)
	}

	if q, ok := exp("query", s.Query); ok && s.Kind == "graphql" && mutationRE.MatchString(q) {
		if prof != nil {
			reps := prof.Repositories
			okRepos := len(reps) == 0
			if len(reps) == 1 {
				if r, err := Expand(reps[0], v); err == nil && r == v.RepoW.String() {
					okRepos = true
				}
			}
			if !okRepos {
				add("graphql mutation needs a profile with no repositories or exactly [{{.RepoW}}]; profile %q has %v", prof.Name, reps)
			}
		}
		for _, m := range gqlRepoLiteralRE.FindAllStringSubmatch(q, -1) {
			if m[1]+"/"+m[2] != v.RepoW.String() {
				add("graphql mutation references %s/%s; only {{.RepoW}} is allowed", m[1], m[2])
			}
		}
	}
	return msgs
}

func checkExpect(where string, e *Expect, v *Vars, add func(string, ...any)) {
	if e == nil {
		return
	}
	for _, x := range []any{e.BodyContains, e.BodyNotContains, e.Header, e.JSON, e.StdoutContains, e.StderrContains} {
		if _, err := ExpandAny(x, v); err != nil {
			add("%s: %v", where, err)
		}
	}
}
