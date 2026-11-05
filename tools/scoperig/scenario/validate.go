package scenario

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	validKinds        = map[string]bool{"rest": true, "graphql": true, "gh": true, "token_api": true}
	validCapabilities = map[string]bool{"repo_w_push": true, "repo_create": true, "github_vhost": true, "agent_installation": true}
	knownIssueRE      = regexp.MustCompile(`^https://github\.com/goodtune/ghp/issues/\d+$`)
)

// gapA1ProbeID is the one scenario allowed to send a forwarded write with a
// read-only token. Its path must still target RepoW.
const gapA1ProbeID = "GAP-A1.delete-ref-contents-ro"

// maxProfileDuration bounds every profile so leaked tokens expire quickly.
const maxProfileDuration = 2 * time.Hour

// PlaceholderVars returns Vars filled with fixed fake values. Validate uses
// it when called with nil Vars, so static validation never needs live
// fixtures. The IDs and node IDs are deliberately distinctive so that a
// literal copy of A's or B's identifier in a query is detectable.
func PlaceholderVars() *Vars {
	f := FixtureVals{IssueNumber: 1, PRNumber: 2, ReleaseID: 3, Branch: "branch", Label: "label",
		PRTitle: "pr", IssueTitle: "issue", ReleaseTag: "v0"}
	return &Vars{
		RunID: "run", Host: "ghp.example", Login: "login",
		RepoA:   RepoRef{Owner: "a-owner", Name: "a-repo", ID: 900000101, NodeID: "R_placeholderA"},
		RepoB:   RepoRef{Owner: "b-owner", Name: "b-repo", ID: 900000202, NodeID: "R_placeholderB"},
		RepoW:   RepoRef{Owner: "w-owner", Name: "w-repo", ID: 900000303, NodeID: "R_placeholderW"},
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
	// Profile IDs are placeholders for every known profile; an unknown
	// name expands to "" (text/template's index ignores missingkey).
	v.ProfileIDs = make(map[string]string, len(t.Profiles))
	for n := range t.Profiles {
		v.ProfileIDs[n] = "00000000-0000-4000-8000-000000000000"
	}
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
	exp := func(where, in string) (string, bool) {
		out, err := Expand(in, v)
		if err != nil {
			add("%s: %v", where, err)
			return "", false
		}
		return out, true
	}
	checkReq := func(where string, stepIdx int, r *Request) {
		path, ok := exp(where+" path", r.Path)
		if _, err := ExpandAny(r.Headers, v); err != nil {
			add("%s headers: %v", where, err)
		}
		body, err := ExpandAny(r.Body, v)
		if err != nil {
			add("%s body: %v", where, err)
		}
		checkExpect(where+" expect", r.Expect, v, add)
		if !ok {
			return
		}
		method := strings.ToUpper(strings.TrimSpace(r.Method))
		if method == "" {
			if r.Body != nil {
				add("%s: method is required when a body is set", where)
				return
			}
			method = "GET" // explicit default for body-less requests
		}
		clean, perr := normalisePath(path)
		if perr != nil {
			add("%s: %v", where, perr)
			return
		}
		if s.Kind == "token_api" {
			// token_api scenarios (steps, request and cleanup alike) talk
			// to the management API, plus read-only GETs to the proxy host
			// under /api/v3/ (sent with the scenario's profile token).
			if (method == "GET" || method == "HEAD") && strings.HasPrefix(clean, "/api/v3/") {
				return
			}
			if clean != "/api/tokens" && !strings.HasPrefix(clean, "/api/tokens/") {
				add("%s: token_api path %q must be /api/tokens or start with /api/tokens/ or /api/tokens? (or be a GET under /api/v3/)", where, path)
				return
			}
			if method == "DELETE" && (clean == "/api/tokens" || strings.TrimPrefix(clean, "/api/tokens/") == "") {
				add("%s: DELETE %q has an empty token id (unknown profile in ProfileIDs?)", where, path)
			}
			return
		}
		if s.Kind == "graphql" && (clean == "/graphql" || strings.Contains(path, "query=")) {
			if method != "POST" {
				add("%s: graphql steps must use POST, not %s", where, method)
				return
			}
			if strings.Contains(path, "?") {
				add("%s: graphql step path must not carry a query string", where)
				return
			}
			// GraphQL steps are checked by the mutation rule, not the REST
			// write rule.
			if m, ok := body.(map[string]any); ok {
				q, _ := m["query"].(string)
				vars, _ := m["variables"].(map[string]any)
				var rawVars map[string]any
				if rm, ok := r.Body.(map[string]any); ok {
					rawVars, _ = rm["variables"].(map[string]any)
				}
				checkGraphQL(where, s, stepIdx, q, vars, rawVars, prof, v, add)
			} else if method != "GET" && method != "HEAD" {
				add("%s: graphql step body must be a map with a query", where)
			}
			return
		}
		if method == "GET" || method == "HEAD" {
			return
		}
		if !strings.HasPrefix(clean, "/repos/"+v.RepoW.String()+"/") {
			add("%s: %s %q must target /repos/{{.RepoW}}/ (write target rule)", where, method, path)
		}
	}
	for i := range s.Steps {
		checkReq(fmt.Sprintf("steps[%d]", i), i, &s.Steps[i])
	}
	for i := range s.Cleanup {
		checkReq(fmt.Sprintf("cleanup[%d]", i), -1, &s.Cleanup[i])
	}
	if s.Request != nil {
		checkReq("request", -1, s.Request)
	} else if s.Kind == "token_api" && len(s.Steps) == 0 {
		add("token_api scenario needs a request or steps")
	}
	// Normalise copies the rest shorthand Expect into Steps[0]; Steps are
	// the source of truth, so do not report the same problem twice.
	if !(len(s.Steps) > 0 && s.Steps[0].Expect == s.Expect) {
		checkExpect("expect", s.Expect, v, add)
	}
	checkExpect("observed", s.Observed, v, add)

	args := make([]string, 0, len(s.Args))
	argsOK := true
	for i, a := range s.Args {
		e, ok := exp(fmt.Sprintf("args[%d]", i), a)
		argsOK = argsOK && ok
		args = append(args, e)
	}
	if s.Kind == "gh" && argsOK {
		checkGH(args, s.Args, s, prof, v, add)
	}

	vars, err := ExpandAny(map[string]any(s.Variables), v)
	if err != nil {
		add("variables: %v", err)
	}
	if q, ok := exp("query", s.Query); ok && s.Kind == "graphql" && s.Query != "" && err == nil {
		vm, _ := vars.(map[string]any)
		checkGraphQL("query", s, -1, q, vm, s.Variables, prof, v, add)
	}
	return msgs
}

// normalisePath unescapes and cleans the path part of p and rejects any
// traversal attempt so that the prefix check cannot be bypassed. It fails
// closed: any "." or ".." segment, or an encoded dot, is an error even when
// it would resolve back inside W, because no legitimate scenario needs one.
func normalisePath(p string) (string, error) {
	raw := p
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if strings.Contains(strings.ToLower(raw), "%2e") {
		return "", fmt.Errorf("path %q contains an encoded dot", p)
	}
	u, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("path %q: %v", p, err)
	}
	if strings.Contains(strings.ToLower(u), "%2e") {
		return "", fmt.Errorf("path %q contains an encoded dot", p)
	}
	for _, seg := range strings.Split(u, "/") {
		if seg == ".." || seg == "." {
			return "", fmt.Errorf("path %q contains a dot segment", p)
		}
	}
	if !strings.HasPrefix(u, "/") {
		return "", fmt.Errorf("path %q must be absolute", p)
	}
	c := path.Clean(u)
	if strings.Contains(c, "..") {
		return "", fmt.Errorf("path %q contains ..", p)
	}
	return c, nil
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
