package scenario

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

var (
	validKinds        = map[string]bool{"rest": true, "graphql": true, "gh": true, "token_api": true, "git": true, "git_credential": true}
	validCapabilities = map[string]bool{"repo_w_push": true, "repo_create": true, "github_vhost": true, "codeload_vhost": true, "agent_installation": true,
		"non_admin_session": true, "default_app": true, "border_block_ghp": true, "border_block_gho": true, "border_block_github_pat": true,
		"no_expiry_disallowed": true, "ghp_cli": true}
	knownIssueRE = regexp.MustCompile(`^https://github\.com/goodtune/ghp/issues/\d+$`)
)

// gapA7ProbeID is the one scenario allowed to send dot segments in its
// path, and only on a GET: it probes that "/repos/A/../../B" cannot escape
// the repository allowlist.
const gapA7ProbeID = "GAP-A7.dotdot-path"

// validVhosts maps each virtual host a rest request may target to the
// capability the scenario must require for it.
var validVhosts = map[string]string{"github.com": "github_vhost", "codeload.github.com": "codeload_vhost"}

// agentAppTemplate and agentInstallationRef are the only values a token_api
// agent token body may give for app_record_id and installation_id.
const (
	agentAppTemplate     = "{{.Agent.AppRecordID}}"
	agentInstallationRef = "$int:InstallationID"
)

// appsReadRE is the token_api read allowance for app records: the list, one
// app, or one app's installations (the CLI's --app/--installation lookups).
var appsReadRE = regexp.MustCompile(`^/api/apps(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(/installations)?)?$`)

// permissionsPath is the token_api read allowance for the valid-permission
// list (GET /api/github/permissions).
const permissionsPath = "/api/github/permissions"

// maxProfileDuration bounds every profile so leaked tokens expire quickly.
const maxProfileDuration = 2 * time.Hour

// PlaceholderHost is the instance host in PlaceholderVars. A scenario must
// reach the instance through {{.Host}}; a literal copy of this host passes
// static validation but becomes a foreign host at run time, so the gh
// checks reject it outright.
const PlaceholderHost = "ghp.example"

// PlaceholderVars returns Vars filled with fixed fake values. Validate uses
// it when called with nil Vars, so static validation never needs live
// fixtures. The IDs and node IDs are deliberately distinctive so that a
// literal copy of A's or B's identifier in a query is detectable.
func PlaceholderVars() *Vars {
	f := FixtureVals{IssueNumber: 1, PRNumber: 2, ReleaseID: 3, Branch: "branch", Label: "label",
		PRTitle: "pr", IssueTitle: "issue", ReleaseTag: "v0"}
	return &Vars{
		RunID: "run", Host: PlaceholderHost, Login: "login",
		RepoA:   RepoRef{Owner: "a-owner", Name: "a-repo", ID: 900000101, NodeID: "R_placeholderA"},
		RepoB:   RepoRef{Owner: "b-owner", Name: "b-repo", ID: 900000202, NodeID: "R_placeholderB"},
		RepoW:   RepoRef{Owner: "w-owner", Name: "w-repo", ID: 900000303, NodeID: "R_placeholderW"},
		Fixture: map[string]FixtureVals{"A": f, "B": f, "W": f},
		Instance: InstanceVals{Host: PlaceholderHost,
			DefaultDuration: time.Hour, MaxDuration: 168 * time.Hour},
		Agent:      AgentVals{AppRecordID: "00000000-0000-4000-8000-0000000000a6", InstallationID: 900000404},
		Step:       map[string]map[string]string{},
		Enterprise: placeholderEnterprise,
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
		switch p.Type {
		case "proxy":
		case "agent":
			if !slices.Contains(p.Requires, "agent_installation") {
				perr("type agent needs requires: [agent_installation]")
			}
		default:
			perr("type %q not supported (proxy or agent)", p.Type)
		}
		for _, r := range p.Requires {
			if !PreMintCapabilities[r] {
				perr("requires %q: a profile may require only agent_installation (known before tokens are minted)", r)
			}
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
	v := CaptureVars(s, &Vars{})
	vv := *base
	vv.Step = v.Step
	v = &vv
	// Profile IDs are placeholders for every known profile; an unknown
	// name expands to "" (text/template's index ignores missingkey).
	v.ProfileIDs = make(map[string]string, len(t.Profiles))
	for n := range t.Profiles {
		v.ProfileIDs[n] = "00000000-0000-4000-8000-000000000000"
	}

	// Rule 1: references and kind.
	if _, ok := t.Claims[s.Claim]; !ok {
		add("claim %q not found in claims.yaml", s.Claim)
	}
	var prof *Profile
	if s.Kind == "git_credential" {
		// The helper mints its own tokens; no profile token is used.
		if s.Profile != "" {
			add("profile is not valid for kind git_credential")
		}
	} else if s.Kind != "token_api" {
		if s.Profile == "" {
			add("profile is required for kind %q", s.Kind)
		} else if p, ok := t.Profiles[s.Profile]; !ok {
			add("profile %q not found in profiles.yaml", s.Profile)
		} else {
			prof = &p
		}
	} else if s.Profile != "" {
		if p, ok := t.Profiles[s.Profile]; !ok {
			add("profile %q not found in profiles.yaml", s.Profile)
		} else {
			prof = &p
		}
	}
	// A profile that is not minted without a capability must not be used by
	// a scenario that would then run (and ERROR) without it.
	if prof != nil {
		for _, r := range prof.Requires {
			if !slices.Contains(s.Requires, r) {
				add("profile %q requires %s; add it to the scenario's requires", s.Profile, r)
			}
		}
	}
	if !validKinds[s.Kind] {
		add("kind %q must be one of rest, graphql, gh, token_api, git, git_credential", s.Kind)
	}

	// The method/path/body/vhost shorthand is only read for kind rest;
	// on any other kind it would be silently ignored.
	if s.Kind != "rest" {
		for _, f := range []struct {
			name string
			set  bool
		}{{"method", s.Method != ""}, {"path", s.Path != ""}, {"body", s.Body != nil}, {"vhost", s.Vhost != ""}} {
			if f.set {
				add("%s is only valid for kind rest (shorthand)", f.name)
			}
		}
	}
	if s.Kind != "git" {
		if s.GitOp != "" {
			add("git_op is only valid for kind git")
		}
		if s.Branch != "" {
			add("branch is only valid for kind git")
		}
	}
	if s.Kind == "git" {
		checkGit(s, v, add)
	}
	if s.Kind == "git_credential" {
		checkGitCredential(s, add)
	}
	if s.OperationName != "" && (s.Kind != "graphql" || len(s.Steps) > 0) {
		add("operation_name is only valid for a kind graphql scenario with a query (not steps)")
	}
	if s.Kind == "graphql" && strings.TrimSpace(s.Query) == "" && len(s.Steps) == 0 {
		add("graphql scenario needs a query or steps")
	}

	// Rule 2: known_issue <=> observed.
	if (s.KnownIssue != "") != (s.Observed != nil) {
		add("known_issue and observed must be set together (known_issue=%q, observed set=%v)", s.KnownIssue, s.Observed != nil)
	}
	if s.KnownIssue != "" && !knownIssueRE.MatchString(s.KnownIssue) {
		add("known_issue %q must match https://github.com/goodtune/ghp/issues/<n>", s.KnownIssue)
	}

	// Rule 3b: an agent token created through token_api must name the
	// configured app and installation by template, so it can never be
	// pinned to the instance's default app (or a literal app).
	if s.Kind == "token_api" {
		reqs := make([]*Request, 0, len(s.Steps)+1)
		for i := range s.Steps {
			reqs = append(reqs, &s.Steps[i])
		}
		if s.Request != nil {
			reqs = append(reqs, s.Request)
		}
		for _, r := range reqs {
			m, ok := r.Body.(map[string]any)
			if !ok || m["type"] != "agent" {
				continue
			}
			if m["app_record_id"] != agentAppTemplate {
				add("agent token body must set app_record_id: %q", agentAppTemplate)
			}
			if m["installation_id"] != agentInstallationRef {
				add("agent token body must set installation_id: %q", agentInstallationRef)
			}
			if !slices.Contains(s.Requires, "agent_installation") {
				add("agent token body needs requires: [agent_installation]")
			}
		}
	}

	// Rule 3: capabilities.
	for _, r := range s.Requires {
		if !validCapabilities[r] {
			add("requires %q is not one of %s", r, strings.Join(sortedCapabilities(), ", "))
		}
	}
	for _, m := range checkMetricDelta(s) {
		add("%s", m)
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
	checkReq := func(where string, stepIdx int, cleanup bool, r *Request) {
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
		if r.Vhost != "" {
			switch {
			case s.Kind != "rest":
				add("%s: vhost is only valid for kind rest", where)
			case validVhosts[r.Vhost] == "":
				add("%s: vhost %q must be github.com or codeload.github.com", where, r.Vhost)
			case method != "GET" && method != "HEAD":
				add("%s: vhost requests must be GET or HEAD, not %s", where, method)
			case !hasString(s.Requires, validVhosts[r.Vhost]):
				add("%s: vhost %s requests need requires: [%s]", where, r.Vhost, validVhosts[r.Vhost])
			}
		}
		// The traversal probe (a rest GET, sent verbatim by design) skips
		// only the dot-segment rejection; every later check still runs.
		// A graphql step always goes to the GraphQL endpoint (the executor
		// ignores the path), so it must say so: any other path would skip
		// the GraphQL mutation check below. Cleanup is REST, not GraphQL.
		graphqlStep := s.Kind == "graphql" && !cleanup
		if graphqlStep {
			// Trim exactly as the executor does, so both agree on
			// whitespace-only and padded paths.
			path = strings.TrimSpace(path)
			if path == "" {
				path = "/graphql"
			}
			if path != "/graphql" {
				add("%s: graphql step path %q must be /graphql", where, path)
				return
			}
		}
		allowDots := s.ID == gapA7ProbeID && s.Kind == "rest" && method == "GET"
		clean, perr := normalisePath(path, allowDots)
		if perr != nil {
			add("%s: %v", where, perr)
			return
		}
		if cleanup {
			// Cleanup runs with the unrestricted open token and is never
			// passed through the GraphQL mutation check, so it must not be
			// a GraphQL request at all: cleanup is a REST write on W.
			if clean == "/graphql" {
				add("%s: GraphQL requests are not allowed in cleanup", where)
				return
			}
			if m, ok := body.(map[string]any); ok {
				if q, ok := m["query"].(string); ok {
					if f, err := parseGraphQL(q); err == nil && f.mutation {
						add("%s: GraphQL mutations are not allowed in cleanup", where)
						return
					}
				}
			}
		}
		if s.Kind == "token_api" {
			// token_api scenarios (steps, request and cleanup alike) talk
			// to the management API, plus read-only GETs to the proxy host
			// under /api/v3/ (sent with the scenario's profile token).
			if (method == "GET" || method == "HEAD") && strings.HasPrefix(clean, "/api/v3/") {
				return
			}
			// Read-only GETs of the app records and installations, the
			// endpoints the CLI resolves --app and --installation with
			// (TOK-C03, TOK-C04). Sent with the session token.
			if (method == "GET" || method == "HEAD") && appsReadRE.MatchString(path) {
				return
			}
			// The permission list the web UI offers (PERM-C18). Sent with
			// the session token; exact path, no query.
			if (method == "GET" || method == "HEAD") && path == permissionsPath {
				return
			}
			if clean != "/api/tokens" && !strings.HasPrefix(clean, "/api/tokens/") {
				add("%s: token_api path %q must be /api/tokens or start with /api/tokens/ (or be a GET under /api/v3/ or /api/apps)", where, path)
				return
			}
			if strings.Contains(path, "?") {
				add("%s: token_api path %q must not have a query string", where, path)
				return
			}
			if method == "DELETE" && (clean == "/api/tokens" || strings.TrimPrefix(clean, "/api/tokens/") == "") {
				add("%s: DELETE %q has an empty token id (unknown profile in ProfileIDs?)", where, path)
			}
			return
		}
		if graphqlStep {
			if method != "POST" {
				add("%s: graphql steps must use POST, not %s", where, method)
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
		checkReq(fmt.Sprintf("steps[%d]", i), i, false, &s.Steps[i])
	}
	// Rule: every runnable step, and a scenario with no steps, must assert
	// something. A missing or empty expect would otherwise be a silent PASS.
	for i := range s.Steps {
		if !hasAssertion(s.Steps[i].Expect) {
			add("steps[%d]: expect is required and must have at least one assertion", i)
		}
	}
	if len(s.Steps) == 0 {
		e := s.Expect
		if s.Request != nil && s.Request.Expect != nil {
			e = s.Request.Expect
		}
		if !hasAssertion(e) {
			add("expect is required and must have at least one assertion")
		}
	}
	for i := range s.Cleanup {
		checkReq(fmt.Sprintf("cleanup[%d]", i), -1, true, &s.Cleanup[i])
	}
	if s.Vhost != "" {
		switch {
		case s.Kind != "rest":
			// Reported with the other shorthand fields above.
		case len(s.Steps) == 0:
			add("vhost needs a request (method and path)")
		case !s.shorthand:
			add("top-level vhost is not allowed with steps; set vhost on each step")
		}
	}
	if s.Request != nil {
		checkReq("request", -1, false, s.Request)
	} else if s.Kind == "token_api" && len(s.Steps) == 0 {
		add("token_api scenario needs a request or steps")
	}
	// Normalise moves the rest shorthand Expect into Steps[0] (checked with
	// the steps above) and clears it here.
	checkExpect("expect", s.Expect, v, add)
	checkExpect("observed", s.Observed, v, add)
	// An empty observed matches every response, so a known issue would
	// stay KNOWN forever and never report KNOWN-CHANGED.
	if s.Observed != nil && !hasAssertion(s.Observed) {
		add("observed must have at least one assertion")
	}

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
//
// If allowDots is true, "." and ".." segments are not rejected (the GAP-A7
// probe); the encoded-dot and absolute-path checks still apply.
func normalisePath(p string, allowDots bool) (string, error) {
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
		if !allowDots && (seg == ".." || seg == ".") {
			return "", fmt.Errorf("path %q contains a dot segment", p)
		}
	}
	if !strings.HasPrefix(u, "/") {
		return "", fmt.Errorf("path %q must be absolute", p)
	}
	c := path.Clean(u)
	if !allowDots && strings.Contains(c, "..") {
		return "", fmt.Errorf("path %q contains a dot-dot segment", p)
	}
	return c, nil
}

// hasAssertion reports whether e has at least one matcher set.
func hasAssertion(e *Expect) bool {
	if e == nil {
		return false
	}
	return e.Status != 0 || len(e.StatusIn) > 0 || len(e.BodyContains) > 0 ||
		len(e.BodyNotContains) > 0 || len(e.Header) > 0 || len(e.HeaderNotContains) > 0 || len(e.JSON) > 0 ||
		e.GHPDenial != nil || e.ExitCode != nil || len(e.ExitCodeIn) > 0 ||
		len(e.StdoutContains) > 0 || len(e.StderrContains) > 0 ||
		e.ExpiresWithin != nil
}

func checkExpect(where string, e *Expect, v *Vars, add func(string, ...any)) {
	if e == nil {
		return
	}
	if len(e.HeaderNotContainsExcept) > 0 && len(e.HeaderNotContains) == 0 {
		add("%s: header_not_contains_except needs header_not_contains", where)
	}
	for _, h := range e.HeaderNotContainsExcept {
		if !strings.EqualFold(h, "Set-Cookie") {
			add("%s: header_not_contains_except may only name Set-Cookie, not %q", where, h)
		}
	}
	if e.ExitCode != nil && len(e.ExitCodeIn) > 0 {
		add("%s: exit_code and exit_code_in are mutually exclusive", where)
	}
	for _, x := range []any{e.BodyContains, e.BodyNotContains, e.Header, e.HeaderNotContains, e.JSON, e.StdoutContains, e.StderrContains} {
		if _, err := ExpandAny(x, v); err != nil {
			add("%s: %v", where, err)
		}
	}
	if w := e.ExpiresWithin; w != nil {
		checkExpiresWithin(where, w, v, add)
	}
}

// checkExpiresWithin requires a field and min/max durations that expand
// and parse, with 0 <= min <= max and max > 0.
func checkExpiresWithin(where string, w *ExpiresWithin, v *Vars, add func(string, ...any)) {
	if strings.TrimSpace(w.Field) == "" || w.FieldPath() == "$" || w.FieldPath() == "$." {
		add("%s: expires_within: field is required", where)
	}
	parse := func(name, raw string) (time.Duration, bool) {
		if strings.TrimSpace(raw) == "" {
			add("%s: expires_within: %s is required", where, name)
			return 0, false
		}
		x, err := Expand(raw, v)
		if err != nil {
			add("%s: expires_within: %s: %v", where, name, err)
			return 0, false
		}
		d, err := time.ParseDuration(x)
		if err != nil {
			add("%s: expires_within: %s %q is not a duration: %v", where, name, x, err)
			return 0, false
		}
		return d, true
	}
	lo, okLo := parse("min", w.Min)
	hi, okHi := parse("max", w.Max)
	if !okLo || !okHi {
		return
	}
	switch {
	case lo < 0:
		add("%s: expires_within: min %s must not be negative", where, lo)
	case hi <= 0:
		add("%s: expires_within: max %s must be positive", where, hi)
	case lo > hi:
		add("%s: expires_within: min %s is greater than max %s", where, lo, hi)
	}
}

func hasString(xs []string, x string) bool {
	for _, e := range xs {
		if e == x {
			return true
		}
	}
	return false
}

// checkGit applies the kind git rules (GIT-C48). A clone reads A, B or W.
// A push writes only to W, on a run-unique branch ({{.RunID}} in branch)
// that a cleanup DELETE of refs/heads/<branch> removes, and requires
// repo_w_push. Both go through the github.com vhost (requires
// github_vhost). Nothing else may be set: the executor builds the git
// command itself.
func checkGit(s *Scenario, v *Vars, add func(string, ...any)) {
	for _, f := range []struct {
		name string
		set  bool
	}{{"args", len(s.Args) > 0}, {"steps", len(s.Steps) > 0}, {"request", s.Request != nil},
		{"query", s.Query != ""}, {"poll", s.Poll != nil}, {"headers", len(s.Headers) > 0}} {
		if f.set {
			add("%s is not valid for kind git", f.name)
		}
	}
	switch s.Repo {
	case "A", "B", "W":
	default:
		add("kind git needs repo: A, B or W (got %q)", s.Repo)
	}
	if !hasString(s.Requires, "github_vhost") {
		add("kind git goes through the github.com vhost: requires: [github_vhost]")
	}
	switch s.GitOp {
	case "clone":
		if s.Branch != "" {
			add("branch is only valid for git_op push")
		}
	case "push":
		if s.Repo != "W" {
			add("git_op push only to W (got repo %q)", s.Repo)
		}
		if !hasString(s.Requires, "repo_w_push") {
			add("git_op push needs requires: [repo_w_push]")
		}
		if !strings.Contains(s.Branch, "{{.RunID}}") {
			add("git_op push needs a run-unique branch containing {{.RunID}} (got %q)", s.Branch)
			return
		}
		branch, err := Expand(s.Branch, v)
		if err != nil {
			add("branch: %v", err)
			return
		}
		if strings.ContainsAny(branch, " ~^:?*[\\") || strings.Contains(branch, "..") || strings.HasPrefix(branch, "-") {
			add("branch %q is not a safe ref name", branch)
			return
		}
		want := "/repos/" + v.RepoW.String() + "/git/refs/heads/" + branch
		found := false
		for _, c := range s.Cleanup {
			p, err := Expand(c.Path, v)
			if err == nil && strings.EqualFold(strings.TrimSpace(c.Method), "DELETE") && p == want {
				found = true
			}
		}
		if !found {
			add("git_op push needs a cleanup DELETE %s", want)
		}
	default:
		add("git_op must be clone or push (got %q)", s.GitOp)
	}
}

// checkGitCredential applies the kind git_credential rules (CRED-C55): the
// executor runs a fixed flow for W with the agent installation app and the
// ghp CLI, and revokes every token itself, so nothing else may be set.
func checkGitCredential(s *Scenario, add func(string, ...any)) {
	if s.Repo != "W" {
		add("kind git_credential needs repo: W (got %q)", s.Repo)
	}
	for _, c := range []string{"agent_installation", "ghp_cli"} {
		if !hasString(s.Requires, c) {
			add("kind git_credential needs requires: [%s]", c)
		}
	}
	for _, f := range []struct {
		name string
		set  bool
	}{{"args", len(s.Args) > 0}, {"steps", len(s.Steps) > 0}, {"request", s.Request != nil},
		{"query", s.Query != ""}, {"poll", s.Poll != nil}, {"headers", len(s.Headers) > 0},
		{"cleanup", len(s.Cleanup) > 0}} {
		if f.set {
			add("%s is not valid for kind git_credential", f.name)
		}
	}
}

// sortedCapabilities lists validCapabilities for error messages.
func sortedCapabilities() []string {
	out := make([]string, 0, len(validCapabilities))
	for c := range validCapabilities {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
