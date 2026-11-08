package scenario

import (
	"strings"
	"testing"
)

// probe is one adversarial scenario shape that Validate must reject with a
// named rule. rule is a substring of the expected error, so a probe that is
// rejected for an unrelated reason (and would pass once that is fixed) still
// fails the test.
type probe struct {
	name string
	s    *Scenario
	raw  bool   // use rawScenarios (no placeholder expect); for matcher probes
	rule string // substring of the rejection
}

func restProbe(id, method, path string) *Scenario {
	return &Scenario{ID: id, Claim: "C1", Profile: "p", Kind: "rest", Method: method, Path: path}
}

func gqlStepProbe(id, profile, path, query string) *Scenario {
	return &Scenario{ID: id, Claim: "C1", Profile: profile, Kind: "graphql",
		Steps: []Request{{Method: "POST", Path: path, Body: map[string]any{"query": query}}}}
}

func cleanupProbe(id, kind string, c Request) *Scenario {
	s := &Scenario{ID: id, Claim: "C1", Profile: "w", Kind: kind, Cleanup: []Request{c}}
	switch kind {
	case "rest":
		s.Method, s.Path = "GET", "/repos/{{.RepoW}}"
	case "graphql":
		s.Query = `query { repository(owner:"{{.RepoW.Owner}}", name:"{{.RepoW.Name}}") { id } }`
	case "gh":
		s.Repo, s.Args = "W", []string{"pr", "list"}
	case "token_api":
		s.Request = &Request{Method: "GET", Path: "/api/tokens"}
	}
	return s
}

const probeMutation = `mutation { addStar(input:{starrableId:"x"}) { clientMutationId } }`

// adversarialProbes is the standing table of validator bypass classes
// (#303). Add a row whenever a new bypass is found.
var adversarialProbes = []probe{
	// Host tricks: gh must only ever talk to {{.Host}}.
	{"host/other", ghScenario("P-H1", "", "repo", "view", "evil.invalid/{{.RepoA}}"), false, "only {{.Host}} is allowed"},
	{"host/http-url-positional", ghScenario("P-H2", "W", "pr", "comment", "http://{{.Host}}/{{.RepoW}}/pull/1", "--body", "x"), false, "only https URLs"},
	{"host/http-url-readonly", ghScenario("P-H3", "", "pr", "list", "--web", "http://{{.Host}}/{{.RepoA}}"), false, "only https URLs"},
	{"host/http-url-repo-write", ghScenario("P-H14", "", "issue", "create", "--repo", "http://{{.Host}}/{{.RepoW}}", "--title", "x"), false, "only https URLs"},
	{"host/userinfo", ghScenario("P-H4", "", "repo", "view", "https://user@{{.Host}}/{{.RepoA}}"), false, "only {{.Host}} is allowed"},
	{"host/port", ghScenario("P-H5", "", "pr", "list", "-R", "{{.Host}}:8443/{{.RepoA}}"), false, "only {{.Host}} is allowed"},
	{"host/trailing-dot", ghScenario("P-H6", "", "pr", "list", "-R", "{{.Host}}./{{.RepoA}}"), false, "only {{.Host}} is allowed"},
	{"host/trailing-dot-write", ghScenario("P-H7", "", "issue", "create", "--repo", "{{.Host}}./{{.RepoW}}", "--title", "x"), false, "only {{.Host}} is allowed"},
	{"host/hostname-flag", ghScenario("P-H8", "", "api", "--hostname", "evil.invalid", "user"), false, "gh:"},
	{"host/hostname-readonly", ghScenario("P-H9", "A", "pr", "list", "--hostname=evil.invalid"), false, "--hostname is not allowed"},
	{"host/api-absolute-url", ghScenario("P-H10", "", "api", "https://evil.invalid/api/v3/user"), false, "absolute URLs are not allowed"},
	{"host/placeholder-literal", ghScenario("P-H11", "", "repo", "view", PlaceholderHost+"/{{.RepoA}}"), false, "placeholder host"},
	{"host/placeholder-literal-mixed-case", ghScenario("P-H12", "", "pr", "list", "-R", "Ghp.Example/{{.RepoA}}"), false, "placeholder host"},
	{"host/vhost-other", &Scenario{ID: "P-H13", Claim: "C1", Profile: "p", Kind: "rest", Vhost: "evil.invalid", Method: "GET", Path: "/x", Requires: []string{"github_vhost"}}, false, "must be github.com or codeload.github.com"},
	{"host/vhost-codeload-wrong-capability", &Scenario{ID: "P-H15", Claim: "C1", Profile: "p", Kind: "rest", Vhost: "codeload.github.com", Method: "GET", Path: "/x", Requires: []string{"github_vhost"}}, false, "requires: [codeload_vhost]"},
	{"host/vhost-codeload-write", &Scenario{ID: "P-H16", Claim: "C1", Profile: "p", Kind: "rest", Vhost: "codeload.github.com", Method: "POST", Path: "/repos/{{.RepoW}}/x", Requires: []string{"codeload_vhost"}}, false, "must be GET or HEAD"},
	{"matcher/header-except-authorization", &Scenario{ID: "P-M20", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/x",
		Expect: &Expect{HeaderNotContains: []string{"[REDACTED]"}, HeaderNotContainsExcept: []string{"Authorization"}}}, true, "header_not_contains_except may only name Set-Cookie"},
	{"matcher/header-except-alone", &Scenario{ID: "P-M21", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/x",
		Expect: &Expect{Status: 200, HeaderNotContainsExcept: []string{"Set-Cookie"}}}, true, "header_not_contains_except needs header_not_contains"},
	{"gql/operation-name-on-rest", &Scenario{ID: "P-G20", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/x", OperationName: "Op"}, false, "operation_name is only valid"},

	// Path tricks.
	{"path/dot-segment-write", restProbe("P-P1", "POST", "/repos/{{.RepoW}}/../../{{.RepoA}}/issues"), false, "dot segment"},
	{"path/single-dot", restProbe("P-P2", "PUT", "/repos/{{.RepoW}}/./contents/x"), false, "dot segment"},
	{"path/encoded-dot", restProbe("P-P3", "DELETE", "/repos/{{.RepoW}}/%2e%2e/%2e%2e/{{.RepoA}}/git/refs/x"), false, "encoded dot"},
	{"path/encoded-dot-upper", restProbe("P-P4", "GET", "/repos/{{.RepoA}}/%2E%2E/x"), false, "encoded dot"},
	{"path/double-encoded-dot", restProbe("P-P5", "POST", "/repos/{{.RepoW}}/%252e%252e/{{.RepoA}}/issues"), false, "encoded dot"},
	{"path/relative", restProbe("P-P6", "POST", "repos/{{.RepoW}}/issues"), false, "must be absolute"},
	{"path/write-outside-w", restProbe("P-P7", "POST", "/repos/{{.RepoA}}/issues"), false, "write target rule"},
	{"path/write-w-prefix-lookalike", restProbe("P-P8", "POST", "/repos/{{.RepoW}}-evil/issues"), false, "write target rule"},
	{"path/graphql-step-rest-path", gqlStepProbe("P-P9", "w", "/repos/{{.RepoW}}/issues", "query { viewer { login } }"), false, "must be /graphql"},
	{"path/graphql-step-query-string", gqlStepProbe("P-P10", "w", "/graphql?x=1", "query { viewer { login } }"), false, "must be /graphql"},
	{"path/graphql-step-whitespace", gqlStepProbe("P-P11", "w", " /graphql/ ", "query { viewer { login } }"), false, "must be /graphql"},
	{"path/gap-a7-post", restProbe(gapA7ProbeID, "POST", "/repos/{{.RepoW}}/../../{{.RepoB}}/issues"), false, "dot segment"},
	{"path/gap-a7-head", restProbe(gapA7ProbeID, "HEAD", "/repos/{{.RepoA}}/../../{{.RepoB}}/contents/README.md"), false, "dot segment"},
	{"path/gap-a7-graphql", gqlStepProbe(gapA7ProbeID, "w", "/graphql/../graphql", "query { viewer { login } }"), false, "must be /graphql"},
	{"path/gap-a7-cleanup", func() *Scenario {
		s := restProbe(gapA7ProbeID, "GET", "/repos/{{.RepoA}}/../../{{.RepoB}}/contents/README.md")
		s.Cleanup = []Request{{Method: "DELETE", Path: "/repos/{{.RepoW}}/../{{.RepoB}}/git/refs/x"}}
		return s
	}(), false, "dot segment"},
	{"path/token-api-query", &Scenario{ID: "P-P12", Claim: "C1", Kind: "token_api", Request: &Request{Method: "POST", Path: "/api/tokens?x=1"}}, false, "query string"},
	{"path/token-api-proxy-write", &Scenario{ID: "P-P13", Claim: "C1", Kind: "token_api", Request: &Request{Method: "POST", Path: "/api/v3/repos/{{.RepoW}}/issues"}}, false, "/api/tokens"},

	// Cleanup must never be a GraphQL request, on any kind.
	{"cleanup/graphql-path-rest", cleanupProbe("P-C1", "rest", Request{Method: "POST", Path: "/graphql", Body: map[string]any{"query": "query { viewer { login } }"}}), false, "not allowed in cleanup"},
	{"cleanup/graphql-mutation-rest", cleanupProbe("P-C2", "rest", Request{Method: "POST", Path: "/repos/{{.RepoW}}/issues", Body: map[string]any{"query": probeMutation}}), false, "not allowed in cleanup"},
	{"cleanup/graphql-mutation-graphql", cleanupProbe("P-C3", "graphql", Request{Method: "POST", Path: "/graphql", Body: map[string]any{"query": probeMutation}}), false, "not allowed in cleanup"},
	{"cleanup/graphql-mutation-gh", cleanupProbe("P-C4", "gh", Request{Method: "POST", Path: "/graphql", Body: map[string]any{"query": probeMutation}}), false, "not allowed in cleanup"},
	{"cleanup/graphql-mutation-token-api", cleanupProbe("P-C5", "token_api", Request{Method: "POST", Path: "/repos/{{.RepoW}}/x", Body: map[string]any{"query": probeMutation}}), false, "not allowed in cleanup"},
	{"cleanup/write-outside-w", cleanupProbe("P-C6", "rest", Request{Method: "DELETE", Path: "/repos/{{.RepoA}}/git/refs/x"}), false, "write target rule"},

	// Empty or invalid matchers would be a silent PASS (or a KNOWN forever).
	{"matcher/no-expect", &Scenario{ID: "P-M1", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/user"}, true, "expect is required"},
	{"matcher/empty-expect", &Scenario{ID: "P-M2", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/user", Expect: &Expect{}}, true, "at least one assertion"},
	{"matcher/empty-step-expect", &Scenario{ID: "P-M3", Claim: "C1", Profile: "p", Kind: "rest",
		Steps: []Request{{Path: "/user", Expect: &Expect{Status: 200}}, {Path: "/user", Expect: &Expect{}}}}, true, "steps[1]: expect is required"},
	{"matcher/empty-observed", &Scenario{ID: "P-M4", Claim: "C1", Profile: "p", Kind: "gh", Repo: "A", Args: []string{"pr", "list"},
		Expect: &Expect{ExitCode: new(int)}, KnownIssue: "https://github.com/goodtune/ghp/issues/1", Observed: &Expect{}}, true, "observed must have at least one assertion"},
	{"matcher/empty-request-expect", &Scenario{ID: "P-M5", Claim: "C1", Kind: "token_api", Request: &Request{Method: "GET", Path: "/api/tokens", Expect: &Expect{}}}, true, "expect is required"},
	{"matcher/expires-within-no-field", &Scenario{ID: "P-M6", Claim: "C1", Kind: "token_api",
		Request: &Request{Method: "POST", Path: "/api/tokens", Expect: &Expect{ExpiresWithin: &ExpiresWithin{Min: "1m", Max: "2m"}}}}, true, "expires_within: field is required"},
	{"matcher/expires-within-bad-duration", &Scenario{ID: "P-M7", Claim: "C1", Kind: "token_api",
		Request: &Request{Method: "POST", Path: "/api/tokens", Expect: &Expect{ExpiresWithin: &ExpiresWithin{Field: "expires_at", Min: "1 hour", Max: "2h"}}}}, true, "not a duration"},
	{"matcher/expires-within-inverted", &Scenario{ID: "P-M8", Claim: "C1", Kind: "token_api",
		Request: &Request{Method: "POST", Path: "/api/tokens", Expect: &Expect{ExpiresWithin: &ExpiresWithin{Field: "expires_at", Min: "2h", Max: "1h"}}}}, true, "greater than max"},
	{"matcher/template-error-expect", &Scenario{ID: "P-M9", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/user",
		Expect: &Expect{Status: 200, JSON: map[string]string{"$.login": "{{.Nope}}"}}}, true, "Nope"},
	{"matcher/template-error-observed", &Scenario{ID: "P-M10", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/user",
		Expect: &Expect{Status: 200}, KnownIssue: "https://github.com/goodtune/ghp/issues/1", Observed: &Expect{Status: 403, BodyContains: []string{"{{.Step.nope.x}}"}}}, true, "observed"},
	{"matcher/known-without-observed", &Scenario{ID: "P-M11", Claim: "C1", Profile: "p", Kind: "rest", Method: "GET", Path: "/user",
		Expect: &Expect{Status: 200}, KnownIssue: "https://github.com/goodtune/ghp/issues/1"}, true, "must be set together"},

	// gh parser shapes.
	{"gh/multi-op-graphql", ghScenario("P-G1", "", "api", "graphql", "-f", "query=query A { viewer { login } } mutation B { addStar(input:{starrableId:\"x\"}) { clientMutationId } }"), false, "gh:"},
	{"gh/two-query-fields", ghScenario("P-G2", "", "api", "graphql", "-f", "query=query { viewer { login } }", "-f", "query="+probeMutation), false, "exactly one inline -f query="},
	{"gh/graphql-input-file", ghScenario("P-G3", "", "api", "graphql", "--input", "q.json"), false, "--input is not allowed"},
	{"gh/graphql-query-file", ghScenario("P-G4", "", "api", "graphql", "-f", "query=@q.graphql"), false, "@file"},
	{"gh/field-file", ghScenario("P-G5", "", "api", "-X", "POST", "repos/{{.RepoW}}/issues", "-F", "body=@/etc/hostname"), false, "@file values"},
	{"gh/unknown-flag-write", ghScenario("P-G6", "W", "issue", "create", "--title", "x", "--sneaky", "y"), false, "unknown flag"},
	{"gh/unknown-flag-api", ghScenario("P-G7", "", "api", "--sneaky", "repos/{{.RepoA}}/issues", "-X", "POST"), false, "unknown flag"},
	{"gh/bundled-short-flags", ghScenario("P-G8", "W", "pr", "merge", "1", "-sd"), false, "bundled short flags"},
	{"gh/repo-value-flag", ghScenario("P-G9", "", "issue", "create", "-R", "-x", "--title", "t"), false, "looks like a flag"},
	{"gh/repo-equals-flag", ghScenario("P-G10", "", "issue", "create", "--repo=--title", "x"), false, "looks like a flag"},
	{"gh/write-no-repo", ghScenario("P-G11", "", "label", "create", "x"), false, "names no repository"},
	{"gh/write-other-repo-attached", ghScenario("P-G12", "W", "pr", "create", "-R{{.RepoA}}"), false, "writes must target {{.RepoW}}"},
	{"gh/write-unresolvable-positional", ghScenario("P-G13", "W", "issue", "comment", "a/b/c/d", "-b", "x"), false, "does not resolve"},
	{"gh/write-subcommand-not-in-table", ghScenario("P-G14", "W", "repo", "delete", "--yes"), false, "no entry in ghFlagTable"},
	{"gh/api-write-other-repo", ghScenario("P-G15", "", "api", "--method=PATCH", "repos/{{.RepoA}}/issues/1", "-f", "state=closed"), false, "must start with repos/{{.RepoW}}/"},
	{"gh/api-nested-field", ghScenario("P-G16", "", "api", "-X", "POST", "repos/{{.RepoW}}/issues", "-f", "labels[]=x"), false, "nested field"},
	{"gh/api-repo-flag", ghScenario("P-G17", "", "api", "-R", "{{.RepoW}}", "repos/{{.RepoW}}/issues"), false, "does not take --repo"},
	{"gh/show-token", ghScenario("P-G18", "", "auth", "status", "--show-token"), false, "prints the credential"},
	{"gh/auth-token", ghScenario("P-G19", "", "auth", "token"), false, "prints the credential"},
}

func TestValidate_AdversarialProbes(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range adversarialProbes {
		if seen[p.name] {
			t.Fatalf("duplicate probe name %q", p.name)
		}
		seen[p.name] = true
		t.Run(p.name, func(t *testing.T) {
			var tree *Tree
			if p.raw {
				tree = rawScenarios(p.s)
			} else {
				tree = withScenarios(p.s)
			}
			errs := Validate(tree, nil)
			if len(errs) == 0 {
				t.Fatalf("bypass accepted: %s", p.s.ID)
			}
			for _, e := range errs {
				if strings.Contains(e.Error(), p.rule) {
					return
				}
			}
			t.Fatalf("rejected, but not by rule %q:\n%v", p.rule, errs)
		})
	}
}

// Shapes next to the probes that must stay valid, so the rules do not
// over-reach.
func TestValidate_AdversarialProbeControls(t *testing.T) {
	for _, s := range []*Scenario{
		ghScenario("OK-1", "", "repo", "view", "{{.Host}}/{{.RepoA}}"),
		ghScenario("OK-2", "", "pr", "list", "-R", "https://{{.Host}}/{{.RepoA}}"),
		// Hosts compare case-insensitively: the same host, no leak.
		ghScenario("OK-3", "", "pr", "list", "-R", "{{upper .Host}}/{{.RepoA}}"),
		ghScenario("OK-4", "", "api", "graphql", "-f", `query=query { repository(owner:"{{.RepoA.Owner}}", name:"{{.RepoA.Name}}") { id } }`),
		ghScenario("OK-5", "W", "pr", "merge", "1", "-s", "-d"),
		restProbe(gapA7ProbeID, "GET", "/repos/{{.RepoA}}/../../{{.RepoB}}/contents/README.md"),
		restProbe("OK-6", "POST", "/repos/{{.RepoW}}/issues"),
		gqlStepProbe("OK-7", "w", " /graphql ", "query { viewer { login } }"),
		cleanupProbe("OK-8", "rest", Request{Method: "DELETE", Path: "/repos/{{.RepoW}}/git/refs/heads/x"}),
	} {
		t.Run(s.ID, func(t *testing.T) {
			requireNoErr(t, Validate(withScenarios(s), nil))
		})
	}
}
