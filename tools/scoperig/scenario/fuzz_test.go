package scenario

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzLoadValidate feeds arbitrary scenario files through Load and Validate
// (#303). It must never panic, and any scenario Validate accepts must keep
// every REST write (steps and cleanup) on /repos/{{.RepoW}}/ once expanded
// with the placeholder Vars. `go test` runs the seeds; run
// `go test -fuzz FuzzLoadValidate ./tools/scoperig/scenario` to search.
func FuzzLoadValidate(f *testing.F) {
	for _, seed := range []string{
		"- {id: C1.ok, claim: C1, profile: w, kind: rest, method: POST, path: \"/repos/{{.RepoW}}/issues\", expect: {status: 201}}\n",
		"- {id: C1.read, claim: C1, profile: p, kind: rest, path: \"/repos/{{.RepoA}}\", expect: {status: 200}}\n",
		"- {id: C1.dots, claim: C1, profile: w, kind: rest, method: DELETE, path: \"/repos/{{.RepoW}}/../{{.RepoA}}/x\", expect: {status: 403}}\n",
		"- {id: C1.enc, claim: C1, profile: w, kind: rest, method: PUT, path: \"/repos/{{.RepoW}}/%2e%2e/x\", expect: {status: 403}}\n",
		"- id: C1.steps\n  claim: C1\n  profile: w\n  kind: rest\n  steps:\n    - {name: a, method: POST, path: \"/repos/{{.RepoW}}/issues\", expect: {status: 201}, capture: {n: $.number}}\n  cleanup:\n    - {method: PATCH, path: \"/repos/{{.RepoW}}/issues/{{index .Step \\\"a\\\" \\\"n\\\"}}\"}\n",
		"- {id: C1.gh, claim: C1, profile: w, kind: gh, repo: W, args: [issue, create, --title, x], expect: {exit_code: 0}}\n",
		"- {id: C1.gql, claim: C1, profile: w, kind: graphql, query: \"query { viewer { login } }\", expect: {status: 200}}\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, scen string) {
		dir := t.TempDir()
		files := map[string]string{
			"claims.yaml": "- {id: C1, doc: d, claim: c, iteration: 1, testable: periodic}\n",
			"profiles.yaml": "- {name: p, type: proxy, repositories: [\"{{.RepoA}}\"], duration: 1h}\n" +
				"- {name: w, type: proxy, repositories: [\"{{.RepoW}}\"], duration: 1h}\n" +
				"- {name: open, type: proxy, duration: 1h}\n",
			"scenarios/s.yaml": scen,
		}
		for name, body := range files {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		tree, err := Load(dir)
		if err != nil {
			return
		}
		v := PlaceholderVars()
		if len(Validate(tree, v)) > 0 {
			return
		}
		w := "/repos/" + v.RepoW.String() + "/"
		for _, s := range tree.Scenarios {
			if s.Kind != "rest" {
				continue
			}
			cv := CaptureVars(s, v)
			for _, r := range append(append([]Request{}, s.Steps...), s.Cleanup...) {
				m := strings.ToUpper(strings.TrimSpace(r.Method))
				if m == "" || m == "GET" || m == "HEAD" {
					continue
				}
				p, err := Expand(r.Path, cv)
				if err != nil {
					t.Fatalf("%s: accepted, but path %q does not expand: %v", s.ID, r.Path, err)
				}
				if raw, _, _ := strings.Cut(p, "?"); !strings.HasPrefix(path.Clean(raw), w) || strings.Contains(strings.ToLower(raw), "%2e") {
					t.Fatalf("%s: accepted write %s %q leaves W", s.ID, m, p)
				}
			}
		}
	})
}
