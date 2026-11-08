package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_OK(t *testing.T) {
	tree, err := Load("testdata/ok")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(tree.Claims) != 2 {
		t.Errorf("claims = %d, want 2", len(tree.Claims))
	}
	if c := tree.Claims["REPO-C05"]; c.Iteration != 1 || c.Testable != "periodic" {
		t.Errorf("claim REPO-C05 = %+v", c)
	}
	if len(tree.Profiles) != 1 {
		t.Fatalf("profiles = %d, want 1", len(tree.Profiles))
	}
	if p := tree.Profiles["repo-A"]; p.Type != "proxy" || p.Duration != "2h" || len(p.Repositories) != 1 {
		t.Errorf("profile = %+v", p)
	}
	if len(tree.Scenarios) != 2 {
		t.Fatalf("scenarios = %d, want 2", len(tree.Scenarios))
	}
	if tree.Scenarios[0].ID != "PERM-C14.issues-write-allows-create" || tree.Scenarios[1].ID != "REPO-C05.other-repo-pulls" {
		t.Errorf("not sorted: %s, %s", tree.Scenarios[0].ID, tree.Scenarios[1].ID)
	}
	s := tree.Scenarios[1]
	if len(s.Steps) != 1 {
		t.Fatalf("shorthand steps = %d, want 1", len(s.Steps))
	}
	st := s.Steps[0]
	if st.Method != "GET" || st.Path != "/repos/{{.RepoB}}/pulls" || st.Expect == nil || st.Expect.Status != 403 {
		t.Errorf("step = %+v", st)
	}
	if st.Expect.GHPDenial == nil || !*st.Expect.GHPDenial {
		t.Errorf("ghp_denial not decoded")
	}
	if s.File == "" || !strings.HasSuffix(s.File, "a.yaml") {
		t.Errorf("File = %q", s.File)
	}
	p := tree.Scenarios[0]
	if len(p.Steps) != 1 || p.Steps[0].Capture["number"] != "$.number" || len(p.Cleanup) != 1 {
		t.Errorf("steps scenario = %+v", p)
	}
}

func writeTree(t *testing.T, scen string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"claims.yaml":   "- {id: X-C1, doc: d, claim: c, iteration: 1, testable: periodic}\n",
		"profiles.yaml": "- {name: open, type: proxy, scopes: \"\", duration: 2h}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "scenarios"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scenarios", "bad.yaml"), []byte(scen), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoad_UnknownField(t *testing.T) {
	dir := writeTree(t, "- id: X-C1.a\n  claim: X-C1\n  kind: rest\n  expct: {status: 200}\n")
	_, err := Load(dir)
	if err == nil {
		t.Fatal("want error for unknown field")
	}
	if !strings.Contains(err.Error(), "bad.yaml") || !strings.Contains(err.Error(), "expct") {
		t.Errorf("error %q should name file and field", err)
	}
}

func TestLoad_DuplicateID(t *testing.T) {
	dir := writeTree(t, "- {id: X-C1.a, claim: X-C1, kind: rest}\n- {id: X-C1.a, claim: X-C1, kind: rest}\n")
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate error, got %v", err)
	}
}

func TestDecodeFile_RejectsSecondDocument(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(p, []byte("- {id: A}\n---\n- {id: B}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	err := decodeFile(p, &out)
	if err == nil || !strings.Contains(err.Error(), "document") {
		t.Fatalf("err = %v, want a second-document error", err)
	}
	// A single document still decodes.
	if err := os.WriteFile(p, []byte("- {id: A}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeFile(p, &out); err != nil || len(out) != 1 {
		t.Fatalf("single document: out=%v err=%v", out, err)
	}
}

func TestNormalise_ClearsScenarioExpect(t *testing.T) {
	want := &Expect{Status: 403}
	s := &Scenario{ID: "X", Kind: "rest", Method: "GET", Path: "/x", Expect: want}
	s.Normalise()
	if s.Expect != nil {
		t.Errorf("Expect = %+v after Normalise, want nil", s.Expect)
	}
	if len(s.Steps) != 1 || s.Steps[0].Expect != want {
		t.Fatalf("steps = %+v", s.Steps)
	}
	if !s.Shorthand() || s.VerdictExpect() != want {
		t.Errorf("Shorthand=%v VerdictExpect=%+v", s.Shorthand(), s.VerdictExpect())
	}
	s.Normalise() // idempotent
	if len(s.Steps) != 1 || s.VerdictExpect() != want {
		t.Errorf("second Normalise changed the scenario: %+v", s)
	}
	// Multi-step scenarios keep their own (absent) scenario Expect.
	m := &Scenario{ID: "M", Kind: "rest", Steps: []Request{{Method: "GET", Path: "/a", Expect: want}}}
	m.Normalise()
	if m.Shorthand() || m.VerdictExpect() != nil {
		t.Errorf("multi-step: Shorthand=%v VerdictExpect=%+v", m.Shorthand(), m.VerdictExpect())
	}
}

func TestDecodeFile_EmptyAndMultiDocument(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantErr    bool
	}{
		{"empty file", "", false},
		{"comment only", "# nothing yet\n", false},
		{"two documents", "- {id: A}\n---\n- {id: B}\n", true},
		{"empty first document then a second", "---\n---\n- {id: B}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "s.yaml")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			var out []map[string]any
			err := decodeFile(p, &out)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && len(out) != 0 {
				t.Errorf("out = %v, want empty", out)
			}
		})
	}
}

func writeCorpusTree(t *testing.T, gen, corpusJSON string) string {
	t.Helper()
	dir := writeTree(t, gen)
	if err := os.WriteFile(filepath.Join(dir, "profiles.yaml"), []byte(
		"- {name: open, type: proxy, duration: 2h}\n- {name: repo-A, type: proxy, repositories: [\"{{.RepoA}}\"], duration: 2h}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cdir := filepath.Join(dir, "corpus", "gh", "9.9.9")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "pr_view.json"), []byte(corpusJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const corpusGen = `- id: X-C1.gh
  claim: X-C1
  doc: d
  description: replay
  kind: corpus
  corpus: corpus/gh/9.9.9
  corpus_profiles: {open: open, repo: repo-A}
`

const corpusOneEntry = `{"gh_version": "9.9.9", "command": "pr view", "rest": [], "graphql": [
 {"operation": "PullRequestByNumber",
  "body": {"query": "query PullRequestByNumber($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { name } }",
           "variables": {"owner": "OWNER", "repo": "REPO", "q": "repo:OWNER/REPO is:pr", "id": "NODE_ID", "n": 1},
           "operationName": "PullRequestByNumber"},
  "expect": {"open": {"verdict": "allow"}, "repo": {"verdict": "deny:cross_repo"}}},
 {"operation": "(anonymous)",
  "body": {"query": "{ viewer { login } }", "variables": {}},
  "expect": {"open": {"verdict": "allow"},
             "repo": {"verdict": "allow", "known_issue": "https://github.com/goodtune/ghp/issues/1", "current": "deny:no_repo_ref"}}}
]}`

func TestLoad_CorpusGenerator(t *testing.T) {
	tree, err := Load(writeCorpusTree(t, corpusGen, corpusOneEntry))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	byID := map[string]*Scenario{}
	for _, s := range tree.Scenarios {
		byID[s.ID] = s
	}
	if len(byID) != 4 {
		t.Fatalf("scenarios = %v, want 4 generated", keysOf(byID))
	}
	if _, ok := byID["X-C1.gh"]; ok {
		t.Fatal("generator entry must not remain in the tree")
	}
	allow := byID["X-C1.gh.pr_view.PullRequestByNumber.open"]
	if allow == nil {
		t.Fatalf("missing allow scenario; have %v", keysOf(byID))
	}
	if allow.Kind != "graphql" || allow.Profile != "open" || allow.Claim != "X-C1" || allow.OperationName != "PullRequestByNumber" {
		t.Errorf("allow = %+v", allow)
	}
	if allow.Expect == nil || allow.Expect.Status != 200 || allow.Expect.GHPDenial == nil || *allow.Expect.GHPDenial {
		t.Errorf("allow expect = %+v", allow.Expect)
	}
	v := allow.Variables
	if v["owner"] != "{{.RepoA.Owner}}" || v["repo"] != "{{.RepoA.Name}}" || v["q"] != "repo:{{.RepoA.Owner}}/{{.RepoA.Name}} is:pr" ||
		v["id"] != "{{.RepoA.NodeID}}" || v["n"] != float64(1) {
		t.Errorf("variables = %v", v)
	}
	deny := byID["X-C1.gh.pr_view.PullRequestByNumber.repo"]
	if deny == nil || deny.Profile != "repo-A" || deny.Expect.Status != 403 || deny.Expect.GHPDenial == nil || !*deny.Expect.GHPDenial ||
		len(deny.Expect.BodyContains) != 1 || deny.Expect.BodyContains[0] != "uses cross-repository fields" {
		t.Errorf("deny = %+v", deny)
	}
	known := byID["X-C1.gh.pr_view.anonymous.repo"]
	if known == nil || known.KnownIssue != "https://github.com/goodtune/ghp/issues/1" || known.Observed == nil ||
		known.Observed.Status != 403 || known.Expect.Status != 200 {
		t.Errorf("known = %+v", known)
	}
	if errs := Validate(tree, nil); len(errs) != 0 {
		t.Errorf("generated scenarios must validate: %v", errs)
	}
}

func TestLoad_CorpusGeneratorErrors(t *testing.T) {
	cases := []struct{ name, gen, corpus, want string }{
		{"unmapped profile", strings.Replace(corpusGen, "{open: open, repo: repo-A}", "{open: open}", 1), corpusOneEntry, `profile "repo"`},
		{"escaping path", strings.Replace(corpusGen, "corpus/gh/9.9.9", "../outside", 1), corpusOneEntry, "corpus"},
		{"empty corpus dir", strings.Replace(corpusGen, "corpus/gh/9.9.9", "corpus/gh", 1), corpusOneEntry, "no corpus files"},
		{"unknown verdict", corpusGen, strings.Replace(corpusOneEntry, `"deny:cross_repo"`, `"deny:bogus"`, 1), "deny:bogus"},
		{"generator with query", corpusGen + "  query: \"{ viewer { login } }\"\n", corpusOneEntry, "kind corpus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeCorpusTree(t, tc.gen, tc.corpus))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func keysOf(m map[string]*Scenario) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
