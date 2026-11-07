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
