package scenario

import "testing"

func TestCorpusVars_WholeWords(t *testing.T) {
	got := corpusVars(map[string]any{
		"q":    "repo:OWNER/REPO is:pr",
		"kind": "REPOSITORY",
		"own":  "OWNERSHIP",
		"r":    "REPO",
	}).(map[string]any)
	want := map[string]string{
		"q":    "repo:{{.RepoA.Owner}}/{{.RepoA.Name}} is:pr",
		"kind": "REPOSITORY",
		"own":  "OWNERSHIP",
		"r":    "{{.RepoA.Name}}",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
}
