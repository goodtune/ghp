package proxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/database"
)

// The gh request corpus lives under rig/corpus/gh/<version>/<command>.json and
// is produced by tools/scoperig. internal/ must not import tools/, so the
// decode structs are declared here.

type ghCorpusFile struct {
	GHVersion string          `json:"gh_version"`
	Command   string          `json:"command"`
	GraphQL   []ghCorpusEntry `json:"graphql"`
}

type ghCorpusEntry struct {
	Operation string                    `json:"operation"`
	Body      json.RawMessage           `json:"body"`
	Expect    map[string]ghCorpusExpect `json:"expect"`
}

type ghCorpusExpect struct {
	Verdict    string `json:"verdict"`
	KnownIssue string `json:"known_issue,omitempty"`
	Current    string `json:"current,omitempty"`
}

var ghCorpusRoot = filepath.Join("..", "..", "rig", "corpus", "gh")

// ghCorpusProfiles are the token profiles every corpus entry is checked against.
var ghCorpusProfiles = []struct {
	name string
	si   tokenScopeInfo
}{
	{"open", tokenScopeInfo{}},
	{"perm-ro", tokenScopeInfo{Scopes: database.Scopes{
		"contents": "read", "issues": "read", "pull_requests": "read", "metadata": "read", "actions": "read",
	}}},
	{"repo", tokenScopeInfo{Repos: []string{"OWNER/REPO"}}},
}

var ghCorpusVerdicts = map[string]bool{
	reasonAllow: true, reasonParse: true, reasonSubscription: true, reasonUnmapped: true,
	reasonCrossRepo: true, reasonMutationRepo: true, reasonUnpinned: true, reasonNoRepoRef: true,
	reasonRepoNotAllowed: true, reasonMutationUnscoped: true, reasonMissingScope: true,
}

const ghCorpusIssuePrefix = "https://github.com/goodtune/ghp/issues/"

var ghCorpusTokenRe = regexp.MustCompile(`(gh[opsurx]_|gha_|ghpr_|github_pat_)[A-Za-z0-9_]{8,}`)

type ghCorpusLoaded struct {
	path string
	dir  string
	raw  []byte
	file ghCorpusFile
}

func loadGHCorpus(t *testing.T) []ghCorpusLoaded {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(ghCorpusRoot, "*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no corpus files under %s", ghCorpusRoot)
	}
	sort.Strings(paths)
	out := make([]ghCorpusLoaded, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f ghCorpusFile
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&f); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out = append(out, ghCorpusLoaded{path: p, dir: filepath.Base(filepath.Dir(p)), raw: raw, file: f})
	}
	return out
}

// classifyCorpus compares an observed verdict with a corpus expectation.
// "pass": matches what the corpus says happens today. "fixed": a known issue
// now yields the desired verdict, so the corpus must drop known_issue and
// current. "changed": a known issue yields neither. "fail": an entry without
// a known issue does not yield its verdict.
func classifyCorpus(got, verdict, current string, known bool) string {
	if !known {
		if got == verdict {
			return "pass"
		}
		return "fail"
	}
	switch got {
	case current:
		return "pass"
	case verdict:
		return "fixed"
	default:
		return "changed"
	}
}

func TestGHCorpus_KnownChanged(t *testing.T) {
	tests := []struct {
		name, got, verdict, current string
		known                       bool
		want                        string
	}{
		{"plain pass", "allow", "allow", "", false, "pass"},
		{"plain fail", "deny:unmapped", "allow", "", false, "fail"},
		{"known still current", "deny:unpinned", "allow", "deny:unpinned", true, "pass"},
		{"known fixed", "allow", "allow", "deny:unpinned", true, "fixed"},
		{"known changed", "deny:cross_repo", "allow", "deny:unpinned", true, "changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyCorpus(tt.got, tt.verdict, tt.current, tt.known); got != tt.want {
				t.Errorf("classifyCorpus = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGHCorpus_Structure(t *testing.T) {
	for _, c := range loadGHCorpus(t) {
		t.Run(c.dir+"/"+filepath.Base(c.path), func(t *testing.T) {
			if c.file.GHVersion != c.dir {
				t.Errorf("gh_version %q does not match directory %q", c.file.GHVersion, c.dir)
			}
			if m := ghCorpusTokenRe.Find(c.raw); m != nil {
				t.Errorf("token-shaped string in corpus file (prefix %q)", m[:4])
			}
			for i, e := range c.file.GraphQL {
				if len(e.Expect) != len(ghCorpusProfiles) {
					t.Errorf("entry %d (%s): expect has %d keys, want %d", i, e.Operation, len(e.Expect), len(ghCorpusProfiles))
				}
				for _, p := range ghCorpusProfiles {
					x, ok := e.Expect[p.name]
					if !ok {
						t.Errorf("entry %d (%s): missing profile %q", i, e.Operation, p.name)
						continue
					}
					if !ghCorpusVerdicts[x.Verdict] {
						t.Errorf("entry %d (%s) %s: verdict %q not in vocabulary", i, e.Operation, p.name, x.Verdict)
					}
					if (x.Current == "") != (x.KnownIssue == "") {
						t.Errorf("entry %d (%s) %s: current and known_issue must be set together", i, e.Operation, p.name)
					}
					if x.Current != "" && !ghCorpusVerdicts[x.Current] {
						t.Errorf("entry %d (%s) %s: current %q not in vocabulary", i, e.Operation, p.name, x.Current)
					}
					if x.KnownIssue != "" && !strings.HasPrefix(x.KnownIssue, ghCorpusIssuePrefix) {
						t.Errorf("entry %d (%s) %s: known_issue %q must start with %s", i, e.Operation, p.name, x.KnownIssue, ghCorpusIssuePrefix)
					}
				}
			}
		})
	}
}

func TestGHCorpus(t *testing.T) {
	for _, c := range loadGHCorpus(t) {
		file := filepath.Join(c.dir, filepath.Base(c.path))
		for i, e := range c.file.GraphQL {
			for _, p := range ghCorpusProfiles {
				name := c.file.GHVersion + "/" + c.file.Command + "/" + e.Operation + "/" + p.name
				t.Run(name, func(t *testing.T) {
					x := e.Expect[p.name]
					d := graphQLVerdict(e.Body, p.si)
					got := d.Reason
					switch classifyCorpus(got, x.Verdict, x.Current, x.KnownIssue != "") {
					case "pass":
					case "fixed":
						t.Errorf("fixed; remove known_issue and current from %s entry %d %s %s (now %q)", file, i, e.Operation, p.name, got)
					case "changed":
						t.Errorf("changed: %s entry %d %s %s: current %q, got %q (%s)", file, i, e.Operation, p.name, x.Current, got, d.Message)
					default:
						t.Errorf("%s entry %d %s %s: got %q, want %q (%s; unknown=%v crossRepo=%v)",
							file, i, e.Operation, p.name, got, x.Verdict, d.Message, d.Analysis.unknownFields, d.Analysis.crossRepoFields)
					}
				})
			}
		}
	}
}
