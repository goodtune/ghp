package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/corpus"
	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
)

func buildOracleFakeGH(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gh")
	cmd := osexec.Command("go", "build", "-o", bin, "./exec/testdata/fakegh")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fakegh: %v\n%s", err, out)
	}
	return bin
}

type oracleFixture struct {
	opts     oracleOpts
	captures string // <fake gh dir>/oracle
	out      string
	temps    []string
}

// newOracleFixture builds a fake gh, a fake operator gh config dir and an
// output root seeded with a 2.102.0 pr_list.json carrying a known issue.
func newOracleFixture(t *testing.T) *oracleFixture {
	t.Helper()
	gh := buildOracleFakeGH(t)
	f := &oracleFixture{captures: filepath.Join(filepath.Dir(gh), "oracle"), out: t.TempDir()}
	hosts := []byte("github.com:\n    user: octo\n    oauth_token: FAKEVALUE\n")
	mustWrite(t, filepath.Join(f.captures, "hosts.expected"), hosts)
	realCfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(realCfg, "hosts.yml"), hosts, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realCfg, "config.yml"), []byte("aliases: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile("ghdebug/testdata/pr_list.txt")
	if err != nil {
		t.Fatal(err)
	}
	// The seeded previous version has the original query.
	ex, err := ghdebug.Parse(bytes.NewReader(orig))
	if err != nil {
		t.Fatal(err)
	}
	prev, err := corpus.Build("2.102.0", "pr list", "cli", "cli", ex, nil)
	if err != nil {
		t.Fatal(err)
	}
	prev.GraphQL[0].Expect["perm-ro"] = corpus.Expectation{Verdict: "deny", KnownIssue: "KI-1", Current: "allow"}
	b, err := corpus.Marshal(prev)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(f.out, "2.102.0", "pr_list.json"), b)
	// An older version that must not be chosen as prev.
	mustWrite(t, filepath.Join(f.out, "2.9.0", "pr_list.json"), []byte(`{"gh_version":"2.9.0","command":"pr list","rest":[],"graphql":[]}`))
	// The new gh asks for one more field.
	mustWrite(t, filepath.Join(f.captures, "pr_list.txt"), bytes.Replace(orig, []byte("{number,title}"), []byte("{number,title,newOracleField}"), 1))

	f.opts = oracleOpts{
		GHPath:    gh,
		Version:   "auto",
		Repo:      "cli/cli",
		PR:        1,
		Issue:     1,
		OutRoot:   f.out,
		ConfigDir: realCfg,
		MkdirTemp: func(dir, pattern string) (string, error) {
			d, err := os.MkdirTemp(dir, pattern)
			if err == nil {
				f.temps = append(f.temps, d)
			}
			return d, err
		},
	}
	return f
}

func mustWrite(t *testing.T, name string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOracle_WritesCorpusPreservingExpect(t *testing.T) {
	f := newOracleFixture(t)
	diff, err := runOracle(context.Background(), f.opts)
	if err != nil {
		t.Fatalf("runOracle: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(f.out, "2.103.0", "pr_list.json"))
	if err != nil {
		t.Fatalf("pr_list.json: %v", err)
	}
	var got corpus.File
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.GHVersion != "2.103.0" || got.Command != "pr list" {
		t.Errorf("header = %q %q", got.GHVersion, got.Command)
	}
	if len(got.GraphQL) != 1 {
		t.Fatalf("graphql entries = %d", len(got.GraphQL))
	}
	if e := got.GraphQL[0].Expect["perm-ro"]; e.Verdict != "deny" || e.KnownIssue != "KI-1" || e.Current != "allow" {
		t.Errorf("perm-ro expect not preserved: %+v", e)
	}
	if strings.Contains(string(b), `"cli"`) || strings.Contains(string(b), "cli/cli") {
		t.Errorf("real repo survived:\n%s", b)
	}
	if !strings.Contains(diff, "newOracleField") {
		t.Errorf("diff does not name the new field:\n%s", diff)
	}
	ents, err := os.ReadDir(filepath.Join(f.out, "2.103.0"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != len(oracleMatrix(oracleTarget{Owner: "cli", Name: "cli", PR: 1, Issue: 1})) || len(ents) != 19 {
		t.Errorf("wrote %d files, want 19", len(ents))
	}
	if _, err := os.Stat(filepath.Join(f.out, "2.103.0", "api_repos_OWNER_REPO.json")); err != nil {
		t.Errorf("api repos file: %v", err)
	}
}

// TestOracle_GHEnvironment checks what each gh invocation saw: the copied
// hosts.yml only (0600), GH_DEBUG=api, no GH_HOST, GH_REPO, and serial order.
func TestOracle_GHEnvironment(t *testing.T) {
	f := newOracleFixture(t)
	t.Setenv("GH_HOST", "ghp.example")
	t.Setenv("GH_TOKEN", "ghx_test0000fakevalue")
	if _, err := runOracle(context.Background(), f.opts); err != nil {
		t.Fatalf("runOracle: %v", err)
	}
	log, err := os.ReadFile(filepath.Join(f.captures, "calls.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	if len(lines) != 20 {
		t.Fatalf("gh calls = %d, want 20 (version + 19):\n%s", len(lines), log)
	}
	if !strings.Contains(lines[0], "ARGS=--version") {
		t.Errorf("first call is not --version: %s", lines[0])
	}
	if !strings.Contains(lines[len(lines)-1], "ARGS=workflow list") {
		t.Errorf("calls not in matrix order; last: %s", lines[len(lines)-1])
	}
	for _, l := range lines[1:] {
		for _, want := range []string{"GH_DEBUG=api", "GH_REPO=cli/cli", "HOSTS=0600:same", "CONFIGYML=absent", "GH_HOST=unset", "GH_TOKEN=unset"} {
			if !strings.Contains(l, want) {
				t.Errorf("call missing %q: %s", want, l)
			}
		}
		if !strings.Contains(l, "GH_CONFIG_DIR="+f.temps[0]) {
			t.Errorf("GH_CONFIG_DIR not under injected temp dir %s: %s", f.temps[0], l)
		}
	}
}

func TestOracle_RemovesCredentialCopy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		f := newOracleFixture(t)
		if _, err := runOracle(context.Background(), f.opts); err != nil {
			t.Fatal(err)
		}
		assertTempsGone(t, f.temps)
	})
	t.Run("error", func(t *testing.T) {
		f := newOracleFixture(t)
		f.opts.GHPath = filepath.Join(t.TempDir(), "no-such-gh")
		if _, err := runOracle(context.Background(), f.opts); err == nil {
			t.Fatal("want error for missing gh")
		}
		assertTempsGone(t, f.temps)
	})
}

func assertTempsGone(t *testing.T, temps []string) {
	t.Helper()
	if len(temps) == 0 {
		t.Fatal("temp dir creator was not used")
	}
	for _, d := range temps {
		if _, err := os.Stat(d); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("temp dir %s still exists (err=%v)", d, err)
		}
	}
}

func TestOracle_RefusesUnsafeOutput(t *testing.T) {
	cases := map[string]string{
		"token":    `{"limit":30,"owner":"cli","repo":"cli","q":"ghx_test0000fakevalue"}`,
		"identity": `{"limit":30,"owner":"cli","repo":"cli","q":"is:pr cli"}`,
	}
	for name, vars := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOracleFixture(t)
			b, err := os.ReadFile(filepath.Join(f.captures, "pr_list.txt"))
			if err != nil {
				t.Fatal(err)
			}
			b = bytes.Replace(b, []byte(`{"limit":30,"owner":"cli","repo":"cli","endCursor":"Y3Vyc29yOjE="}`), []byte(vars), 1)
			mustWrite(t, filepath.Join(f.captures, "pr_list.txt"), b)
			_, err = runOracle(context.Background(), f.opts)
			if err == nil {
				t.Fatal("want refusal")
			}
			if strings.Contains(err.Error(), "ghx_test0000fakevalue") {
				t.Errorf("error leaks token: %v", err)
			}
			if _, err := os.Stat(filepath.Join(f.out, "2.103.0")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("output dir written despite refusal (err=%v)", err)
			}
			assertTempsGone(t, f.temps)
		})
	}
}

func TestOracle_RefusesNoLogin(t *testing.T) {
	f := newOracleFixture(t)
	f.opts.ConfigDir = t.TempDir()
	if _, err := runOracle(context.Background(), f.opts); err == nil || !strings.Contains(err.Error(), "hosts.yml") {
		t.Fatalf("err = %v, want hosts.yml error", err)
	}
}

func TestParseGHVersion(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"gh version 2.102.0 (2026-10-01)\nhttps://github.com/cli/cli/releases/tag/v2.102.0\n", "2.102.0", true},
		{"gh version 2.103.1\n", "2.103.1", true},
		{"gh version DEV\n", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseGHVersion(tt.in)
			if (err == nil) != tt.ok || got != tt.want {
				t.Errorf("parseGHVersion(%q) = %q, %v", tt.in, got, err)
			}
		})
	}
}

func TestPrevVersionDir(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"2.9.0", "2.102.0", "2.103.0", "2.104.0", "notes"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct{ version, want string }{
		{"2.103.0", "2.102.0"},
		{"2.105.0", "2.104.0"},
		{"2.10.0", "2.9.0"},
		{"2.9.0", ""},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got, err := prevVersionDir(root, tt.version)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("prevVersionDir(%s) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestOracleCmd_Registered(t *testing.T) {
	var out, errb bytes.Buffer
	cmd := newRootCmd(&out, &errb, func(string) string { return "" }, runDeps{})
	c, _, err := cmd.Find([]string{"oracle"})
	if err != nil || c.Name() != "oracle" {
		t.Fatalf("oracle not registered: %v", err)
	}
	for _, fl := range []string{"gh-version", "oracle-repo", "pr", "issue", "out", "gh"} {
		if c.Flags().Lookup(fl) == nil {
			t.Errorf("missing flag --%s", fl)
		}
	}
}
