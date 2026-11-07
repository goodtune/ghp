package exec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// fakeToken is the secret the fake management API issues (helpers_test.go).
const fakeToken = "ghx_test0000fakevalue"

func buildFakeGH(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gh")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/fakegh")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fakegh: %v\n%s", err, out)
	}
	return bin
}

func ghScenario(args ...string) *scenario.Scenario {
	return &scenario.Scenario{ID: "gh-test", Kind: "gh", Repo: "A", Args: args}
}

// runFakeGH runs s against the fake gh and returns the observation, a
// function listing what is left in TMPDIR, and the run error.
func runFakeGH(t *testing.T, ctx context.Context, s *scenario.Scenario) (*expect.Observation, func() []string, error) {
	t.Helper()
	env, _, tok := newEnv(t, nil)
	env.GHPath = buildFakeGH(t)
	tmpRoot := t.TempDir()
	t.Setenv("TMPDIR", tmpRoot)
	t.Setenv("GH_TOKEN", "ghp_inheritedvalue0000")
	t.Setenv("GITHUB_TOKEN", "ghp_inheritedvalue0001")
	t.Setenv("GH_HOST", "github.com")
	obs, err := GH{}.Run(ctx, s, tok, env)
	left := func() []string {
		ents, _ := os.ReadDir(tmpRoot)
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		return names
	}
	return obs, left, err
}

func checkDenied(t *testing.T, obs *expect.Observation) {
	t.Helper()
	if obs.GHExit == nil || *obs.GHExit != 1 {
		t.Errorf("GHExit = %v, want 1", obs.GHExit)
	}
	if obs.Status != 403 {
		t.Errorf("Status = %d, want 403", obs.Status)
	}
	d := 0
	for _, x := range obs.Exchanges {
		if x.Status == 403 {
			d++
			if x.Path != "/api/v3/repos/a-owner/a-repo/pulls/2" {
				t.Errorf("denied path = %q", x.Path)
			}
		}
	}
	if d != 1 {
		t.Errorf("Exchanges = %+v", obs.Exchanges)
	}
	for _, bad := range []string{"* Request", "> ", "< HTTP", "token not scoped\",", "GraphQL"} {
		if strings.Contains(obs.Stderr, bad) {
			t.Errorf("Stderr keeps debug text %q: %q", bad, obs.Stderr)
		}
	}
	if !strings.Contains(obs.Stderr, "HTTP 403: token not scoped") {
		t.Errorf("Stderr lost gh's error: %q", obs.Stderr)
	}
}

func TestGH_Kind(t *testing.T) {
	if (GH{}).Kind() != "gh" {
		t.Fatal("kind")
	}
}

func TestGH_Env(t *testing.T) {
	obs, left, err := runFakeGH(t, context.Background(), ghScenario("pr", "view", "{{.Fixture.A.PRNumber}}"))
	if err != nil {
		t.Fatal(err)
	}
	out := obs.Stdout
	tmp := os.Getenv("TMPDIR")
	want := []string{
		"ENV GH_HOST=ghp.example\n", "ENV GH_REPO=ghp.example/a-owner/a-repo\n",
		"ENV GH_DEBUG=api\n", "ENV GH_PROMPT_DISABLED=1\n", "ENV NO_COLOR=1\n",
		"ENV GH_NO_UPDATE_NOTIFIER=1\n", "ENV GH_PAGER=cat\n", "ENV PAGER=cat\n",
		"ENV GIT_CEILING_DIRECTORIES=", "ENV GH_ENTERPRISE_TOKEN=len=", "ARGS=pr view 2\n",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
	for _, bad := range []string{"ENV GH_TOKEN=", "ENV GITHUB_TOKEN=", "ENV GH_HOST=github.com", "inheritedvalue"} {
		if strings.Contains(out, bad) {
			t.Errorf("unexpected %q in output", bad)
		}
	}
	got := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "CWD="); ok {
			got["cwd"] = v
		}
		for _, k := range []string{"GH_CONFIG_DIR", "XDG_CACHE_HOME", "HOME", "GIT_CEILING_DIRECTORIES"} {
			if v, ok := strings.CutPrefix(l, "ENV "+k+"="); ok {
				got[k] = v
			}
		}
	}
	rtmp, _ := filepath.EvalSymlinks(tmp)
	for _, name := range []string{"cwd", "GH_CONFIG_DIR", "XDG_CACHE_HOME", "HOME", "GIT_CEILING_DIRECTORIES"} {
		p := got[name]
		if p == "" || (!strings.HasPrefix(p, tmp) && !strings.HasPrefix(p, rtmp)) {
			t.Errorf("%s = %q, want under %q", name, p, tmp)
		}
	}
	repoRoot, _ := filepath.Abs("../../..")
	if strings.HasPrefix(got["cwd"], repoRoot) {
		t.Errorf("cwd %q is inside the repo", got["cwd"])
	}
	if l := left(); len(l) != 0 {
		t.Errorf("temp dirs left behind: %v", l)
	}
}

func TestGH_ParsesFirstDenied(t *testing.T) {
	obs, _, err := runFakeGH(t, context.Background(), ghScenario("pr", "view", "2"))
	if err != nil {
		t.Fatal(err)
	}
	checkDenied(t, obs)
}

func TestGH_StderrKeepsGHMessages(t *testing.T) {
	for _, tc := range []struct{ mode, marker string }{
		{"nottook", "error: no took line marker"},
		{"between", "warning: between requests marker"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			obs, _, err := runFakeGH(t, context.Background(), ghScenario(tc.mode))
			if err != nil {
				t.Fatal(err)
			}
			checkDenied(t, obs)
			if !strings.Contains(obs.Stderr, tc.marker) {
				t.Errorf("Stderr lost %q: %q", tc.marker, obs.Stderr)
			}
		})
	}
}

func TestGH_NoTokenInOutput(t *testing.T) {
	obs, _, err := runFakeGH(t, context.Background(), ghScenario("pr", "view", "2"))
	if err != nil {
		t.Fatal(err)
	}
	all := fmt.Sprintf("%+v", obs)
	if !strings.Contains(all, "/api/v3/repos/a-owner/a-repo/pulls/2") {
		t.Fatalf("dump does not include exchanges: %s", all)
	}
	for _, secret := range []string{fakeToken, "test0000fakevalue"} {
		if strings.Contains(all, secret) {
			t.Errorf("token leaked:\n%s", all)
		}
	}
	if redact.Contains([]byte(all)) {
		t.Errorf("redact.Contains found a token:\n%s", all)
	}
}

func TestGH_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, left, err := runFakeGH(t, ctx, ghScenario("sleep"))
	if err == nil {
		t.Fatal("want rig error on timeout")
	}
	if l := left(); len(l) != 0 {
		t.Errorf("temp dirs left behind: %v", l)
	}
}

func TestGH_NotFound(t *testing.T) {
	env, _, tok := newEnv(t, nil)
	env.GHPath = filepath.Join(t.TempDir(), "no-such-gh")
	if _, err := (GH{}).Run(context.Background(), ghScenario("pr", "list"), tok, env); err == nil {
		t.Fatal("want rig error")
	}
}

// gh pr status needs a current branch: the work dir must be a git checkout
// on the fixture branch (no remotes; GH_REPO names the base repo).
func TestGH_WorkDirIsGitCheckoutOnFixtureBranch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	env, _, tok := newEnv(t, nil)
	env.GHPath = buildFakeGH(t)
	env.Vars.Fixture = map[string]scenario.FixtureVals{"A": {Branch: "scoperig-fixture"}}
	obs, err := GH{}.Run(context.Background(), ghScenario("gitbranch"), tok, env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(obs.Stdout, "BRANCH=scoperig-fixture\n") {
		t.Errorf("stdout = %q", obs.Stdout)
	}
}

func TestStripDebug(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{
			name: "message after a complete exchange",
			in:   "* Request at x\n* Request to https://h/a\n> GET /a HTTP/1.1\n\n< HTTP/2.0 403 Forbidden\n\n{}\n\n* Request took 1ms\nHTTP 403: denied\n",
			want: "HTTP 403: denied\n",
		},
		{
			name: "unterminated GraphQL block ends at the next request",
			in:   "* Request at x\n> POST /graphql HTTP/1.1\n\nGraphQL query:\nquery { a }\n* Request at y\n* Request took 1ms\ngh: kept message\n",
			want: "gh: kept message\n",
		},
		{
			name: "unterminated GraphQL block ends at took",
			in:   "* Request at x\n> POST /graphql HTTP/1.1\n\nGraphQL query:\nquery { a }\n* Request took 2ms\nGraphQL: Resource not accessible\n",
			want: "GraphQL: Resource not accessible\n",
		},
		{
			name: "star and request lines are always removed",
			in:   "before\n* anything\n> anything\nafter\n",
			want: "before\nafter\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripDebug(tt.in); got != tt.want {
				t.Errorf("stripDebug() = %q, want %q", got, tt.want)
			}
		})
	}
}
