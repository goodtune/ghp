package exec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

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

func runFakeGH(t *testing.T, ctx context.Context, s *scenario.Scenario) (string, error, func() []string) {
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
	if obs == nil {
		return "", err, left
	}
	if obs.GHExit == nil || *obs.GHExit != 1 {
		t.Errorf("GHExit = %v, want 1", obs.GHExit)
	}
	if obs.Status != 403 {
		t.Errorf("Status = %d, want 403", obs.Status)
	}
	if len(obs.Exchanges) != 1 || obs.Exchanges[0].Path != "/api/v3/repos/a-owner/a-repo/pulls/2" {
		t.Errorf("Exchanges = %+v", obs.Exchanges)
	}
	if strings.Contains(obs.Stderr, "* Request") || !strings.Contains(obs.Stderr, "HTTP 403") {
		t.Errorf("Stderr not stripped of debug log: %q", obs.Stderr)
	}
	return obs.Stdout + "\n--stderr--\n" + obs.Stderr + "\n" + obs.Exchanges[0].ResponseBody, err, left
}

func TestGH_Kind(t *testing.T) {
	if (GH{}).Kind() != "gh" {
		t.Fatal("kind")
	}
}

func TestGH_Env(t *testing.T) {
	out, err, left := runFakeGH(t, context.Background(), ghScenario("pr", "view", "{{.Fixture.A.PRNumber}}"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ENV GH_HOST=ghp.example\n", "ENV GH_REPO=ghp.example/a-owner/a-repo\n",
		"ENV GH_DEBUG=api\n", "ENV GH_PROMPT_DISABLED=1\n", "ENV NO_COLOR=1\n",
		"ENV GH_NO_UPDATE_NOTIFIER=1\n", "ENV GH_ENTERPRISE_TOKEN=len=", "ARGS=pr view 2\n",
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
	tmp := os.Getenv("TMPDIR")
	var cwd, cfg, cache, home string
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "CWD="); ok {
			cwd = v
		}
		if v, ok := strings.CutPrefix(l, "ENV GH_CONFIG_DIR="); ok {
			cfg = v
		}
		if v, ok := strings.CutPrefix(l, "ENV XDG_CACHE_HOME="); ok {
			cache = v
		}
		if v, ok := strings.CutPrefix(l, "ENV HOME="); ok {
			home = v
		}
	}
	rtmp, _ := filepath.EvalSymlinks(tmp)
	for name, p := range map[string]string{"cwd": cwd, "cfg": cfg, "cache": cache, "home": home} {
		rp := p
		if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			rp = filepath.Join(r, filepath.Base(p))
		}
		if p == "" || !(strings.HasPrefix(p, tmp) || strings.HasPrefix(rp, rtmp)) {
			t.Errorf("%s = %q, want under %q", name, p, tmp)
		}
	}
	repoRoot, _ := filepath.Abs("../../..")
	if strings.HasPrefix(cwd, repoRoot) {
		t.Errorf("cwd %q is inside the repo", cwd)
	}
	if l := left(); len(l) != 0 {
		t.Errorf("temp dirs left behind: %v", l)
	}
}

func TestGH_ParsesFirstDenied(t *testing.T) {
	_, err, _ := runFakeGH(t, context.Background(), ghScenario("pr", "view", "2"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestGH_NoTokenInOutput(t *testing.T) {
	out, err, _ := runFakeGH(t, context.Background(), ghScenario("pr", "view", "2"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ghx_test0000fakevalue") {
		t.Errorf("token leaked:\n%s", out)
	}
}

func TestGH_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err, left := runFakeGH(t, ctx, ghScenario("sleep"))
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
