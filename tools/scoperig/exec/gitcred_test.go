package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// buildGHP builds the ghp CLI once per test binary run.
var (
	ghpOnce sync.Once
	ghpBin  string
	ghpErr  error
)

func buildGHP(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the ghp binary")
	}
	ghpOnce.Do(func() {
		dir, err := osTempDir()
		if err != nil {
			ghpErr = err
			return
		}
		ghpBin = filepath.Join(dir, "ghp")
		cmd := osexec.Command("go", "build", "-o", ghpBin, "github.com/goodtune/ghp/cmd/ghp")
		cmd.Env = append(cmdEnv(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			ghpErr = fmt.Errorf("go build ghp: %v: %s", err, out)
		}
	})
	if ghpErr != nil {
		t.Fatal(ghpErr)
	}
	return ghpBin
}

// fakeGitCredServer is the management API and proxied REST API the git
// credential helper and the executor use.
type fakeGitCredServer struct {
	mu        sync.Mutex
	appID     string
	owner     string
	toks      map[string]*fakeCredTok
	order     []string
	n         int
	posts     []map[string]any
	appsCalls int
}

type fakeCredTok struct {
	ID, Value, Type, Session string
	Repos                    []string
	Revoked                  bool
}

func (f *fakeGitCredServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/v3/") {
		val := strings.TrimPrefix(r.Header.Get("Authorization"), "token ")
		var tok *fakeCredTok
		for _, t := range f.toks {
			if t.Value == val && !t.Revoked {
				tok = t
			}
		}
		if tok == nil {
			writeJSONT(w, 401, map[string]string{"message": "Invalid token"})
			return
		}
		repo := strings.TrimPrefix(p, "/api/v3/repos/")
		for _, rr := range tok.Repos {
			if rr == repo {
				writeJSONT(w, 200, map[string]string{"full_name": repo})
				return
			}
		}
		writeJSONT(w, 403, map[string]string{"message": "Token is not scoped to " + repo})
		return
	}
	if r.Header.Get("Authorization") != "Bearer sess" {
		writeJSONT(w, 401, map[string]string{"message": "unauthorized"})
		return
	}
	switch {
	case r.Method == http.MethodGet && p == "/api/apps":
		f.appsCalls++
		writeJSONT(w, 200, []map[string]any{
			{"id": "11111111-1111-4111-8111-111111111111", "name": "default", "is_default": true},
			{"id": f.appID, "name": "rig", "is_default": false}})
	case r.Method == http.MethodGet && p == "/api/apps/"+f.appID+"/installations":
		writeJSONT(w, 200, []map[string]any{{"id": 77, "account": map[string]string{"login": f.owner},
			"permissions": map[string]string{"contents": "write", "metadata": "read"}}})
	case r.Method == http.MethodPost && p == "/api/tokens":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.posts = append(f.posts, body)
		if body["app_record_id"] != f.appID {
			writeJSONT(w, 400, map[string]string{"message": "wrong app"})
			return
		}
		f.n++
		t := &fakeCredTok{ID: fmt.Sprintf("tok-%d", f.n), Value: fmt.Sprintf("gha_fakevalue%04d", f.n), Type: "agent",
			Session: fmt.Sprint(body["session_id"])}
		for _, x := range body["repositories"].([]any) {
			t.Repos = append(t.Repos, fmt.Sprint(x))
		}
		f.toks[t.ID] = t
		f.order = append(f.order, t.ID)
		writeJSONT(w, 201, map[string]any{"token": t.Value, "id": t.ID, "type": "agent", "repositories": t.Repos,
			"scopes": map[string]string{"contents": "write"}, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	case r.Method == http.MethodGet && p == "/api/tokens":
		out := []map[string]any{}
		for _, id := range f.order {
			out = append(out, f.tokJSON(f.toks[id]))
		}
		writeJSONT(w, 200, out)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/api/tokens/"):
		t := f.toks[strings.TrimPrefix(p, "/api/tokens/")]
		if t == nil {
			writeJSONT(w, 404, map[string]string{"message": "not found"})
			return
		}
		writeJSONT(w, 200, f.tokJSON(t))
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/api/tokens/"):
		t := f.toks[strings.TrimPrefix(p, "/api/tokens/")]
		if t == nil {
			writeJSONT(w, 404, map[string]string{"message": "not found"})
			return
		}
		if t.Revoked {
			writeJSONT(w, 400, map[string]string{"message": "already revoked"})
			return
		}
		t.Revoked = true
		writeJSONT(w, 200, map[string]string{"message": "revoked"})
	default:
		writeJSONT(w, 404, map[string]string{"message": "not found"})
	}
}

func (f *fakeGitCredServer) tokJSON(t *fakeCredTok) map[string]any {
	m := map[string]any{"id": t.ID, "token_type": t.Type, "session_id": t.Session, "repositories": t.Repos,
		"token_prefix": t.Value[:8]}
	if t.Revoked {
		m["revoked_at"] = time.Now().UTC().Format(time.RFC3339)
	}
	return m
}

func writeJSONT(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newGitCredEnv(t *testing.T) (*RunEnv, *fakeGitCredServer) {
	t.Helper()
	v := scenario.PlaceholderVars()
	f := &fakeGitCredServer{appID: v.Agent.AppRecordID, owner: v.RepoW.Owner, toks: map[string]*fakeCredTok{}}
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	m := tokens.NewManager(ts.URL, "sess", "run", ts.Client(), 0)
	env := &RunEnv{Vars: v, HTTP: ts.Client(), Mgmt: ts.URL, APIBase: ts.URL + "/api/v3", Tokens: m, Session: "sess",
		GHPPath: buildGHP(t), AgentAppRecordID: v.Agent.AppRecordID}
	return env, f
}

// TestGitCredential_RigScenario runs the checked-in CRED-C55 scenario with
// the real ghp binary against the fake server.
func TestGitCredential_RigScenario(t *testing.T) {
	env, f := newGitCredEnv(t)
	tree, err := scenario.Load("../../../rig")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range tree.Scenarios {
		if s.Kind != "git_credential" {
			continue
		}
		n++
		obs, err := GitCredential{}.Run(context.Background(), s, tokens.Handle{}, env)
		if err != nil {
			t.Fatal(err)
		}
		want, err := scenario.ExpandExpect(s.Expect, env.Vars)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: summary %s", s.ID, obs.Body)
		if errs := expect.Match(want, obs); len(errs) > 0 {
			t.Errorf("%s: %v\nbody %s\nstderr %s", s.ID, errs, obs.Body, obs.Stderr)
		}
		if strings.Contains(string(obs.Body)+obs.Stdout+obs.Stderr, "fakevalue") {
			t.Errorf("token value in observation: %s %s %s", obs.Body, obs.Stdout, obs.Stderr)
		}
	}
	if n != 1 {
		t.Fatalf("git_credential scenarios = %d, want 1", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range f.order {
		if !f.toks[id].Revoked {
			t.Errorf("token %s left live", id)
		}
	}
	if f.appsCalls != 2 {
		t.Errorf("GET /api/apps called %d times, want 2: the cache hit must not contact the server", f.appsCalls)
	}
	if len(f.order) != 2 {
		t.Errorf("minted %d tokens, want 2 (get, cache hit, get after erase)", len(f.order))
	}
	for _, b := range f.posts {
		if b["app_record_id"] != env.AgentAppRecordID || b["type"] != "agent" {
			t.Errorf("mint body %v: want the agent installation app, never the default", b)
		}
	}
}

// TestGitCredential_RequiresConfig checks the executor refuses to run
// without a ghp binary, an agent app, or for a repository other than W.
func TestGitCredential_RequiresConfig(t *testing.T) {
	s := &scenario.Scenario{ID: "X", Kind: "git_credential", Repo: "W"}
	for _, env := range []*RunEnv{{AgentAppRecordID: "a"}, {GHPPath: "/bin/true"}} {
		env.Vars = scenario.PlaceholderVars()
		if _, err := (GitCredential{}).Run(context.Background(), s, tokens.Handle{}, env); err == nil {
			t.Errorf("env %+v: want error", env)
		}
	}
	s.Repo = "A"
	env := &RunEnv{Vars: scenario.PlaceholderVars(), GHPPath: "/bin/true", AgentAppRecordID: "a"}
	if _, err := (GitCredential{}).Run(context.Background(), s, tokens.Handle{}, env); err == nil || !strings.Contains(err.Error(), "only for repo W") {
		t.Errorf("repo A: err = %v", err)
	}
}

func TestTokenPrefixAndParseCredential(t *testing.T) {
	if tokenPrefix("gha_abc") != "gha_" || tokenPrefix("ghx_abc") != "ghx_" || tokenPrefix("plain") != "other" {
		t.Error("tokenPrefix")
	}
	m := parseCredential("protocol=https\nusername=x-access-token\r\npassword=a=b\n")
	if m["username"] != "x-access-token" || m["password"] != "a=b" {
		t.Errorf("parseCredential = %v", m)
	}
}

func osTempDir() (string, error) { return os.MkdirTemp("", "scoperig-ghp-bin-") }

func cmdEnv() []string { return os.Environ() }
