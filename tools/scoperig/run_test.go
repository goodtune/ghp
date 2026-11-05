package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/report"
)

const (
	fakeSession = "ghpr_test00000000session"
	fakeTokPfx  = "ghx_test0000"
)

// fakeGHP is an httptest stand-in for a GHP instance: the management token
// API plus the proxied GitHub REST API for fixtures and scenarios.
type fakeGHP struct {
	t  *testing.T
	ts *httptest.Server

	mu         sync.Mutex
	tokens     map[string]*fakeTok // id -> token
	order      []string
	nextID     int
	requests   int
	creates    int
	failRevoke bool
	failList   bool // fail GET /api/tokens after the preflight call
	listCalls  int
	pushW      bool
	deletes    []string          // ids passed to DELETE /api/tokens/{id}, in order
	onScenario func(path string) // called for scenario (non-fixture) GETs
}

type fakeTok struct {
	ID, SessionID, Value string
	Revoked              bool
}

func newFakeGHP(t *testing.T) *fakeGHP {
	f := &fakeGHP{t: t, tokens: map[string]*fakeTok{}}
	// A token left by an earlier run (swept) and a foreign one (kept).
	f.tokens["old-1"] = &fakeTok{ID: "old-1", SessionID: "scoperig-20200101T0000Z-aaaa", Value: fakeTokPfx + "old1"}
	f.tokens["other-1"] = &fakeTok{ID: "other-1", SessionID: "manual", Value: fakeTokPfx + "other"}
	f.order = []string{"old-1", "other-1"}
	f.ts = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.ts.Config.ErrorLog = log.New(io.Discard, "", 0) // vhost probe handshake noise
	f.ts.StartTLS()
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeGHP) host() string { return f.ts.Listener.Addr().String() }

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeGHP) tokenOK(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	_, val, _ := strings.Cut(auth, " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.Value == val && !t.Revoked {
			return true
		}
	}
	return false
}

func (f *fakeGHP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	f.mu.Unlock()
	p := r.URL.Path
	switch {
	case p == "/":
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case p == "/login":
		_, _ = fmt.Fprint(w, "<html>ghp version 0.23.0</html>")
	case strings.HasPrefix(p, "/api/tokens"):
		if r.Header.Get("Authorization") != "Bearer "+fakeSession {
			writeJSONResp(w, 401, map[string]string{"message": "unauthorized"})
			return
		}
		f.serveTokens(w, r)
	case strings.HasPrefix(p, "/api/v3"):
		if !f.tokenOK(r) {
			writeJSONResp(w, 401, map[string]string{"message": "Invalid token"})
			return
		}
		f.serveAPI(w, r, strings.TrimPrefix(p, "/api/v3"))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGHP) serveTokens(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/tokens"), "/")
	switch {
	case r.Method == http.MethodGet && id == "" && f.failList && f.listCalls > 0:
		writeJSONResp(w, 500, map[string]string{"message": "list failed"})
	case r.Method == http.MethodGet && id == "":
		f.listCalls++
		list := make([]map[string]any, 0)
		for _, k := range f.order {
			t := f.tokens[k]
			var rev any
			if t.Revoked {
				rev = "2026-11-05T00:00:00Z"
			}
			list = append(list, map[string]any{"id": t.ID, "session_id": t.SessionID, "revoked_at": rev})
		}
		writeJSONResp(w, 200, list)
	case r.Method == http.MethodPost && id == "":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.nextID++
		f.creates++
		t := &fakeTok{ID: fmt.Sprintf("tok-%d", f.nextID), Value: fmt.Sprintf("%s%04d", fakeTokPfx, f.nextID)}
		t.SessionID, _ = body["session_id"].(string)
		f.tokens[t.ID] = t
		f.order = append(f.order, t.ID)
		writeJSONResp(w, 201, map[string]any{"id": t.ID, "token": t.Value})
	case r.Method == http.MethodDelete:
		t, ok := f.tokens[id]
		if !ok {
			writeJSONResp(w, 404, map[string]string{"message": "not found"})
			return
		}
		if f.failRevoke && strings.HasPrefix(id, "tok-") {
			writeJSONResp(w, 500, map[string]string{"message": "boom"})
			return
		}
		if t.Revoked {
			f.deletes = append(f.deletes, id)
			writeJSONResp(w, 400, map[string]string{"message": "token already revoked"})
			return
		}
		f.deletes = append(f.deletes, id)
		t.Revoked = true
		writeJSONResp(w, 200, map[string]string{"status": "revoked"})
	case r.Method == http.MethodGet:
		t, ok := f.tokens[id]
		if !ok {
			writeJSONResp(w, 404, map[string]string{"message": "not found"})
			return
		}
		var rev any
		if t.Revoked {
			rev = "2026-11-05T00:00:00Z"
		}
		writeJSONResp(w, 200, map[string]any{"id": t.ID, "revoked_at": rev})
	default:
		writeJSONResp(w, 405, nil)
	}
}

func (f *fakeGHP) serveAPI(w http.ResponseWriter, r *http.Request, p string) {
	switch p {
	case "/user":
		writeJSONResp(w, 200, map[string]any{"login": "goodtune"})
		return
	case "/", "":
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		writeJSONResp(w, 200, map[string]any{})
		return
	}
	parts := strings.Split(strings.TrimPrefix(p, "/repos/"), "/")
	if !strings.HasPrefix(p, "/repos/") || len(parts) < 2 {
		writeJSONResp(w, 404, map[string]string{"message": "Not Found"})
		return
	}
	repo, rest := parts[0]+"/"+parts[1], strings.Join(parts[2:], "/")
	switch rest {
	case "":
		f.mu.Lock()
		push := f.pushW && strings.HasSuffix(repo, "-w")
		f.mu.Unlock()
		writeJSONResp(w, 200, map[string]any{"id": len(repo) * 1000, "default_branch": "main",
			"permissions": map[string]bool{"push": push}})
		return
	case "issues":
		writeJSONResp(w, 200, []map[string]any{{"number": 1, "title": "scoperig fixture issue"}})
		return
	case "pulls":
		writeJSONResp(w, 200, []map[string]any{{"number": 2, "title": "scoperig fixture PR"}})
		return
	case "releases/tags/scoperig-fixture-v0":
		writeJSONResp(w, 200, map[string]any{"id": 3})
		return
	}
	// Scenario endpoints.
	if f.onScenario != nil {
		f.onScenario(p)
	}
	switch {
	case r.Method == http.MethodDelete && strings.HasPrefix(rest, "git/refs/"):
		writeJSONResp(w, 500, map[string]string{"message": "cleanup boom"})
	case rest == "commits" || rest == "branches" || rest == "tags":
		// Echo the auth header to prove the body is redacted in reports.
		writeJSONResp(w, 200, []map[string]any{{"sha": "abc", "echo": r.Header.Get("Authorization")}})
	default:
		writeJSONResp(w, 404, map[string]string{"message": "Not Found"})
	}
}

func (f *fakeGHP) liveRunTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for _, k := range f.order {
		if t := f.tokens[k]; !t.Revoked && strings.HasPrefix(t.SessionID, "scoperig-") {
			ids = append(ids, k)
		}
	}
	return ids
}

const testClaims = `
- {id: REPO-C05, doc: d.md, claim: c, iteration: 1, testable: periodic}
- {id: REPO-C06, doc: d.md, claim: c, iteration: 1, testable: periodic}
- {id: REPO-C07, doc: d.md, claim: c, iteration: 1, testable: periodic}
- {id: PERM-C14, doc: d.md, claim: c, iteration: 1, testable: periodic}
- {id: PERM-C15, doc: d.md, claim: c, iteration: 1, testable: periodic}
`

const testProfiles = `
- {name: open, type: proxy, duration: 2h}
- {name: repo-A, type: proxy, repositories: ["{{.RepoA}}"], duration: 2h}
`

const testScenarios = `
- id: REPO-C05.other-repo
  claim: REPO-C05
  profile: repo-A
  kind: rest
  method: GET
  path: /repos/{{.RepoB}}/commits
  expect: {status: 403}
- id: REPO-C06.own-repo
  claim: REPO-C06
  profile: repo-A
  kind: rest
  method: GET
  path: /repos/{{.RepoA}}/commits
  expect: {status: 200, body_not_contains: ["nothing"]}
- id: REPO-C07.known
  claim: REPO-C07
  profile: repo-A
  kind: rest
  known_issue: https://github.com/goodtune/ghp/issues/290
  observed: {status: 200}
  method: GET
  path: /repos/{{.RepoA}}/branches
  expect: {status: 403}
- id: PERM-C14.needs-push
  claim: PERM-C14
  profile: open
  kind: rest
  requires: [repo_w_push]
  method: GET
  path: /repos/{{.RepoW}}/commits
  expect: {status: 200}
- id: PERM-C15.residue
  claim: PERM-C15
  profile: open
  kind: rest
  method: GET
  path: /repos/{{.RepoA}}/tags
  expect: {status: 200}
  cleanup:
    - {method: DELETE, path: "/repos/{{.RepoW}}/git/refs/heads/scoperig-{{.RunID}}"}
`

func writeTree(t *testing.T, host, scenarios string) (root, cfg string) {
	t.Helper()
	root = t.TempDir()
	must := func(name, body string) {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("claims.yaml", testClaims)
	must("profiles.yaml", testProfiles)
	must("scenarios/s.yaml", scenarios)
	must("config.yaml", fmt.Sprintf(`instance:
  host: %s
  management_host: %s
  token_create_rate: 20/min
fixtures:
  repo_a: goodtune/ghp-scoperig-a
  repo_b: goodtune/ghp-scoperig-b
  repo_w: goodtune/ghp-scoperig-w
`, host, host))
	return root, filepath.Join(root, "config.yaml")
}

type cliResult struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, env map[string]string, deps runDeps, args ...string) cliResult {
	t.Helper()
	return runCLICtx(t, context.Background(), env, deps, args...)
}

func runCLICtx(t *testing.T, ctx context.Context, env map[string]string, deps runDeps, args ...string) cliResult {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := newRootCmd(&out, &errb, func(k string) string { return env[k] }, deps)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	return cliResult{code: exitCode(err, &errb), stdout: out.String(), stderr: errb.String()}
}

func fakeEnv(f *fakeGHP, root string) map[string]string {
	return map[string]string{"GHP_SERVER_URL": f.ts.URL, "GHP_USER_TOKEN": fakeSession, "GHP_RIG_SCENARIOS": root}
}

func fakeDeps(f *fakeGHP, paceCalls *[]int) runDeps {
	return runDeps{
		HTTP:  f.ts.Client(),
		Now:   func() time.Time { return time.Date(2026, 11, 5, 4, 12, 0, 0, time.UTC) },
		RunID: func() string { return "20261105T0412Z-7f3a" },
		Pace: func(rate int) time.Duration {
			if paceCalls != nil {
				*paceCalls = append(*paceCalls, rate)
			}
			return time.Millisecond
		},
	}
}

func statusesByID(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()
	var doc struct {
		Claims []struct {
			Scenarios []map[string]any `json:"scenarios"`
		} `json:"claims"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode report: %v\n%s", err, raw)
	}
	m := map[string]map[string]any{}
	for _, c := range doc.Claims {
		for _, s := range c.Scenarios {
			m[s["id"].(string)] = s
		}
	}
	return m
}

func TestRun_EndToEndFake(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios)
	out := filepath.Join(t.TempDir(), "report.json")
	var pace []int
	res := runCLI(t, fakeEnv(f, root), fakeDeps(f, &pace), "run", "--config", cfg, "--out", out)

	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (FAIL present)\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := statusesByID(t, raw)
	want := map[string]string{
		"REPO-C05.other-repo": "FAIL",
		"REPO-C06.own-repo":   "PASS",
		"REPO-C07.known":      "KNOWN",
		"PERM-C14.needs-push": "GAP",
		"PERM-C15.residue":    "PASS",
	}
	for id, st := range want {
		if got[id] == nil || got[id]["status"] != st {
			t.Errorf("%s status = %v, want %s", id, got[id]["status"], st)
		}
	}
	if !strings.Contains(res.stdout, "requires repo_w_push") {
		t.Errorf("GAP reason missing from table:\n%s", res.stdout)
	}
	if r, _ := got["PERM-C15.residue"]["residue"].([]any); len(r) != 1 || !strings.Contains(fmt.Sprint(r[0]), "status 500") {
		t.Errorf("cleanup residue = %v, want one entry with status 500", got["PERM-C15.residue"]["residue"])
	}
	// Sweep revoked the stale token and kept the foreign one.
	f.mu.Lock()
	if !f.tokens["old-1"].Revoked || f.tokens["other-1"].Revoked {
		t.Errorf("sweep: old-1 revoked=%v other-1 revoked=%v", f.tokens["old-1"].Revoked, f.tokens["other-1"].Revoked)
	}
	creates := f.creates
	f.mu.Unlock()
	if creates != 2 {
		t.Errorf("created %d tokens, want 2 (open, repo-A)", creates)
	}
	if len(pace) != 1 || pace[0] != 20 {
		t.Errorf("pacer called with %v, want [20]", pace)
	}
	if left := f.liveRunTokens(); len(left) != 0 {
		t.Errorf("tokens left live: %v", left)
	}
	var doc struct {
		Tokens struct {
			Created  int      `json:"created"`
			Revoked  int      `json:"revoked"`
			Leftover []string `json:"leftover_ids"`
		} `json:"tokens"`
	}
	_ = json.Unmarshal(raw, &doc)
	if doc.Tokens.Created != 2 || doc.Tokens.Revoked != 2 || len(doc.Tokens.Leftover) != 0 {
		t.Errorf("tokens = %+v", doc.Tokens)
	}
	for name, s := range map[string]string{"stdout": res.stdout, "stderr": res.stderr, "json": string(raw)} {
		if strings.Contains(s, fakeTokPfx) || strings.Contains(s, fakeSession) {
			t.Errorf("%s contains a token value", name)
		}
	}
}

func TestRun_ValidationErrorExits3(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios+`
- id: BAD.unknown-claim
  claim: NOPE-C99
  profile: open
  kind: rest
  path: /repos/{{.RepoA}}
  expect: {status: 200}
`)
	res := runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg)
	if res.code != 3 {
		t.Fatalf("exit = %d, want 3\n%s", res.code, res.stderr)
	}
	if f.requests != 0 {
		t.Errorf("made %d HTTP requests, want 0", f.requests)
	}
}

func TestRun_PreflightFailExits3(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios)
	env := fakeEnv(f, root)
	env["GHP_USER_TOKEN"] = "ghpr_wrong0000000000"
	res := runCLI(t, env, fakeDeps(f, nil), "run", "--config", cfg)
	if res.code != 3 {
		t.Fatalf("exit = %d, want 3\n%s", res.code, res.stderr)
	}
	if f.creates != 0 {
		t.Errorf("created %d tokens, want 0", f.creates)
	}
	if strings.Contains(res.stderr, "ghpr_wrong") {
		t.Errorf("session token leaked: %s", res.stderr)
	}
}

func TestRun_MissingEnvExits3(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios)
	res := runCLI(t, map[string]string{"GHP_RIG_SCENARIOS": root}, fakeDeps(f, nil), "run", "--config", cfg)
	if res.code != 3 || !strings.Contains(res.stderr, "GHP_SERVER_URL") {
		t.Fatalf("exit = %d stderr=%q, want 3 naming GHP_SERVER_URL", res.code, res.stderr)
	}
}

func TestRun_SignalTriggersRevoke(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	f.onScenario = func(string) { once.Do(cancel) } // first scenario request
	out := filepath.Join(t.TempDir(), "r.json")
	res := runCLICtx(t, ctx, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--out", out)
	if res.code == 0 {
		t.Fatalf("exit = 0 after interrupt\n%s", res.stdout)
	}
	if left := f.liveRunTokens(); len(left) != 0 {
		t.Errorf("tokens left live after cancel: %v", left)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := statusesByID(t, raw)
	// Sorted order: PERM-C14 (GAP, no request), PERM-C15 (cancels), then REPO-*.
	for _, id := range []string{"REPO-C05.other-repo", "REPO-C06.own-repo", "REPO-C07.known"} {
		if got[id]["status"] != "ERROR" {
			t.Errorf("%s status = %v, want ERROR", id, got[id]["status"])
		}
	}
}

func TestRun_SweepFailureExits2(t *testing.T) {
	f := newFakeGHP(t)
	f.failList = true
	root, cfg := writeTree(t, f.host(), `
- id: REPO-C06.own-repo
  claim: REPO-C06
  profile: repo-A
  kind: rest
  method: GET
  path: /repos/{{.RepoA}}/commits
  expect: {status: 200}
`)
	res := runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	f.mu.Lock()
	creates := f.creates
	f.mu.Unlock()
	if creates != 0 {
		t.Errorf("created %d tokens after a failed sweep, want 0", creates)
	}
}

func TestRun_RevokeFailureExits2(t *testing.T) {
	f := newFakeGHP(t)
	f.failRevoke = true
	root, cfg := writeTree(t, f.host(), `
- id: REPO-C06.own-repo
  claim: REPO-C06
  profile: repo-A
  kind: rest
  method: GET
  path: /repos/{{.RepoA}}/commits
  expect: {status: 200}
`)
	res := runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	all := res.stdout + res.stderr
	if !strings.Contains(all, "tok-1") || !strings.Contains(all, "tok-2") {
		t.Errorf("leftover ids not printed:\n%s", all)
	}
	if strings.Contains(all, fakeTokPfx) {
		t.Errorf("token value printed:\n%s", all)
	}
}

func TestRun_ProfileIDsReachTokenAPIDelete(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), `
- id: REPO-C06.revoke-profile
  claim: REPO-C06
  profile: x
  kind: token_api
  steps:
    - {name: revoke, method: DELETE, path: "/api/tokens/{{index .ProfileIDs \"x\"}}", expect: {status: 200}}
  expect: {status: 200}
`)
	if err := os.WriteFile(filepath.Join(root, "profiles.yaml"), []byte(testProfiles+"- {name: x, type: proxy, duration: 2h}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.json")
	res := runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--out", out)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	raw, _ := os.ReadFile(out)
	if st := statusesByID(t, raw)["REPO-C06.revoke-profile"]["status"]; st != "PASS" {
		t.Errorf("status = %v, want PASS", st)
	}
	// open is tok-1, x is tok-2. The scenario's DELETE must target tok-2,
	// and RevokeAll must not error on (or re-send) the already revoked token.
	f.mu.Lock()
	deletes := append([]string(nil), f.deletes...)
	f.mu.Unlock()
	var xDeletes int
	for _, id := range deletes {
		if id == "tok-2" {
			xDeletes++
		}
	}
	if xDeletes != 1 {
		t.Errorf("DELETE /api/tokens/tok-2 sent %d times (deletes %v), want 1", xDeletes, deletes)
	}
	if strings.Contains(res.stdout+res.stderr, "revoke:") {
		t.Errorf("RevokeAll reported an error:\n%s%s", res.stdout, res.stderr)
	}
	if left := f.liveRunTokens(); len(left) != 0 {
		t.Errorf("tokens left live: %v", left)
	}
}

func TestRun_OnlyFilter(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios)
	out := filepath.Join(t.TempDir(), "r.json")
	res := runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--out", out, "--only", "REPO-C06.*")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\n%s\n%s", res.code, res.stdout, res.stderr)
	}
	raw, _ := os.ReadFile(out)
	got := statusesByID(t, raw)
	if len(got) != 1 || got["REPO-C06.own-repo"]["status"] != "PASS" {
		t.Errorf("scenarios = %v, want only REPO-C06.own-repo PASS", got)
	}
	f.mu.Lock()
	swept := f.tokens["old-1"].Revoked
	f.mu.Unlock()
	if !swept {
		t.Error("--only must still sweep")
	}
	if left := f.liveRunTokens(); len(left) != 0 {
		t.Errorf("tokens left live: %v", left)
	}
}

func TestRun_SkipKnown(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios)
	out := filepath.Join(t.TempDir(), "r.json")
	runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--out", out, "--skip-known")
	raw, _ := os.ReadFile(out)
	if _, ok := statusesByID(t, raw)["REPO-C07.known"]; ok {
		t.Error("--skip-known still ran REPO-C07.known")
	}
}

func TestRun_GapClearsWhenCapabilityPresent(t *testing.T) {
	f := newFakeGHP(t)
	f.pushW = true
	root, cfg := writeTree(t, f.host(), testScenarios)
	out := filepath.Join(t.TempDir(), "r.json")
	runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--out", out)
	raw, _ := os.ReadFile(out)
	if st := statusesByID(t, raw)["PERM-C14.needs-push"]["status"]; st != "PASS" {
		t.Errorf("PERM-C14.needs-push = %v, want PASS when repo_w_push probed true", st)
	}
}

func TestRun_ExitCodeMapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		rep  *report.Report
		want int
	}{
		{"pass", repWith(report.StatusPass), 0},
		{"known", repWith(report.StatusKnown), 0},
		{"fail", repWith(report.StatusFail), 1},
		{"changed", repWith(report.StatusKnownChanged), 1},
		{"error", repWith(report.StatusError), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := report.ExitCode(tc.rep)
			var err error
			if code != 0 {
				err = &exitError{code: code}
			}
			if got := exitCode(err, io.Discard); got != tc.want {
				t.Errorf("exit = %d, want %d", got, tc.want)
			}
		})
	}
	if got := exitCode(fmt.Errorf("x: %w", ErrPreflight), io.Discard); got != 3 {
		t.Errorf("preflight exit = %d, want 3", got)
	}
}

func repWith(st report.Status) *report.Report {
	return &report.Report{Claims: []report.ClaimResult{{ID: "X", Status: st,
		Scenarios: []report.ScenarioResult{{ID: "X.a", Claim: "X", Status: st}}}}}
}

func TestValidate_NoEnv(t *testing.T) {
	// Real rig/ tree, empty environment, no HTTP client: must succeed.
	root, err := filepath.Abs("../../rig")
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"GHP_RIG_SCENARIOS": root}
	res := runCLI(t, env, runDeps{}, "validate", "--config", filepath.Join(root, "config.example.yaml"))
	if res.code != 0 {
		t.Fatalf("exit = %d\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "0 errors") {
		t.Errorf("stdout = %q, want '0 errors'", res.stdout)
	}
}

func TestValidate_ReportsErrors(t *testing.T) {
	root, cfg := writeTree(t, "ghp.invalid", `
- id: BAD.x
  claim: NOPE-C99
  profile: open
  kind: rest
  path: /repos/{{.RepoA}}
  expect: {status: 200}
`)
	res := runCLI(t, map[string]string{"GHP_RIG_SCENARIOS": root}, runDeps{}, "validate", "--config", cfg)
	if res.code != 3 || !strings.Contains(res.stdout, "1 errors") {
		t.Fatalf("exit = %d stdout=%q, want 3 and '1 errors'", res.code, res.stdout)
	}
}

func TestDefaultConfig_FallsBackToExample(t *testing.T) {
	src, err := os.ReadFile("../../rig/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../rig")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rig"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rig", "config.example.yaml"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	res := runCLI(t, map[string]string{"GHP_RIG_SCENARIOS": root}, runDeps{}, "validate")
	if res.code != 0 || !strings.Contains(res.stdout, "0 errors") {
		t.Fatalf("exit = %d\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	// An explicit missing --config does not fall back.
	res = runCLI(t, map[string]string{"GHP_RIG_SCENARIOS": root}, runDeps{}, "validate", "--config", "other.yaml")
	if res.code != 3 {
		t.Fatalf("explicit missing config: exit = %d", res.code)
	}
}

func TestPlaceholderFixtureOwner_Exit3(t *testing.T) {
	root, err := filepath.Abs("../../rig")
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"GHP_RIG_SCENARIOS": root, "GHP_SERVER_URL": "https://s.invalid", "GHP_USER_TOKEN": "ghpr_test0000"}
	for _, args := range [][]string{{"run"}, {"fixtures", "ensure"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			res := runCLI(t, env, runDeps{}, append(args, "--config", filepath.Join(root, "config.example.yaml"))...)
			if res.code != 3 || !strings.Contains(res.stderr, "OWNER") {
				t.Fatalf("exit = %d stderr = %q", res.code, res.stderr)
			}
		})
	}
}

// A failed intermediate step in a known_issue scenario must surface as
// KNOWN-CHANGED with the step error, even when the failed step's response
// happens to match observed: (KNOWN) or expect: (KNOWN-FIXED).
func TestRun_KnownIssueStepFailureIsKnownChanged(t *testing.T) {
	for _, tc := range []struct{ name, scenarioExpect string }{
		{"matchesObserved", "{status: 403}"},
		{"matchesExpect", "{status: 200}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeGHP(t)
			root, cfg := writeTree(t, f.host(), `
- id: REPO-C07.steps
  claim: REPO-C07
  profile: repo-A
  kind: rest
  known_issue: https://github.com/goodtune/ghp/issues/290
  observed: {status: 200}
  expect: `+tc.scenarioExpect+`
  steps:
    - {name: one, method: GET, path: "/repos/{{.RepoA}}/branches", expect: {status: 404}}
    - {name: two, method: GET, path: "/repos/{{.RepoA}}/tags"}
`)
			out := filepath.Join(t.TempDir(), "r.json")
			res := runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--out", out)
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("%v\nstdout:\n%s\nstderr:\n%s", err, res.stdout, res.stderr)
			}
			got := statusesByID(t, raw)["REPO-C07.steps"]
			if got["status"] != "KNOWN-CHANGED" {
				t.Fatalf("status = %v, want KNOWN-CHANGED (%v)", got["status"], got)
			}
			if d, _ := got["detail"].(string); !strings.Contains(d, "one") {
				t.Errorf("detail = %q, want the step error", d)
			}
		})
	}
}
