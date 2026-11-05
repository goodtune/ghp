package fixtures

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGitHub is an httptest-backed stand-in for GitHub's REST API. It keeps
// minimal state for one or more repositories and records every call.
type fakeGitHub struct {
	mu    sync.Mutex
	repos map[string]*fakeRepo // "owner/name"
	login string
	calls []string // "METHOD /path?query"
	srv   *httptest.Server
}

type fakeRepo struct {
	id                         int64
	label, issue, branch, file bool
	pr, release                bool
	empty                      bool // no commits yet: git ref reads return 409
}

func newFake(t *testing.T, login string) *fakeGitHub {
	f := &fakeGitHub{repos: map[string]*fakeRepo{}, login: login}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func fullRepo(id int64) *fakeRepo {
	return &fakeRepo{id: id, label: true, issue: true, branch: true, file: true, pr: true, release: true}
}

func (f *fakeGitHub) nonGET() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET ") {
			out = append(out, c)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := r.Method + " " + r.URL.Path
	if r.URL.RawQuery != "" {
		call += "?" + r.URL.RawQuery
	}
	f.calls = append(f.calls, call)
	nf := func() { writeJSON(w, 404, map[string]string{"message": "Not Found"}) }

	if r.Method == "POST" && r.URL.Path == "/user/repos" {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["private"] != true || b["auto_init"] != true {
			writeJSON(w, 422, nil)
			return
		}
		name := f.login + "/" + b["name"].(string)
		f.repos[name] = &fakeRepo{id: 999}
		writeJSON(w, 201, map[string]any{"id": 999})
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/repos/"), "/", 3)
	if len(parts) < 2 {
		nf()
		return
	}
	full := parts[0] + "/" + parts[1]
	rp := f.repos[full]
	if rp == nil {
		nf()
		return
	}
	rest := ""
	if len(parts) == 3 {
		rest = parts[2]
	}
	q := r.URL.Query()
	if rp.empty && r.Method == "GET" && strings.HasPrefix(rest, "git/ref/") {
		writeJSON(w, 409, map[string]string{"message": "Git Repository is empty."})
		return
	}
	switch {
	case r.Method == "PUT" && rest == "contents/README.md":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if !rp.empty || b["branch"] != nil || b["content"] == "" {
			writeJSON(w, 422, nil)
			return
		}
		rp.empty = false
		writeJSON(w, 201, nil)
	case r.Method == "GET" && rest == "":
		writeJSON(w, 200, map[string]any{"id": rp.id, "default_branch": "main", "owner": map[string]any{"login": parts[0]}, "name": parts[1]})
	case r.Method == "GET" && rest == "labels/scoperig":
		if !rp.label {
			nf()
			return
		}
		writeJSON(w, 200, map[string]any{"name": "scoperig"})
	case r.Method == "POST" && rest == "labels":
		rp.label = true
		writeJSON(w, 201, map[string]any{"name": "scoperig"})
	case r.Method == "GET" && rest == "issues":
		out := []any{map[string]any{"number": 1, "title": "unrelated"}}
		if rp.issue && q.Get("labels") == "scoperig" && q.Get("state") == "open" {
			out = append(out, map[string]any{"number": 7, "title": IssueTitle})
		}
		writeJSON(w, 200, out)
	case r.Method == "POST" && rest == "issues":
		rp.issue = true
		writeJSON(w, 201, map[string]any{"number": 7})
	case r.Method == "GET" && rest == "git/ref/heads/main":
		writeJSON(w, 200, map[string]any{"object": map[string]any{"sha": "abc123"}})
	case r.Method == "GET" && rest == "git/ref/heads/"+Branch:
		if !rp.branch {
			nf()
			return
		}
		writeJSON(w, 200, map[string]any{"object": map[string]any{"sha": "def456"}})
	case r.Method == "POST" && rest == "git/refs":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["ref"] != "refs/heads/"+Branch || b["sha"] != "abc123" {
			writeJSON(w, 422, nil)
			return
		}
		rp.branch = true
		writeJSON(w, 201, nil)
	case r.Method == "GET" && rest == "contents/"+FixtureFile:
		if !rp.file || q.Get("ref") != Branch {
			nf()
			return
		}
		writeJSON(w, 200, map[string]any{"sha": "f1"})
	case r.Method == "PUT" && rest == "contents/"+FixtureFile:
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["branch"] != Branch || b["content"] == "" {
			writeJSON(w, 422, nil)
			return
		}
		rp.file = true
		writeJSON(w, 201, nil)
	case r.Method == "GET" && rest == "pulls":
		out := []any{}
		if rp.pr && q.Get("head") == parts[0]+":"+Branch && q.Get("state") == "open" {
			out = append(out, map[string]any{"number": 8, "title": PRTitle})
		}
		writeJSON(w, 200, out)
	case r.Method == "POST" && rest == "pulls":
		rp.pr = true
		writeJSON(w, 201, map[string]any{"number": 8})
	case r.Method == "GET" && rest == "releases/tags/"+ReleaseTag:
		if !rp.release {
			nf()
			return
		}
		writeJSON(w, 200, map[string]any{"id": 4242, "tag_name": ReleaseTag})
	case r.Method == "POST" && rest == "releases":
		rp.release = true
		writeJSON(w, 201, map[string]any{"id": 4242})
	default:
		writeJSON(w, 500, map[string]string{"message": fmt.Sprintf("unexpected %s", call)})
	}
}

func api(f *fakeGitHub) API { return NewHTTPAPI(f.srv.Client(), f.srv.URL, "ghx_test0000") }

func TestDiscover_OK(t *testing.T) {
	f := newFake(t, "goodtune")
	f.repos["goodtune/ghp-scoperig-a"] = fullRepo(101)
	ref, v, err := Discover(context.Background(), api(f), "goodtune/ghp-scoperig-a")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Owner != "goodtune" || ref.Name != "ghp-scoperig-a" || ref.ID != 101 {
		t.Errorf("ref = %+v", ref)
	}
	if v.IssueNumber != 7 || v.PRNumber != 8 || v.ReleaseID != 4242 || v.Branch != Branch ||
		v.Label != Label || v.PRTitle != PRTitle || v.IssueTitle != IssueTitle || v.ReleaseTag != ReleaseTag {
		t.Errorf("vals = %+v", v)
	}
	if n := f.nonGET(); len(n) != 0 {
		t.Errorf("non-GET calls: %v", n)
	}
}

func TestDiscover_MissingPR(t *testing.T) {
	f := newFake(t, "goodtune")
	r := fullRepo(101)
	r.pr = false
	f.repos["goodtune/ghp-scoperig-a"] = r
	_, _, err := Discover(context.Background(), api(f), "goodtune/ghp-scoperig-a")
	if err == nil || !strings.Contains(err.Error(), "fixture pr missing in goodtune/ghp-scoperig-a; run 'scoperig fixtures ensure'") {
		t.Fatalf("err = %v", err)
	}
}

func TestDiscover_MissingRepo(t *testing.T) {
	f := newFake(t, "goodtune")
	_, _, err := Discover(context.Background(), api(f), "goodtune/ghp-scoperig-a")
	if err == nil || !strings.Contains(err.Error(), "fixture repo missing") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsure_NoCreateFlag(t *testing.T) {
	f := newFake(t, "goodtune")
	p, err := Ensure(context.Background(), api(f), "goodtune/ghp-scoperig-a", "goodtune", false, true)
	if err == nil || !strings.Contains(err.Error(), "would create goodtune/ghp-scoperig-a; pass --create-fixtures") {
		t.Fatalf("err = %v", err)
	}
	if !p.Create || p.Repo != "goodtune/ghp-scoperig-a" || len(p.Seed) == 0 {
		t.Errorf("plan = %+v", p)
	}
	if n := f.nonGET(); len(n) != 0 {
		t.Errorf("non-GET calls: %v", n)
	}
}

func TestEnsure_CreateWithoutCapability(t *testing.T) {
	f := newFake(t, "goodtune")
	_, err := Ensure(context.Background(), api(f), "goodtune/ghp-scoperig-a", "goodtune", true, false)
	if err == nil || !strings.Contains(err.Error(), "gh repo create --private") {
		t.Fatalf("err = %v", err)
	}
	if n := f.nonGET(); len(n) != 0 {
		t.Errorf("non-GET calls: %v", n)
	}
}

func TestEnsure_CreatesAndSeeds(t *testing.T) {
	f := newFake(t, "goodtune")
	p, err := Ensure(context.Background(), api(f), "goodtune/ghp-scoperig-a", "goodtune", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Create {
		t.Errorf("plan.Create false")
	}
	n := f.nonGET()
	if len(n) == 0 || n[0] != "POST /user/repos" {
		t.Fatalf("calls: %v", n)
	}
	if _, _, err := Discover(context.Background(), api(f), "goodtune/ghp-scoperig-a"); err != nil {
		t.Fatalf("discover after ensure: %v", err)
	}
}

func TestEnsure_Idempotent(t *testing.T) {
	f := newFake(t, "goodtune")
	f.repos["goodtune/ghp-scoperig-a"] = fullRepo(101)
	p, err := Ensure(context.Background(), api(f), "goodtune/ghp-scoperig-a", "goodtune", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Create || len(p.Seed) != 0 {
		t.Errorf("plan = %+v", p)
	}
	if n := f.nonGET(); len(n) != 0 {
		t.Errorf("non-GET calls: %v", n)
	}
}

func TestEnsure_SeedsMissing(t *testing.T) {
	f := newFake(t, "goodtune")
	f.repos["goodtune/ghp-scoperig-a"] = &fakeRepo{id: 101}
	p, err := Ensure(context.Background(), api(f), "goodtune/ghp-scoperig-a", "goodtune", false, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /repos/goodtune/ghp-scoperig-a/labels",
		"POST /repos/goodtune/ghp-scoperig-a/issues",
		"POST /repos/goodtune/ghp-scoperig-a/git/refs",
		"PUT /repos/goodtune/ghp-scoperig-a/contents/fixture.txt",
		"POST /repos/goodtune/ghp-scoperig-a/pulls",
		"POST /repos/goodtune/ghp-scoperig-a/releases",
	}
	got := f.nonGET()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(p.Seed) != len(want) {
		t.Errorf("plan seed = %v", p.Seed)
	}
	// Second run is a no-op.
	before := len(f.nonGET())
	if _, err := Ensure(context.Background(), api(f), "goodtune/ghp-scoperig-a", "goodtune", false, false); err != nil {
		t.Fatal(err)
	}
	if after := len(f.nonGET()); after != before {
		t.Errorf("second ensure made %d non-GET calls", after-before)
	}
}

func TestEnsure_RefusesNonRigRepo(t *testing.T) {
	tests := []struct {
		repo, login string
		allowed     bool
	}{
		{"goodtune/ghp", "goodtune", false},
		{"other/ghp-scoperig-a", "goodtune", false},
		{"goodtune/ghp-scoperig-a", "goodtune", true},
		{"goodtune/ghp-scoperig-a", "", false},
		{"bad", "goodtune", false},
	}
	for _, tt := range tests {
		t.Run(tt.repo+"@"+tt.login, func(t *testing.T) {
			f := newFake(t, "goodtune")
			for _, name := range []string{"goodtune/ghp", "other/ghp-scoperig-a", "goodtune/ghp-scoperig-a"} {
				f.repos[name] = &fakeRepo{id: 1}
			}
			_, err := Ensure(context.Background(), api(f), tt.repo, tt.login, true, true)
			if tt.allowed {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "refusing") {
				t.Fatalf("err = %v", err)
			}
			if n := f.nonGET(); len(n) != 0 {
				t.Errorf("non-GET calls: %v", n)
			}
		})
	}
}

type staticAPI struct {
	status int
	body   string
}

func (s staticAPI) Do(context.Context, string, string, any) (int, []byte, error) {
	return s.status, []byte(s.body), nil
}

func TestErrorIncludesRedactedBody(t *testing.T) {
	body := `{"message":"Bad credentials","token":"ghx_test0000abcdef"}` + strings.Repeat("x", 2000)
	_, _, err := Discover(context.Background(), staticAPI{401, body}, "goodtune/ghp-scoperig-a")
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "status 401") || !strings.Contains(msg, "Bad credentials") {
		t.Errorf("err = %q", msg)
	}
	if strings.Contains(msg, "ghx_test0000") {
		t.Errorf("token leaked: %q", msg)
	}
	if len(msg) > 700 {
		t.Errorf("body not truncated: %d bytes", len(msg))
	}
}

// A repo made by hand with 'gh repo create --private' has no commits; GitHub
// answers git ref reads with 409. Ensure must make an initial commit first.
func TestEnsure_SeedsEmptyRepo(t *testing.T) {
	f := newFake(t, "goodtune")
	f.repos["goodtune/ghp-scoperig-a"] = &fakeRepo{id: 101, empty: true}
	p, err := Ensure(context.Background(), api(f), "goodtune/ghp-scoperig-a", "goodtune", false, false)
	if err != nil {
		t.Fatal(err)
	}
	got := f.nonGET()
	if len(got) < 3 || got[2] != "PUT /repos/goodtune/ghp-scoperig-a/contents/README.md" {
		t.Fatalf("calls: %v", got)
	}
	if len(p.Seed) != 7 {
		t.Errorf("plan seed = %v", p.Seed)
	}
	before := len(f.nonGET())
	if _, err := Ensure(context.Background(), api(f), "goodtune/ghp-scoperig-a", "goodtune", false, false); err != nil {
		t.Fatal(err)
	}
	if after := len(f.nonGET()); after != before {
		t.Errorf("second ensure made %d non-GET calls", after-before)
	}
}
