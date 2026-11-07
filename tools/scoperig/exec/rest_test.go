package exec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

func TestREST_SendsPathVerbatim(t *testing.T) {
	var got string
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.RequestURI }))
	for _, p := range []string{"/repos/O/R/../../B/contents/README.md", "/repos/OWNER/NAME", "/repos/o/r/%2e%2e/x"} {
		s := &scenario.Scenario{ID: "x", Kind: "rest", Path: p}
		if _, err := (restExecutor{}).Run(context.Background(), s, tok, env); err != nil {
			t.Fatal(err)
		}
		if got != "/api/v3"+p {
			t.Errorf("RequestURI = %q, want %q", got, "/api/v3"+p)
		}
	}
}

func TestREST_StepsCaptureAndCleanup(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.RequestURI)
		mu.Unlock()
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"number":7}`)
		case strings.HasSuffix(r.RequestURI, "/fail"):
			w.WriteHeader(500)
		default:
			w.WriteHeader(204)
		}
	}))
	s := &scenario.Scenario{ID: "x", Kind: "rest",
		Steps: []scenario.Request{
			{Name: "create", Method: "POST", Path: "/repos/w/w/issues", Body: map[string]any{"title": "t"}, Capture: map[string]string{"n": "$.number"}},
			{Name: "two", Path: "/repos/w/w/fail", Expect: &scenario.Expect{Status: 200}},
		},
		Cleanup: []scenario.Request{{Method: "PATCH", Path: `/repos/w/w/issues/{{index .Step "create" "n"}}`}},
	}
	_, err := (restExecutor{}).Run(context.Background(), s, tok, env)
	var sf StepFailure
	if !errors.As(err, &sf) || sf.Step != "two" {
		t.Fatalf("err = %v, want StepFailure for step two", err)
	}
	if res := RunCleanup(context.Background(), s, env); len(res) != 0 {
		t.Fatalf("residue = %v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if last := seen[len(seen)-1]; last != "PATCH /api/v3/repos/w/w/issues/7" {
		t.Errorf("cleanup sent %q", last)
	}
}

func TestREST_CleanupResidue(t *testing.T) {
	env, _, _ := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	s := &scenario.Scenario{ID: "x", Kind: "rest", Cleanup: []scenario.Request{{Method: "DELETE", Path: "/repos/w/w/git/refs/x"}}}
	if res := RunCleanup(context.Background(), s, env); len(res) != 1 || !strings.Contains(res[0], "500") {
		t.Fatalf("residue = %v", res)
	}
}

func TestREST_HeaderOverridesAuthorization(t *testing.T) {
	var got string
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") }))
	s := &scenario.Scenario{ID: "x", Kind: "rest", Path: "/user", Headers: map[string]string{"Authorization": "token ghp_notreal"}}
	if _, err := (restExecutor{}).Run(context.Background(), s, tok, env); err != nil {
		t.Fatal(err)
	}
	if got != "token ghp_notreal" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestREST_ObservationRedacted(t *testing.T) {
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"auth":"`+r.Header.Get("Authorization")+`"}`)
	}))
	s := &scenario.Scenario{ID: "x", Kind: "rest", Path: "/user"}
	obs, err := (restExecutor{}).Run(context.Background(), s, tok, env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(obs.Body), "test0000") || strings.Contains(obs.Header.Get("X-Echo"), "test0000") {
		t.Errorf("token leaked: %s", obs.Body)
	}
}

func TestREST_BodyCapped(t *testing.T) {
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("a", 2*MaxBody))
	}))
	obs, err := (restExecutor{}).Run(context.Background(), &scenario.Scenario{ID: "x", Kind: "rest", Path: "/"}, tok, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Body) != MaxBody {
		t.Errorf("len = %d", len(obs.Body))
	}
}

// failOnce fails the first round trip with a transport error.
type failOnce struct {
	mu sync.Mutex
	n  int
}

func (f *failOnce) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.n++
	n := f.n
	f.mu.Unlock()
	if n == 1 {
		return nil, errors.New("boom")
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestREST_RetriesTransportErrorOnce(t *testing.T) {
	var calls atomic.Int32
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(502) }))
	ft := &failOnce{}
	env.HTTP = &http.Client{Transport: ft}
	obs, err := (restExecutor{}).Run(context.Background(), &scenario.Scenario{ID: "x", Kind: "rest", Path: "/"}, tok, env)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != 502 || calls.Load() != 1 || ft.n != 2 {
		t.Errorf("status=%d calls=%d attempts=%d; product 502 must not be retried", obs.Status, calls.Load(), ft.n)
	}
}

func TestREST_WriteNotRetriedAfterAmbiguousError(t *testing.T) {
	var calls atomic.Int32
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	env.HTTP = &http.Client{Transport: &failOnce{}}
	s := &scenario.Scenario{ID: "x", Kind: "rest", Method: "POST", Path: "/repos/w/w/issues", Body: map[string]any{"t": "x"}}
	_, err := (restExecutor{}).Run(context.Background(), s, tok, env)
	if err == nil || !strings.Contains(err.Error(), "may have been applied") {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() > 1 {
		t.Errorf("server saw %d calls", calls.Load())
	}
}

func TestFor_GH(t *testing.T) {
	if e, err := For("gh"); err != nil || e.Kind() != "gh" {
		t.Fatalf("For(gh) = %v, %v", e, err)
	}
}

func TestREST_Vhost(t *testing.T) {
	var gotHost, gotSNI, gotURI string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotURI = r.Host, r.RequestURI
		if r.TLS != nil {
			gotSNI = r.TLS.ServerName
		}
		w.WriteHeader(403)
	}))
	defer ts.Close()
	env, _, tok := newEnv(t, nil)
	env.HTTP = ts.Client()
	env.APIBase = ts.URL + "/api/v3"
	// httptest's certificate is valid for example.com, so it stands in for
	// github.com here.
	s := &scenario.Scenario{ID: "x", Kind: "rest", Vhost: "example.com", Path: "/{{.RepoB}}/archive/HEAD.tar.gz"}
	obs, err := (restExecutor{}).Run(context.Background(), s, tok, env)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != 403 {
		t.Errorf("status = %d", obs.Status)
	}
	if gotHost != "example.com" || gotSNI != "example.com" {
		t.Errorf("Host = %q, SNI = %q, want example.com for both", gotHost, gotSNI)
	}
	if want := "/b-owner/b-repo/archive/HEAD.tar.gz"; gotURI != want {
		t.Errorf("RequestURI = %q, want %q (no /api/v3 prefix)", gotURI, want)
	}
}

// Step expectations are expanded with the Vars, including earlier steps'
// captures, before they are matched (#307).
func TestREST_StepExpectIsExpanded(t *testing.T) {
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"number":7}`)
			return
		}
		_, _ = io.WriteString(w, `{"login":"`+"login"+`","number":7}`)
	}))
	s := &scenario.Scenario{ID: "x", Kind: "rest",
		Steps: []scenario.Request{
			{Name: "create", Method: "POST", Path: "/repos/w/w/issues", Capture: map[string]string{"n": "$.number"},
				Expect: &scenario.Expect{Status: 201}},
			{Name: "read", Path: "/repos/w/w/issues/7", Expect: &scenario.Expect{Status: 200,
				JSON: map[string]string{"$.login": "{{.Login}}", "$.number": `{{index .Step "create" "n"}}`}}},
			{Name: "last", Path: "/user", Expect: &scenario.Expect{Status: 200}},
		},
	}
	if _, err := (restExecutor{}).Run(context.Background(), s, tok, env); err != nil {
		t.Fatalf("err = %v, want the templated step expect to hold", err)
	}
}
