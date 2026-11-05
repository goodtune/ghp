package exec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
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
			io.WriteString(w, `{"number":7}`)
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
		io.WriteString(w, `{"auth":"`+r.Header.Get("Authorization")+`"}`)
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
		io.WriteString(w, strings.Repeat("a", 2*MaxBody))
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
	calls := 0
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(502) }))
	ft := &failOnce{}
	env.HTTP = &http.Client{Transport: ft}
	obs, err := (restExecutor{}).Run(context.Background(), &scenario.Scenario{ID: "x", Kind: "rest", Path: "/"}, tok, env)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != 502 || calls != 1 || ft.n != 2 {
		t.Errorf("status=%d calls=%d attempts=%d; product 502 must not be retried", obs.Status, calls, ft.n)
	}
}
