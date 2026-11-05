package exec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// fakeMgmt is a minimal management API.
type fakeMgmt struct {
	mu      sync.Mutex
	n       int
	deletes []string
	bodies  []string
}

func (f *fakeMgmt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/tokens":
		b, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(b))
		f.n++
		id := "id" + strings.Repeat("x", f.n)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "token": "ghx_test0000fakevalue"})
	case r.Method == http.MethodDelete:
		f.deletes = append(f.deletes, strings.TrimPrefix(r.URL.Path, "/api/tokens/"))
		_ = json.NewEncoder(w).Encode(map[string]any{})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": r.Header.Get("Authorization") != ""})
	}
}

func newEnv(t *testing.T, api http.Handler) (*RunEnv, *fakeMgmt, tokens.Handle) {
	t.Helper()
	fm := &fakeMgmt{}
	ms := httptest.NewServer(fm)
	t.Cleanup(ms.Close)
	var as *httptest.Server
	if api != nil {
		as = httptest.NewServer(api)
		t.Cleanup(as.Close)
	}
	m := tokens.NewManager(ms.URL, "sess", "run", ms.Client(), 0)
	v := scenario.PlaceholderVars()
	h, err := m.Create(context.Background(), scenario.Profile{Name: "open", Type: "proxy", Duration: "1h"}, v)
	if err != nil {
		t.Fatal(err)
	}
	env := &RunEnv{Vars: v, HTTP: http.DefaultClient, Mgmt: ms.URL, Tokens: m, Open: h, Session: "sess"}
	if as != nil {
		env.APIBase = as.URL + "/api/v3"
		env.GraphQL = as.URL + "/api/graphql"
	}
	return env, fm, h
}
