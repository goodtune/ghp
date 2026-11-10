package exec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// fakeTokenServer mimics the instance's token API for PERM-C18 and
// LIFE-C39: GET /api/github/permissions and POST /api/tokens with the
// server's no-expiry rule.
func fakeTokenServer(t *testing.T, allowNoExpiry bool, perms map[string]string) (*httptest.Server, *[]string) {
	var revoked []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sess" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/github/permissions":
			_ = json.NewEncoder(w).Encode(perms)
		case r.Method == http.MethodPost && r.URL.Path == "/api/tokens":
			var body struct {
				Duration, Scopes string
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Duration == "never" && !allowNoExpiry {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "no-expiry tokens are not allowed by server configuration"})
				return
			}
			scopes := map[string]string{}
			for _, s := range strings.Split(body.Scopes, ",") {
				if k, v, ok := strings.Cut(s, ":"); ok {
					scopes[k] = v
				}
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "tok-1", "token": "ghx_test0000new", "scopes": scopes})
		case r.Method == http.MethodDelete:
			revoked = append(revoked, strings.TrimPrefix(r.URL.Path, "/api/tokens/"))
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, &revoked
}

func runRigTokenAPI(t *testing.T, claim string, allowNoExpiry bool, perms map[string]string) {
	t.Helper()
	tree, err := scenario.Load("../../../rig")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range tree.Scenarios {
		if s.Claim != claim {
			continue
		}
		n++
		ts, revoked := fakeTokenServer(t, allowNoExpiry, perms)
		m := tokens.NewManager(ts.URL, "sess", "run", ts.Client(), 0)
		env := &RunEnv{Vars: scenario.PlaceholderVars(), HTTP: ts.Client(), Mgmt: ts.URL, Tokens: m, Session: "sess"}
		obs, err := tokenAPIExecutor{}.Run(context.Background(), s, tokens.Handle{}, env)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		if errs := expect.Match(s.VerdictExpect(), obs); len(errs) > 0 {
			t.Errorf("%s: %v", s.ID, errs)
		}
		if left := m.RevokeAll(context.Background()); len(left) > 0 {
			t.Errorf("%s: leftover %v", s.ID, left)
		}
		if s.ID == "PERM-C18.pull-requests-write-offered" && (len(*revoked) != 1 || (*revoked)[0] != "tok-1") {
			t.Errorf("%s: revoked %v, want the created token", s.ID, *revoked)
		}
	}
	if n == 0 {
		t.Fatalf("no scenarios for %s", claim)
	}
}

func TestRigScenario_PERMC18(t *testing.T) {
	runRigTokenAPI(t, "PERM-C18", false, map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"})
}

func TestRigScenario_PERMC18_FailsWithoutPullRequestsWrite(t *testing.T) {
	tree, err := scenario.Load("../../../rig")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range tree.Scenarios {
		if s.Claim != "PERM-C18" {
			continue
		}
		ts, _ := fakeTokenServer(t, false, map[string]string{"pull_requests": "read"})
		m := tokens.NewManager(ts.URL, "sess", "run", ts.Client(), 0)
		env := &RunEnv{Vars: scenario.PlaceholderVars(), HTTP: ts.Client(), Mgmt: ts.URL, Tokens: m, Session: "sess"}
		_, err := tokenAPIExecutor{}.Run(context.Background(), s, tokens.Handle{}, env)
		var sf StepFailure
		if !errors.As(err, &sf) || sf.Step != "list" {
			t.Errorf("%s: err = %v, want a failure of step list", s.ID, err)
		}
	}
}

func TestRigScenario_LIFEC39(t *testing.T) {
	runRigTokenAPI(t, "LIFE-C39", false, nil)
}

func TestRigScenario_LIFEC39_FailsWhenAllowed(t *testing.T) {
	tree, err := scenario.Load("../../../rig")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range tree.Scenarios {
		if s.Claim != "LIFE-C39" {
			continue
		}
		ts, _ := fakeTokenServer(t, true, nil)
		m := tokens.NewManager(ts.URL, "sess", "run", ts.Client(), 0)
		env := &RunEnv{Vars: scenario.PlaceholderVars(), HTTP: ts.Client(), Mgmt: ts.URL, Tokens: m, Session: "sess"}
		obs, err := tokenAPIExecutor{}.Run(context.Background(), s, tokens.Handle{}, env)
		if err != nil {
			t.Fatal(err)
		}
		if len(expect.Match(s.VerdictExpect(), obs)) == 0 {
			t.Errorf("%s: a 201 must not match", s.ID)
		}
		if left := m.RevokeAll(context.Background()); len(left) > 0 {
			t.Errorf("%s: leftover %v", s.ID, left)
		}
	}
}
