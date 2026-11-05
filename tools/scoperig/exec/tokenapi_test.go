package exec

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

func TestTokenAPI_DeleteUsesManagerRevoke(t *testing.T) {
	env, fm, tok := newEnv(t, nil)
	s := &scenario.Scenario{ID: "x", Kind: "token_api", Request: &scenario.Request{Method: "DELETE", Path: "/api/tokens/" + tok.ID()}}
	obs, err := (tokenAPIExecutor{}).Run(context.Background(), s, tok, env)
	if err != nil || obs.Status != 200 {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	if left := env.Tokens.RevokeAll(context.Background()); len(left) != 0 {
		t.Fatal(left)
	}
	if len(fm.deletes) != 1 {
		t.Errorf("deletes = %v, want exactly one", fm.deletes)
	}
}

func TestTokenAPI_TypedInstallationID(t *testing.T) {
	env, fm, tok := newEnv(t, nil)
	env.InstallationID = 42
	s := &scenario.Scenario{ID: "x", Kind: "token_api", Request: &scenario.Request{Method: "POST", Path: "/api/tokens",
		Body: map[string]any{"installation_id": "$int:InstallationID"}}}
	if _, err := (tokenAPIExecutor{}).Run(context.Background(), s, tok, env); err != nil {
		t.Fatal(err)
	}
	if b := fm.bodies[len(fm.bodies)-1]; !strings.Contains(b, `"installation_id":42`) {
		t.Errorf("body = %s", b)
	}
}

func TestTokenAPI_UnknownIntName(t *testing.T) {
	env, _, tok := newEnv(t, nil)
	s := &scenario.Scenario{ID: "x", Kind: "token_api", Request: &scenario.Request{Method: "POST", Path: "/api/tokens",
		Body: map[string]any{"x": "$int:Nope"}}}
	if _, err := (tokenAPIExecutor{}).Run(context.Background(), s, tok, env); err == nil {
		t.Fatal("want error")
	}
}

func TestTokenAPI_RecordsCreatedID(t *testing.T) {
	env, fm, tok := newEnv(t, nil)
	s := &scenario.Scenario{ID: "x", Kind: "token_api", Request: &scenario.Request{Name: "mk", Method: "POST", Path: "/api/tokens",
		Body: map[string]any{"duration": "1h"}, Capture: map[string]string{"id": "$.id"}}}
	obs, err := (tokenAPIExecutor{}).Run(context.Background(), s, tok, env)
	if err != nil || obs.Status != 201 {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	if strings.Contains(string(obs.Body), "test0000") {
		t.Error("token value in observation")
	}
	id := env.Vars.Step["mk"]["id"]
	if id == "" || env.Tokens.Created() != 2 {
		t.Fatalf("id=%q created=%d", id, env.Tokens.Created())
	}
	env.Tokens.RevokeAll(context.Background())
	found := false
	for _, d := range fm.deletes {
		found = found || d == id
	}
	if !found {
		t.Errorf("created id %s not revoked: %v", id, fm.deletes)
	}
}

func TestTokenAPI_SessionGET(t *testing.T) {
	env, _, tok := newEnv(t, nil)
	s := &scenario.Scenario{ID: "x", Kind: "token_api", Request: &scenario.Request{Path: "/api/tokens?all=true"}}
	obs, err := (tokenAPIExecutor{}).Run(context.Background(), s, tok, env)
	if err != nil || !strings.Contains(string(obs.Body), `"auth":true`) {
		t.Fatalf("obs=%s err=%v", obs.Body, err)
	}
}

func TestTokenAPI_Poll(t *testing.T) {
	for _, tc := range []struct {
		name   string
		after  int32
		status int
	}{{"eventually401", 2, 401}, {"never", 1 << 30, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			var n atomic.Int32
			env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if n.Add(1) > tc.after {
					w.WriteHeader(401)
				}
			}))
			want := &scenario.Expect{Status: 401}
			s := &scenario.Scenario{ID: "x", Kind: "token_api", Expect: want, Poll: &scenario.Poll{Interval: "5ms", Timeout: "100ms"},
				Request: &scenario.Request{Name: "probe", Path: "/api/v3/user"}}
			obs, err := (tokenAPIExecutor{}).Run(context.Background(), s, tok, env)
			if err != nil {
				t.Fatal(err)
			}
			if obs.Status != tc.status {
				t.Fatalf("status %d, want %d", obs.Status, tc.status)
			}
			if mm := expect.Match(want, obs); (len(mm) == 0) != (tc.status == 401) {
				t.Errorf("match = %v", mm)
			}
		})
	}
}

func TestTokenAPI_PollNeedsExpect(t *testing.T) {
	env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	s := &scenario.Scenario{ID: "x", Kind: "token_api", Poll: &scenario.Poll{Interval: "1ms", Timeout: "5ms"},
		Request: &scenario.Request{Name: "probe", Path: "/api/v3/user"}}
	if _, err := (tokenAPIExecutor{}).Run(context.Background(), s, tok, env); err == nil {
		t.Fatal("want error for poll without expect")
	}
}
