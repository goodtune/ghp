package gitcred

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseSettings(t *testing.T) {
	tests := []struct {
		name    string
		in      Settings
		want    Plan
		wantErr string
	}{
		{
			name: "defaults",
			in:   Settings{},
			want: Plan{Type: TypeAgent, Scopes: map[string]string{"contents": "write"}, TTL: time.Hour},
		},
		{
			name: "agent with app",
			in:   Settings{Type: "agent", App: "my-app"},
			want: Plan{Type: TypeAgent, App: "my-app", Scopes: map[string]string{"contents": "write"}, TTL: time.Hour},
		},
		{name: "proxy with flag app", in: Settings{Type: "proxy", App: "x"}, wantErr: "--app is only valid with --type agent"},
		{
			name: "proxy flag ignores env app",
			in:   Settings{Type: "proxy", App: "x", AppFromEnv: true, TypeFromFlag: true},
			want: Plan{Type: TypeProxy, Scopes: map[string]string{"contents": "write"}, TTL: time.Hour},
		},
		{name: "proxy env with env app", in: Settings{Type: "proxy", App: "x", AppFromEnv: true}, wantErr: "--app is only valid with --type agent"},
		{name: "proxy flag with flag app", in: Settings{Type: "proxy", App: "x", TypeFromFlag: true}, wantErr: "--app is only valid with --type agent"},
		{
			name: "proxy without app",
			in:   Settings{Type: "proxy"},
			want: Plan{Type: TypeProxy, Scopes: map[string]string{"contents": "write"}, TTL: time.Hour},
		},
		{name: "bogus type", in: Settings{Type: "bogus"}, wantErr: `invalid token type "bogus" (want agent or proxy)`},
		{name: "type is case sensitive", in: Settings{Type: "Agent"}, wantErr: "invalid token type"},
		{name: "bad scopes", in: Settings{Scopes: "pulls:write", ScopesExplicit: true}, wantErr: "invalid scopes"},
		{name: "ttl never", in: Settings{TTL: "never"}, wantErr: "--ttl never is not allowed: cached tokens must expire"},
		{name: "ttl zero", in: Settings{TTL: "0s"}, wantErr: `invalid --ttl "0s"`},
		{name: "ttl negative", in: Settings{TTL: "-1h"}, wantErr: `invalid --ttl "-1h"`},
		{name: "ttl unparsable", in: Settings{TTL: "soon"}, wantErr: `invalid --ttl "soon"`},
		{
			name: "ttl 90m",
			in:   Settings{TTL: "90m"},
			want: Plan{Type: TypeAgent, Scopes: map[string]string{"contents": "write"}, TTL: 90 * time.Minute},
		},
		{
			name: "explicit scopes kept",
			in:   Settings{Scopes: "contents:read", ScopesExplicit: true},
			want: Plan{Type: TypeAgent, Scopes: map[string]string{"contents": "read"}, ScopesExplicit: true, TTL: time.Hour},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSettings(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseSettings() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSettings() error = %v", err)
			}
			if got.Type != tt.want.Type || got.App != tt.want.App || got.ScopesExplicit != tt.want.ScopesExplicit || got.TTL != tt.want.TTL {
				t.Errorf("ParseSettings() = %+v, want %+v", got, tt.want)
			}
			if !maps.Equal(got.Scopes, tt.want.Scopes) {
				t.Errorf("Scopes = %v, want %v", got.Scopes, tt.want.Scopes)
			}
		})
	}
}

func TestSelectApp(t *testing.T) {
	a := App{ID: "11111111-1111-1111-1111-111111111111", Name: "a"}
	b := App{ID: "22222222-2222-2222-2222-222222222222", Name: "b"}
	bDefault := b
	bDefault.IsDefault = true
	myApp := App{ID: "33333333-3333-3333-3333-333333333333", Name: "my-app"}
	staging := App{ID: "44444444-4444-4444-4444-444444444444", Name: "staging"}

	tests := []struct {
		name     string
		apps     []App
		selector string
		want     App
		wantErr  []string
	}{
		{name: "name ascii fold", apps: []App{a, myApp}, selector: "MY-APP", want: myApp},
		{name: "by id", apps: []App{a, b}, selector: b.ID, want: b},
		{name: "by id upper case", apps: []App{a, b}, selector: strings.ToUpper(b.ID), want: b},
		{name: "empty picks default", apps: []App{a, bDefault}, want: bDefault},
		{name: "empty picks only app", apps: []App{a}, want: a},
		{name: "no apps", apps: nil, wantErr: []string{"no GitHub Apps are configured on the ghp server; use --type proxy or ask an admin to add one"}},
		{name: "no apps with selector", apps: nil, selector: "a", wantErr: []string{"no GitHub Apps"}},
		{name: "several no default", apps: []App{a, b}, wantErr: []string{"several GitHub Apps are configured and none is the default; set --app or GHP_GIT_CM_APP to one of: a, b"}},
		{name: "not found", apps: []App{a, b}, selector: "zzz", wantErr: []string{`GitHub App "zzz" not found; available apps: a, b`}},
		{name: "long s does not fold", apps: []App{staging}, selector: "ſtaging", wantErr: []string{`"ſtaging" not found`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SelectApp(tt.apps, tt.selector)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("SelectApp() = %+v, want error", got)
				}
				for _, s := range tt.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("SelectApp() error = %q, want containing %q", err.Error(), s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectApp() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("SelectApp() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func installation(id int64, login string, perms map[string]string) Installation {
	var inst Installation
	inst.ID = id
	inst.Account.Login = login
	inst.Permissions = perms
	return inst
}

func TestSelectInstallation(t *testing.T) {
	goodtune := installation(42, "goodtune", map[string]string{"contents": "read"})
	kube := installation(43, "kube", nil)
	tests := []struct {
		name    string
		insts   []Installation
		owner   string
		wantID  int64
		wantErr []string
	}{
		{name: "ascii fold", insts: []Installation{kube, goodtune}, owner: "GoodTune", wantID: 42},
		{name: "kelvin sign does not fold", insts: []Installation{kube}, owner: "Kube", wantErr: []string{"has no installation"}},
		{name: "missing", insts: []Installation{kube}, owner: "goodtune", wantErr: []string{`GitHub App "my-app" has no installation for "goodtune"; install it there or choose another app with --app`}},
		{name: "none", insts: nil, owner: "goodtune", wantErr: []string{`"my-app"`, `"goodtune"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SelectInstallation(tt.insts, tt.owner, "my-app")
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("SelectInstallation() = %+v, want error", got)
				}
				for _, s := range tt.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("SelectInstallation() error = %q, want containing %q", err.Error(), s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectInstallation() error = %v", err)
			}
			if got.ID != tt.wantID {
				t.Errorf("SelectInstallation().ID = %d, want %d", got.ID, tt.wantID)
			}
		})
	}
}

func TestEffectiveScopes(t *testing.T) {
	tests := []struct {
		name      string
		requested map[string]string
		granted   map[string]string
		explicit  bool
		want      map[string]string
		wantErr   []string
	}{
		{name: "defaulted lowered to read", requested: map[string]string{"contents": "write"}, granted: map[string]string{"contents": "read"}, want: map[string]string{"contents": "read"}},
		{name: "defaulted kept at write", requested: map[string]string{"contents": "write"}, granted: map[string]string{"contents": "write"}, want: map[string]string{"contents": "write"}},
		{name: "defaulted admin grants write", requested: map[string]string{"contents": "write"}, granted: map[string]string{"contents": "admin"}, want: map[string]string{"contents": "write"}},
		{name: "explicit read under write", requested: map[string]string{"contents": "read"}, granted: map[string]string{"contents": "write"}, explicit: true, want: map[string]string{"contents": "read"}},
		{
			name: "explicit exceeds grant", requested: map[string]string{"contents": "write"}, granted: map[string]string{"contents": "read"}, explicit: true,
			wantErr: []string{`installation for "goodtune" grants contents:read but contents:write was requested; lower --scopes or GHP_GIT_CM_SCOPES`},
		},
		{
			name: "explicit absent", requested: map[string]string{"contents": "write"}, granted: map[string]string{"issues": "write"}, explicit: true,
			wantErr: []string{`installation for "goodtune" does not grant contents, needed for contents:write`},
		},
		{
			name: "defaulted absent", requested: map[string]string{"contents": "write"}, granted: map[string]string{"issues": "write"},
			wantErr: []string{"does not grant contents"},
		},
		{name: "defaulted nil grant", requested: map[string]string{"contents": "write"}, granted: nil, wantErr: []string{"does not grant contents"}},
		{name: "workflows read via actions", requested: map[string]string{"workflows": "read"}, granted: map[string]string{"actions": "read"}, explicit: true, want: map[string]string{"workflows": "read"}},
		{
			name: "projects needs both project permissions", requested: map[string]string{"projects": "write"}, granted: map[string]string{"repository_projects": "write"}, explicit: true,
			wantErr: []string{"does not grant organization_projects, needed for projects:write"},
		},
		{
			name: "defaulted projects lowered to lowest grant", requested: map[string]string{"projects": "write"},
			granted: map[string]string{"repository_projects": "write", "organization_projects": "read"},
			want:    map[string]string{"projects": "read"},
		},
		{name: "unknown granted level is no grant", requested: map[string]string{"contents": "read"}, granted: map[string]string{"contents": "bogus"}, wantErr: []string{"does not grant contents"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requested := maps.Clone(tt.requested)
			got, err := EffectiveScopes(tt.requested, tt.granted, tt.explicit, "goodtune")
			if !maps.Equal(tt.requested, requested) {
				t.Errorf("EffectiveScopes() modified requested: %v", tt.requested)
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("EffectiveScopes() = %v, want error", got)
				}
				for _, s := range tt.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("EffectiveScopes() error = %q, want containing %q", err.Error(), s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("EffectiveScopes() error = %v", err)
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("EffectiveScopes() = %v, want %v", got, tt.want)
			}
		})
	}
}

const testAppID = "0b0e0000-0000-4000-8000-000000000001"

// agentAPI fakes /api/apps (default app "my-app") and its installations
// (installation 42 for "goodtune" with contents:read).
func agentAPI(t *testing.T, appsStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/apps", func(w http.ResponseWriter, r *http.Request) {
		if appsStatus != http.StatusOK {
			writeJSONBody(t, w, appsStatus, map[string]string{"message": "Admin role required"})
			return
		}
		writeJSONBody(t, w, http.StatusOK, []map[string]any{
			{"id": "99999999-9999-4999-8999-999999999999", "name": "other", "app_id": 2, "is_default": false},
			{"id": testAppID, "name": "my-app", "app_id": 1, "is_default": true},
		})
	})
	mux.HandleFunc("GET /api/apps/{id}/installations", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != testAppID {
			t.Errorf("installations for %q, want %q", r.PathValue("id"), testAppID)
		}
		writeJSONBody(t, w, http.StatusOK, []map[string]any{
			{"id": 41, "account": map[string]any{"login": "someone"}, "permissions": map[string]string{"contents": "write"}},
			{"id": 42, "account": map[string]any{"login": "goodtune"}, "permissions": map[string]string{"contents": "read", "metadata": "read"}},
		})
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testSessionToken {
			t.Errorf("Authorization = %q, want bearer session token", got)
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolve_Agent(t *testing.T) {
	srv := agentAPI(t, http.StatusOK)
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	p := Plan{Type: TypeAgent, Scopes: map[string]string{"contents": "write"}, TTL: time.Hour}
	got, err := Resolve(context.Background(), c, p, Target{Owner: "GoodTune", Repo: "ghp"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Type != TypeAgent || got.AppRecordID != testAppID || got.AppName != "my-app" || got.InstallationID != 42 {
		t.Errorf("Resolve() = %+v", got)
	}
	if want := map[string]string{"contents": "read"}; !maps.Equal(got.Scopes, want) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, want)
	}
}

func TestResolve_AgentExplicitScopesExceedGrant(t *testing.T) {
	srv := agentAPI(t, http.StatusOK)
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	p := Plan{Type: TypeAgent, Scopes: map[string]string{"contents": "write"}, ScopesExplicit: true, TTL: time.Hour}
	_, err := Resolve(context.Background(), c, p, Target{Owner: "goodtune", Repo: "ghp"})
	if err == nil || !strings.Contains(err.Error(), "grants contents:read but contents:write was requested") {
		t.Fatalf("Resolve() error = %v, want scope shortfall", err)
	}
}

func TestResolve_AgentForbidden(t *testing.T) {
	srv := agentAPI(t, http.StatusForbidden)
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	p := Plan{Type: TypeAgent, Scopes: map[string]string{"contents": "write"}, TTL: time.Hour}
	_, err := Resolve(context.Background(), c, p, Target{Owner: "goodtune", Repo: "ghp"})
	if err == nil {
		t.Fatal("Resolve() error = nil, want forbidden")
	}
	if err.Error() != msgAgentForbidden {
		t.Errorf("Error() = %q, want %q", err.Error(), msgAgentForbidden)
	}
	if !strings.Contains(err.Error(), "--type proxy") {
		t.Errorf("Error() = %q, want --type proxy hint", err.Error())
	}
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("errors.Is(err, ErrForbidden) = false")
	}
}

func TestResolve_InstallationsForbidden(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/apps", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(t, w, http.StatusOK, []map[string]any{{"id": testAppID, "name": "my-app", "is_default": true}})
	})
	mux.HandleFunc("GET /api/apps/{id}/installations", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(t, w, http.StatusForbidden, map[string]string{"message": "Admin role required"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	p := Plan{Type: TypeAgent, Scopes: map[string]string{"contents": "write"}, TTL: time.Hour}
	_, err := Resolve(context.Background(), c, p, Target{Owner: "goodtune", Repo: "ghp"})
	if err == nil || err.Error() != msgAgentForbidden || !errors.Is(err, ErrForbidden) {
		t.Fatalf("Resolve() error = %v, want msgAgentForbidden wrapping ErrForbidden", err)
	}
}

func TestResolve_AgentUnauthorizedPassesThrough(t *testing.T) {
	srv := agentAPI(t, http.StatusUnauthorized)
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	p := Plan{Type: TypeAgent, Scopes: map[string]string{"contents": "write"}, TTL: time.Hour}
	_, err := Resolve(context.Background(), c, p, Target{Owner: "goodtune", Repo: "ghp"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Resolve() error = %v, want ErrUnauthorized", err)
	}
}

func TestResolve_Proxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	requested := map[string]string{"contents": "write"}
	p := Plan{Type: TypeProxy, Scopes: requested, TTL: time.Hour}
	got, err := Resolve(context.Background(), c, p, Target{Owner: "goodtune", Repo: "ghp"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Type != TypeProxy || got.AppRecordID != "" || got.AppName != "" || got.InstallationID != 0 {
		t.Errorf("Resolve() = %+v", got)
	}
	if !maps.Equal(got.Scopes, requested) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, requested)
	}
}
