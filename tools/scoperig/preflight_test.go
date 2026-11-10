package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

func fmtV(c *Config) string { return fmt.Sprintf("%v %+v %#v", c, c, c) }

func TestPreflight(t *testing.T) {
	mk := func(rootStatus, tokStatus int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				if rootStatus == http.StatusSeeOther {
					http.Redirect(w, r, "/login", rootStatus)
					return
				}
				w.WriteHeader(rootStatus)
			case "/login":
				_, _ = fmt.Fprint(w, `<footer>ghp version v1.2.3-rc1</footer>`)
			case "/api/tokens":
				if tokStatus == http.StatusFound {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				if r.Header.Get("Authorization") != "Bearer ghpr_test0000" {
					w.WriteHeader(401)
					return
				}
				w.WriteHeader(tokStatus)
				_, _ = fmt.Fprint(w, `[]`)
			}
		}))
	}
	tests := []struct {
		name        string
		root, tok   int
		wantErr     bool
		wantVersion string
	}{
		{"ok redirect", 303, 200, false, "v1.2.3-rc1"},
		{"ok 200", 200, 200, false, "v1.2.3-rc1"},
		{"root 500", 500, 200, true, ""},
		{"session 401", 303, 401, true, ""},
		{"session redirect not accepted", 303, 302, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mk(tt.root, tt.tok)
			defer srv.Close()
			c := &Config{ServerURL: srv.URL, UserToken: "ghpr_test0000"}
			v, err := Preflight(context.Background(), c, srv.Client())
			if tt.wantErr {
				if !errors.Is(err, ErrPreflight) {
					t.Fatalf("want ErrPreflight, got %v", err)
				}
				if strings.Contains(err.Error(), "ghpr_test0000") {
					t.Fatal("token leaked in error")
				}
				return
			}
			if err != nil || v != tt.wantVersion {
				t.Fatalf("v=%q err=%v", v, err)
			}
		})
	}
	t.Run("unreachable", func(t *testing.T) {
		srv := mk(200, 200)
		u := srv.URL
		srv.Close()
		_, err := Preflight(context.Background(), &Config{ServerURL: u, UserToken: "x"}, http.DefaultClient)
		if !errors.Is(err, ErrPreflight) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("missing env", func(t *testing.T) {
		if _, err := Preflight(context.Background(), &Config{}, http.DefaultClient); !errors.Is(err, ErrPreflight) {
			t.Fatalf("got %v", err)
		}
	})
}

type probeOpts struct {
	push      bool
	scopes    string
	repoCode  int
	appCode   int // GET /api/apps/{testAppID}
	userCode  int
	appBodyID string // id in the app body; testAppID when empty
	apps      string // GET /api/apps body; 404 when empty
}

const testAppID = "00000000-0000-4000-8000-0000000000a6"

func probeServer(t *testing.T, o probeOpts) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/v3/user":
			if auth != "token ghx_test0000" {
				w.WriteHeader(401)
				return
			}
			if o.userCode != 0 {
				w.WriteHeader(o.userCode)
				return
			}
			_, _ = fmt.Fprint(w, `{"login":"octo"}`)
		case "/api/v3/repos/octo/w":
			if o.repoCode != 0 {
				w.WriteHeader(o.repoCode)
				return
			}
			_, _ = fmt.Fprintf(w, `{"permissions":{"push":%v}}`, o.push)
		case "/api/v3/":
			if o.scopes != "" {
				w.Header().Set("X-OAuth-Scopes", o.scopes)
			}
			_, _ = fmt.Fprint(w, `{}`)
		case "/api/apps/" + testAppID:
			if auth != "Bearer ghpr_test0000" {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(o.appCode)
			id := o.appBodyID
			if id == "" {
				id = testAppID
			}
			_, _ = fmt.Fprintf(w, `{"id":%q,"name":"rig"}`, id)
		case "/api/apps":
			if o.apps == "" || auth != "Bearer ghpr_test0000" {
				w.WriteHeader(404)
				return
			}
			_, _ = fmt.Fprint(w, o.apps)
		case "/api/tokens":
			if r.Method == http.MethodPost {
				w.WriteHeader(201)
				_, _ = fmt.Fprint(w, `{"id":"t1","token":"ghx_test0000"}`)
				return
			}
			w.WriteHeader(400)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestProbeCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		o       probeOpts
		repoW   string
		instID  int64
		want    Capabilities
		wantErr bool
	}{
		{"full", probeOpts{push: true, scopes: "repo, read:org", appCode: 200}, "octo/w", 7,
			Capabilities{"repo_w_push": true, "repo_create": true, "github_vhost": false, "codeload_vhost": false, "agent_installation": true}, false},
		{"public_repo scope", probeOpts{push: true, scopes: "public_repo", appCode: 200}, "octo/w", 0,
			Capabilities{"repo_w_push": true, "repo_create": true, "github_vhost": false, "agent_installation": false}, false},
		{"no push no scopes", probeOpts{push: false, appCode: 200}, "octo/w", 7,
			Capabilities{"repo_w_push": false, "repo_create": false, "github_vhost": false, "agent_installation": true}, false},
		{"repo-ish scope not repo", probeOpts{push: true, scopes: "repo:status, read:repo_hook", appCode: 200}, "octo/w", 7,
			Capabilities{"repo_w_push": true, "repo_create": false, "github_vhost": false, "agent_installation": true}, false},
		{"W owned by someone else", probeOpts{push: true, scopes: "repo", appCode: 200}, "other/w", 7,
			Capabilities{"repo_w_push": false, "repo_create": false, "github_vhost": false, "agent_installation": true}, false},
		{"repo 404 and tokens 403", probeOpts{repoCode: 404, scopes: "repo", appCode: 403}, "octo/w", 7,
			Capabilities{"repo_w_push": false, "repo_create": true, "github_vhost": false, "agent_installation": false}, false},
		{"user fails", probeOpts{userCode: 500}, "octo/w", 0, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := probeServer(t, tt.o)
			defer srv.Close()
			host := strings.TrimPrefix(srv.URL, "https://")
			c := &Config{ServerURL: srv.URL, UserToken: "ghpr_test0000", RepoW: tt.repoW, InstallationID: tt.instID,
				AgentAppRecordID: testAppID, Instance: scenario.InstanceVals{Host: host}}
			v := &scenario.Vars{}
			open := mintOpen(t, srv, v)
			// github_vhost: the httptest cert is not valid for github.com, so the
			// TLS handshake with ServerName github.com fails -> false.
			got, err := ProbeCapabilities(context.Background(), c, srv.Client(), open, v)
			if tt.wantErr {
				if !errors.Is(err, ErrPreflight) {
					t.Fatalf("want ErrPreflight, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.Login != "octo" {
				t.Fatalf("login %q", v.Login)
			}
			for k, w := range tt.want {
				if got[k] != w {
					t.Errorf("%s = %v, want %v", k, got[k], w)
				}
			}
			if len(got) != 12 {
				t.Errorf("caps %v", got)
			}
		})
	}
	t.Run("border_block declared", func(t *testing.T) {
		srv := probeServer(t, probeOpts{appCode: 200})
		defer srv.Close()
		host := strings.TrimPrefix(srv.URL, "https://")
		c := &Config{ServerURL: srv.URL, UserToken: "ghpr_test0000", RepoW: "octo/w",
			Instance: scenario.InstanceVals{Host: host}, BorderBlock: []string{"ghp_", "github_pat_"}}
		v := &scenario.Vars{}
		got, err := ProbeCapabilities(context.Background(), c, srv.Client(), mintOpen(t, srv, v), v)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{"border_block_ghp": true, "border_block_gho": false, "border_block_github_pat": true}
		for k, w := range want {
			if b, ok := got[k]; !ok || b != w {
				t.Errorf("%s = %v (present %v), want %v", k, b, ok, w)
			}
		}
	})
	t.Run("allow_no_expiry declared", func(t *testing.T) {
		f, tr := false, true
		for _, tt := range []struct {
			name string
			v    *bool
			want bool
		}{{"unset", nil, false}, {"false", &f, true}, {"true", &tr, false}} {
			t.Run(tt.name, func(t *testing.T) {
				srv := probeServer(t, probeOpts{appCode: 200})
				defer srv.Close()
				host := strings.TrimPrefix(srv.URL, "https://")
				c := &Config{ServerURL: srv.URL, UserToken: "ghpr_test0000", RepoW: "octo/w",
					Instance: scenario.InstanceVals{Host: host}, AllowNoExpiry: tt.v}
				v := &scenario.Vars{}
				got, err := ProbeCapabilities(context.Background(), c, srv.Client(), mintOpen(t, srv, v), v)
				if err != nil {
					t.Fatal(err)
				}
				if b, ok := got["no_expiry_disallowed"]; !ok || b != tt.want {
					t.Errorf("no_expiry_disallowed = %v (present %v), want %v", b, ok, tt.want)
				}
			})
		}
	})
	t.Run("empty host", func(t *testing.T) {
		_, err := ProbeCapabilities(context.Background(), &Config{}, http.DefaultClient, tokens.Handle{}, &scenario.Vars{})
		if !errors.Is(err, ErrPreflight) || !strings.Contains(err.Error(), "instance.host not set") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("vhost dial fails", func(t *testing.T) {
		srv := probeServer(t, probeOpts{appCode: 200})
		srv.Close()
		if probeVHost(context.Background(), "127.0.0.1:1", nil, "", "github.com") {
			t.Fatal("want false")
		}
	})
	t.Run("vhost server name", func(t *testing.T) {
		srv := probeServer(t, probeOpts{appCode: 200})
		defer srv.Close()
		host := strings.TrimPrefix(srv.URL, "https://")
		pool := rootCAs(srv.Client())
		// httptest's certificate is valid for example.com only.
		if !probeVHost(context.Background(), host, pool, "", "example.com") {
			t.Error("example.com: want true")
		}
		if probeVHost(context.Background(), host, pool, "", "codeload.github.com") {
			t.Error("codeload.github.com: want false (certificate does not cover it)")
		}
	})
}

// mintOpen obtains a Handle the way the rig does: through the Manager.
func mintOpen(t *testing.T, srv *httptest.Server, v *scenario.Vars) tokens.Handle {
	t.Helper()
	m := tokens.NewManager(srv.URL, "ghpr_test0000", "run1", srv.Client(), 0)
	h, err := m.Create(context.Background(), scenario.Profile{Name: "open", Type: "proxy", Duration: "1h"}, v)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestProbeAgentInstallation(t *testing.T) {
	tests := []struct {
		name   string
		o      probeOpts
		appID  string
		instID int64
		want   bool
	}{
		{"app exists", probeOpts{appCode: 200}, testAppID, 7, true},
		{"app missing", probeOpts{appCode: 404}, testAppID, 7, false},
		{"session not admin", probeOpts{appCode: 403}, testAppID, 7, false},
		{"body names another app", probeOpts{appCode: 200, appBodyID: "00000000-0000-4000-8000-0000000000d1"}, testAppID, 7, false},
		{"no installation", probeOpts{appCode: 200}, testAppID, 0, false},
		{"no app", probeOpts{appCode: 200}, "", 7, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := probeServer(t, tt.o)
			defer srv.Close()
			c := &Config{ServerURL: srv.URL, UserToken: "ghpr_test0000", InstallationID: tt.instID, AgentAppRecordID: tt.appID}
			if got := ProbeAgentInstallation(context.Background(), c, srv.Client()); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProbeDefaultApp(t *testing.T) {
	for _, tc := range []struct {
		name, apps string
		want       bool
	}{
		{"one default", `[{"is_default":true},{"is_default":false}]`, true},
		{"no default", `[{"is_default":false}]`, false},
		{"two defaults", `[{"is_default":true},{"is_default":true}]`, false},
		{"no apps", `[]`, false},
		{"not listed", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := probeServer(t, probeOpts{apps: tc.apps})
			defer srv.Close()
			c := &Config{ServerURL: srv.URL, UserToken: "ghpr_test0000"}
			if got := probeDefaultApp(context.Background(), c, srv.Client()); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
