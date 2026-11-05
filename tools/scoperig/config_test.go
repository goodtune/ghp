package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeCfg(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	body := `instance:
  host: ghp.example.test
  management_host: mgmt.example.test
  default_duration: 24h
  max_duration: 168h
  token_create_rate: 20/min
  border_block: [ghp_, gho_]
fixtures:
  repo_a: o/a
  repo_b: o/b
  repo_w: o/w
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig(t *testing.T) {
	cfg := writeCfg(t)
	t.Run("defaults from file", func(t *testing.T) {
		c, err := LoadConfig(envMap(nil), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if c.RepoA != "o/a" || c.RepoB != "o/b" || c.RepoW != "o/w" {
			t.Fatalf("repos: %q %q %q", c.RepoA, c.RepoB, c.RepoW)
		}
		if c.TokenCreateRate != 20 {
			t.Fatalf("rate %d", c.TokenCreateRate)
		}
		if c.Instance.Host != "ghp.example.test" || c.Instance.ManagementHost != "mgmt.example.test" ||
			c.Instance.DefaultDuration != 24*time.Hour || c.Instance.MaxDuration != 168*time.Hour {
			t.Fatalf("instance %+v", c.Instance)
		}
		if strings.Join(c.BorderBlock, ",") != "ghp_,gho_" {
			t.Fatalf("border_block %v", c.BorderBlock)
		}
		if c.Root != "rig" || c.ConfigFile != cfg {
			t.Fatalf("root %q cfg %q", c.Root, c.ConfigFile)
		}
	})
	t.Run("env overrides", func(t *testing.T) {
		c, err := LoadConfig(envMap(map[string]string{
			"GHP_SERVER_URL": "https://s.test/", "GHP_USER_TOKEN": "ghpr_test0000",
			"GHP_RIG_REPO_A": "x/a", "GHP_RIG_REPO_W": "x/w",
			"GHP_RIG_GH": "/bin/gh", "GHP_RIG_SCENARIOS": "other", "GHP_RIG_CA_FILE": "/ca.pem",
			"GHP_RIG_INSTALLATION_ID": "42",
		}), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if c.RepoA != "x/a" || c.RepoB != "o/b" || c.RepoW != "x/w" {
			t.Fatalf("repos: %q %q %q", c.RepoA, c.RepoB, c.RepoW)
		}
		if c.ServerURL != "https://s.test" || c.GHPath != "/bin/gh" || c.Root != "other" || c.CAFile != "/ca.pem" || c.InstallationID != 42 {
			t.Fatalf("%+v", c)
		}
		if err := c.RequireServer(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing server url names it", func(t *testing.T) {
		c, err := LoadConfig(envMap(map[string]string{"GHP_USER_TOKEN": "ghpr_test0000"}), cfg)
		if err != nil {
			t.Fatal(err)
		}
		err = c.RequireServer()
		if err == nil || !strings.Contains(err.Error(), "GHP_SERVER_URL") {
			t.Fatalf("want GHP_SERVER_URL error, got %v", err)
		}
	})
	t.Run("missing user token names it", func(t *testing.T) {
		c, _ := LoadConfig(envMap(map[string]string{"GHP_SERVER_URL": "https://s.test"}), cfg)
		if err := c.RequireServer(); err == nil || !strings.Contains(err.Error(), "GHP_USER_TOKEN") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad values", func(t *testing.T) {
		for _, env := range []map[string]string{
			{"GHP_RIG_INSTALLATION_ID": "abc"},
			{"GHP_RIG_INSTALLATION_ID": "-1"},
			{"GHP_SERVER_URL": "ftp://x"},
		} {
			if _, err := LoadConfig(envMap(env), cfg); err == nil {
				t.Errorf("%v: want error", env)
			}
		}
		if _, err := LoadConfig(envMap(nil), filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
			t.Error("missing file: want error")
		}
	})
}

// validate-only paths must work with no environment at all.
func TestLoadConfig_NoEnv(t *testing.T) {
	c, err := LoadConfig(envMap(nil), writeCfg(t))
	if err != nil {
		t.Fatalf("no env must load: %v", err)
	}
	if c.ServerURL != "" || c.UserToken != "" {
		t.Fatal("unexpected server/token")
	}
}

func TestParseRate(t *testing.T) {
	for in, want := range map[string]int{"20/min": 20, "5/m": 5, " 30 / minute ": 30} {
		if got, err := parseRate(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "20", "x/min", "0/min", "20/h"} {
		if _, err := parseRate(in); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}

func TestConfig_StringRedacts(t *testing.T) {
	c, err := LoadConfig(envMap(map[string]string{"GHP_SERVER_URL": "https://s.test", "GHP_USER_TOKEN": "ghpr_secret0000"}), writeCfg(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{c.String(), fmtV(c)} {
		if strings.Contains(s, "ghpr_secret0000") {
			t.Fatalf("token leaked: %s", s)
		}
		if !strings.Contains(s, "https://s.test") {
			t.Fatalf("missing server: %s", s)
		}
	}
}

// run must find gh on PATH when GHP_RIG_GH is unset, like the oracle does.
func TestLoadConfig_GHPathFallback(t *testing.T) {
	old := lookPath
	t.Cleanup(func() { lookPath = old })
	lookPath = func(name string) (string, error) {
		if name != "gh" {
			t.Fatalf("lookPath(%q)", name)
		}
		return "/opt/bin/gh", nil
	}
	c, err := LoadConfig(envMap(nil), writeCfg(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.GHPath != "/opt/bin/gh" {
		t.Errorf("GHPath = %q, want PATH fallback", c.GHPath)
	}
	c, err = LoadConfig(envMap(map[string]string{"GHP_RIG_GH": "/x/gh"}), writeCfg(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.GHPath != "/x/gh" {
		t.Errorf("GHPath = %q, want env value", c.GHPath)
	}
}
